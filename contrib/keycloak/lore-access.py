#!/usr/bin/python3
"""Root-only administration of Lore users and repository grants."""
import argparse,json,os,secrets,sys,requests
BASE='https://10.8.0.1:8443'
SECRET='/etc/lore-auth/management.json'
CA='/etc/lore-auth/tls/ca.crt'
def duration_seconds(value):
 import re
 match=re.fullmatch(r'([1-9][0-9]*)([smhdw])',value)
 if not match: raise argparse.ArgumentTypeError('Use a positive duration such as 8h, 7d or 1w')
 seconds=int(match[1])*{'s':1,'m':60,'h':3600,'d':86400,'w':604800}[match[2]]
 if seconds>2147483647: raise argparse.ArgumentTypeError('Duration exceeds Keycloak integer limit')
 return seconds

def session_settings(duration):
 """Keep idle lifetime equal to absolute lifetime, including closed clients."""
 credentials=json.load(open('/etc/lore-auth/bootstrap.json'))
 s=requests.Session(); s.verify=CA
 r=s.post(BASE+'/realms/master/protocol/openid-connect/token',data={
  'grant_type':'password','client_id':'admin-cli',
  'username':credentials['admin_username'],'password':credentials['admin_password']},timeout=20)
 if not r.ok: sys.exit('Realm administrator authentication failed; no changes made')
 s.headers['Authorization']='Bearer '+r.json()['access_token']
 url=BASE+'/admin/realms/lore'
 def request(method,url,**kwargs):
  response=s.request(method,url,timeout=20,**kwargs)
  if not response.ok: sys.exit(f'Session settings: HTTP {response.status_code}')
  return response.json() if response.content else None
 keys=['ssoSessionIdleTimeout','ssoSessionMaxLifespan',
       'ssoSessionIdleTimeoutRememberMe','ssoSessionMaxLifespanRememberMe',
       'clientSessionIdleTimeout','clientSessionMaxLifespan']
 if duration is not None:
  clients=request('GET',url+'/clients?clientId=lore-cli')
  if len(clients)!=1: sys.exit('Lore client not found; no changes made')
  attrs=clients[0].get('attributes',{})
  for key in ['client.session.idle.timeout','client.session.max.lifespan']:
   override=int(attrs.get(key,'0') or '0')
   if override>0 and override<duration:
    sys.exit('Client override '+key+' is shorter than requested; remove it in Keycloak first. No changes made.')
  request('PUT',url,json={key:duration for key in keys})
 realm=request('GET',url)
 values={key:realm.get(key,0) for key in keys}
 values['accessTokenLifespan']=realm.get('accessTokenLifespan')
 if duration is not None and any(values[key]!=duration for key in keys):
  sys.exit('Session settings verification failed; inspect the realm settings')
 print(json.dumps(values,indent=2))

def main():
 if os.geteuid()!=0: sys.exit('Run via sudo/root on p4-vps')
 p=argparse.ArgumentParser(description=__doc__)
 sub=p.add_subparsers(dest='cmd',required=True)
 q=sub.add_parser('session-settings',help='Show/set login lifetime independently of activity')
 q.add_argument('--duration',type=duration_seconds,help='Absolute login lifetime, e.g. 8h, 7d, 1w')
 sub.add_parser('repositories')
 q=sub.add_parser('repository-register'); q.add_argument('name'); q.add_argument('repository_id')
 for name in ['user-create','user-disable','password-reset','grants']:
  q=sub.add_parser(name); q.add_argument('username')
 for name in ['grant','revoke']:
  q=sub.add_parser(name); q.add_argument('username'); q.add_argument('repository_id')
  if name=='grant':
   level=q.add_mutually_exclusive_group()
   level.add_argument('--admin',action='store_true',help='Compatibility alias for --access admin')
   level.add_argument('--access',choices=['read','write','admin'],default='write')
 a=p.parse_args()
 if a.cmd=='session-settings':
  session_settings(a.duration); return
 registry_path='/etc/lore-auth/repositories.json'
 registry=json.load(open(registry_path))
 if a.cmd=='repositories':
  for name,rid in sorted(registry.items()): print(name+' '+rid)
  return
 if a.cmd=='repository-register':
  import re,tempfile
  if not re.fullmatch('[0-9a-fA-F]{32}',a.repository_id): sys.exit('Use exact 32-character repository ID')
  if a.name in registry and registry[a.name]!=a.repository_id.lower(): sys.exit('Name already registered with another ID')
  registry[a.name]=a.repository_id.lower()
  fd,path=tempfile.mkstemp(prefix='.repositories-',dir='/etc/lore-auth')
  with os.fdopen(fd,'w') as f: json.dump(registry,f)
  os.chmod(path,0o644); os.replace(path,registry_path)
  print('Repository added to catalog. No new user grants created.'); return
 secret=json.load(open(SECRET)); s=requests.Session(); s.verify=CA
 r=s.post(BASE+'/realms/lore/protocol/openid-connect/token',data={'grant_type':'client_credentials','client_id':secret['client_id'],'client_secret':secret['client_secret']},timeout=20)
 if not r.ok: sys.exit('Administrator authentication failed; no changes made')
 s.headers['Authorization']='Bearer '+r.json()['access_token']
 def api(method,path,data=None):
  r=s.request(method,BASE+'/admin/realms/lore/'+path,json=data,timeout=20)
  if not r.ok: sys.exit(f'{method} {path}: HTTP {r.status_code}')
  return r.json() if r.content else None
 users=api('GET','users?username='+requests.utils.quote(a.username,safe='')+'&exact=true')
 if a.cmd=='user-create':
  if users: sys.exit('User already exists')
  password=secrets.token_urlsafe(24)
  api('POST','users',{'username':a.username,'enabled':True,'attributes':{'lore_resources':['[]']},'credentials':[{'type':'password','value':password,'temporary':True}]})
  os.makedirs('/etc/lore-auth/issued-passwords',mode=0o700,exist_ok=True)
  # The filename is encoded; a username is never interpreted as a path.
  path='/etc/lore-auth/issued-passwords/'+a.username.encode().hex()+'.json'
  with open(path,'w') as f: json.dump({'username':a.username,'temporary_password':password},f)
  os.chmod(path,0o600)
  print('User created with NO repository access. Temporary password file: '+path)
  return
 if len(users)!=1: sys.exit('User not found or ambiguous')
 u=users[0]; uid=u['id']; attrs=u.get('attributes',{})
 if a.cmd=='user-disable':
  u['enabled']=False; api('PUT','users/'+uid,u); api('POST','users/'+uid+'/logout'); print('User disabled. Existing access JWTs expire within 120 seconds (plus verifier clock tolerance).'); return
 if a.cmd=='password-reset':
  password=secrets.token_urlsafe(24)
  api('PUT','users/'+uid+'/reset-password',{'type':'password','value':password,'temporary':True})
  api('POST','users/'+uid+'/logout')
  os.makedirs('/etc/lore-auth/issued-passwords',mode=0o700,exist_ok=True)
  path='/etc/lore-auth/issued-passwords/'+a.username.encode().hex()+'.json'
  with open(path,'w') as f: json.dump({'username':a.username,'temporary_password':password},f)
  os.chmod(path,0o600); print('Temporary password file: '+path); return
 grants=json.loads(attrs.get('lore_resources',['[]'])[0])
 if a.cmd=='grants': print(json.dumps(grants,indent=2)); return
 import re
 a.repository_id=registry.get(a.repository_id,a.repository_id)
 if not re.fullmatch('[0-9a-fA-F]{32}',a.repository_id): sys.exit('Use registered repository name or exact 32-character ID; wildcard grants are not allowed by this helper')
 resource='urc-'+a.repository_id.lower()
 grants=[g for g in grants if g.get('resource_id')!=resource]
 if a.cmd=='grant':
  levels={'read':['read'],'write':['read','write'],'admin':['read','write','admin','owner','push-protected','obliterate']}
  grants.append({'resource_id':resource,'permission':levels['admin' if a.admin else a.access]})
 attrs['lore_resources']=[json.dumps(grants,separators=(',',':'))]; u['attributes']=attrs
 api('PUT','users/'+uid,u)
 # Remove all current sessions, preventing old refresh tokens from restoring access.
 api('POST','users/'+uid+'/logout')
 print('Grants updated. User must log in again. Existing access JWTs expire within 120 seconds (plus verifier clock tolerance).')
if __name__=='__main__': main()
