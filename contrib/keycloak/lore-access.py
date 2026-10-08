#!/usr/bin/python3
"""Root-only administration of Lore users and repository grants."""
import argparse,json,os,secrets,sys,requests
BASE='https://10.8.0.1:8443'
SECRET='/etc/lore-auth/management.json'
CA='/etc/lore-auth/tls/ca.crt'
def main():
 if os.geteuid()!=0: sys.exit('Run via sudo/root on p4-vps')
 p=argparse.ArgumentParser(description=__doc__)
 sub=p.add_subparsers(dest='cmd',required=True)
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
