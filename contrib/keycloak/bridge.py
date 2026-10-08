#!/usr/bin/python3
"""UrcAuthApi compatibility adapter. Keycloak owns identities and signing keys."""
import json,time,threading,secrets,fnmatch,logging,ssl,os
from concurrent.futures import ThreadPoolExecutor
import grpc,jwt,requests
import auth_api_pb2 as pb
import auth_api_pb2_grpc as rpc
CONFIG=json.load(open(os.environ.get('LORE_AUTH_CONFIG_PATH','/etc/lore-auth/bridge.json')))
ISSUER=CONFIG['issuer']; CA=CONFIG['ca']; BASE=ISSUER.split('/realms/')[0]
JWKS=jwt.PyJWKClient(ISSUER+'/protocol/openid-connect/certs',cache_keys=True,lifespan=300,timeout=15)
logging.basicConfig(level=logging.INFO,format='%(asctime)s %(levelname)s %(message)s')
class Bridge(rpc.UrcAuthApiServicer):
 def __init__(self):
  self.lock=threading.Lock(); self.pending={}; self.service_token=''; self.service_until=0
 def request(self,method,url,**kwargs):
  try:
   r=requests.request(method,url,verify=CA,timeout=15,**kwargs)
   r.raise_for_status(); return r.json() if r.content else {}
  except requests.RequestException:
   # Never log HTTP request bodies, tokens or credentials.
   raise RuntimeError('Identity provider request failed')
 def keycloak(self,path):
  with self.lock:
   if time.time()>=self.service_until:
    result=self.request('POST',ISSUER+'/protocol/openid-connect/token',data={'grant_type':'client_credentials','client_id':'lore-auth-bridge','client_secret':CONFIG['client_secret']})
    self.service_token=result['access_token']; self.service_until=time.time()+result['expires_in']-15
   token=self.service_token
  return self.request('GET',BASE+'/admin/realms/lore/'+path,headers={'Authorization':'Bearer '+token})
 def verify(self,token,context):
  try:
   key=JWKS.get_signing_key_from_jwt(token).key
   claims=jwt.decode(token,key,algorithms=['RS256'],audience='10.8.0.1',issuer=ISSUER,options={'require':['exp','iat','sub']},leeway=5)
   user=self.keycloak('users/'+claims['sub'])
   if not user.get('enabled'): context.abort(grpc.StatusCode.PERMISSION_DENIED,'Account disabled')
   return claims,user
  except grpc.RpcError: raise
  except Exception: context.abort(grpc.StatusCode.UNAUTHENTICATED,'Invalid or expired credentials')
 def principal(self,context):
  header=dict(context.invocation_metadata()).get('authorization','')
  if not header.startswith('Bearer '): context.abort(grpc.StatusCode.UNAUTHENTICATED,'Authentication required')
  token=header[7:]; claims,user=self.verify(token,context); return token,claims,user
 def grants(self,user):
  try: return json.loads(user.get('attributes',{}).get('lore_resources',['[]'])[0])
  except (ValueError,TypeError): return []
 def permission(self,user,resource):
  result=[]; found=False
  for entry in self.grants(user):
   if entry.get('resource_id') in (resource,'urc-*'):
    found=True; result+=entry.get('permission',[])
  return sorted(set(result)) if found else None
 def user_token(self,token,claims,user,refresh=None):
  return pb.UserToken(user_token=token,expires_at=int(claims['exp'])*1000,user_id=claims['sub'],user_name=user.get('username',claims['sub']),refresh_token=refresh or '')
 def HealthCheck(self,request,context): return pb.HealthCheckResponse(status='ok')
 def StartAuthSession(self,request,context):
  # Bound unauthenticated device sessions. Secrets are memory-only and expire.
  with self.lock:
   now=time.time(); self.pending={k:v for k,v in self.pending.items() if v['until']>now}
   if len(self.pending)>=128: context.abort(grpc.StatusCode.RESOURCE_EXHAUSTED,'Too many pending logins')
  try: device=self.request('POST',ISSUER+'/protocol/openid-connect/auth/device',data={'client_id':'lore-cli','scope':'openid profile'})
  except Exception: context.abort(grpc.StatusCode.UNAVAILABLE,'Login provider unavailable')
  code=secrets.token_urlsafe(32)
  with self.lock: self.pending[code]={'state':request.client_state,'device':device['device_code'],'until':time.time()+device['expires_in'],'interval':device.get('interval',5),'next_poll':0}
  return pb.StartAuthSessionResponse(session_code=code,login_url=device['verification_uri_complete'])
 def GetAuthSession(self,request,context):
  with self.lock: session=self.pending.get(request.session_code)
  if not session or not secrets.compare_digest(session['state'],request.client_state) or session['until']<time.time(): context.abort(grpc.StatusCode.UNAUTHENTICATED,'Login session expired')
  with self.lock:
   if time.time()<session['next_poll']: return pb.GetAuthSessionResponse()
   session['next_poll']=time.time()+session['interval']
  try:
   r=requests.post(ISSUER+'/protocol/openid-connect/token',verify=CA,timeout=15,data={'grant_type':'urn:ietf:params:oauth:grant-type:device_code','client_id':'lore-cli','device_code':session['device']})
   if not r.ok:
    if r.json().get('error') in ('authorization_pending','slow_down'): return pb.GetAuthSessionResponse()
    context.abort(grpc.StatusCode.UNAUTHENTICATED,'Login declined or expired')
   tokens=r.json(); token=tokens['access_token']; claims,user=self.verify(token,context)
  except grpc.RpcError: raise
  except Exception: context.abort(grpc.StatusCode.UNAVAILABLE,'Login provider unavailable')
  with self.lock: self.pending.pop(request.session_code,None)
  return pb.GetAuthSessionResponse(user_token=self.user_token(token,claims,user,tokens.get('refresh_token')))
 def RefreshAuthSession(self,request,context):
  if not request.refresh_token: context.abort(grpc.StatusCode.UNAUTHENTICATED,'Refresh credential required')
  try:
   tokens=self.request('POST',ISSUER+'/protocol/openid-connect/token',data={'grant_type':'refresh_token','client_id':'lore-cli','refresh_token':request.refresh_token})
   token=tokens['access_token']; claims,user=self.verify(token,context)
  except grpc.RpcError: raise
  except Exception: context.abort(grpc.StatusCode.UNAUTHENTICATED,'Session expired or revoked; log in again')
  return pb.RefreshAuthSessionResponse(user_token=self.user_token(token,claims,user,tokens.get('refresh_token')))
 def VerifyUser(self,request,context):
  _,claims,user=self.principal(context)
  return pb.VerifyUserResponse(user_info=pb.UserInfo(user_id=claims['sub'],display_name=user['username']))
 def ExchangeExternalTokenForUserToken(self,request,context):
  if request.token_type not in ('lore','keycloak'): context.abort(grpc.StatusCode.INVALID_ARGUMENT,'Unsupported token type')
  claims,user=self.verify(request.external_token,context)
  return pb.ExchangeExternalTokenForUserTokenResponse(user_token=self.user_token(request.external_token,claims,user))
 def ExchangeUserTokenForMultiresourceToken(self,request,context):
  token,claims,user=self.principal(context)
  for resource in request.resource_id:
   if self.permission(user,resource) is None: context.abort(grpc.StatusCode.PERMISSION_DENIED,'No grant for repository')
  # Keycloak already signed the exact user grants. No local signing key exists.
  return pb.ExchangeUserTokenForMultiresourceTokenResponse(token=self.user_token(token,claims,user))
 def CheckUserPermission(self,request,context):
  _,claims,user=self.principal(context)
  if request.HasField('target_user') and request.target_user.user_token:
   target,_=self.verify(request.target_user.user_token,context)
   if target['sub']!=claims['sub']: context.abort(grpc.StatusCode.PERMISSION_DENIED,'Cannot check another identity')
  allowed=[]; denied=[]
  for resource in request.resource_id:
   permission=self.permission(user,resource)
   (allowed if permission is not None else denied).append(pb.ResourcePermission(resource_id=resource,permission=permission or []))
  return pb.CheckUserPermissionResponse(allowed_resource_permission=allowed,denied_resource_permission=denied)
 def LookupUserPermissions(self,request,context):
  _,_,user=self.principal(context)
  registry=json.load(open('/etc/lore-auth/repositories.json'))
  candidates=set('urc-'+rid for rid in registry.values())
  candidates.update(g.get('resource_id','') for g in self.grants(user) if g.get('resource_id')!='urc-*')
  entries=[]
  for resource in sorted(candidates):
   permission=self.permission(user,resource)
   pattern='urc-*' if request.resource_filter=='urc' else (request.resource_filter or '*')
   if permission is not None and fnmatch.fnmatchcase(resource,pattern):
    entries.append(pb.ResourcePermission(resource_id=resource,permission=permission))
  # Current deployments are small; return all candidates in one bounded response.
  if len(entries)>10000: context.abort(grpc.StatusCode.RESOURCE_EXHAUSTED,'Catalog too large')
  return pb.LookupUserPermissionsResponse(resource_permission=entries)
 def GetUserInfo(self,request,context):
  _,_,user=self.principal(context)
  if self.permission(user,request.resource_id) is None: context.abort(grpc.StatusCode.PERMISSION_DENIED,'No grant for repository')
  info=[]
  for uid in request.user_id[:100]:
   try: other=self.keycloak('users/'+requests.utils.quote(uid,safe='')); name=other['username']
   except Exception: name=uid
   info.append(pb.UserInfo(user_id=uid,display_name=name))
  return pb.GetUserInfoResponse(user_info=info)
 def GetUserId(self,request,context):
  _,_,user=self.principal(context)
  if self.permission(user,request.resource_id) is None: context.abort(grpc.StatusCode.PERMISSION_DENIED,'No grant for repository')
  users=self.keycloak('users?exact=true&username='+requests.utils.quote(request.user_display_name,safe=''))
  if len(users)!=1: context.abort(grpc.StatusCode.NOT_FOUND,'User not found')
  return pb.GetUserIdResponse(user_info=pb.UserInfo(user_id=users[0]['id'],display_name=users[0]['username']))
 def GetProviderUserId(self,request,context):
  _,claims,_=self.principal(context)
  if request.user_id!=claims['sub']: context.abort(grpc.StatusCode.PERMISSION_DENIED,'Cannot resolve another identity')
  return pb.GetProviderUserIdResponse(user_id=claims['sub'],provider_user_id=claims['sub'])
def main():
 server=grpc.server(ThreadPoolExecutor(max_workers=12),maximum_concurrent_rpcs=64,options=[('grpc.max_receive_message_length',1048576)])
 rpc.add_UrcAuthApiServicer_to_server(Bridge(),server)
 credentials=grpc.ssl_server_credentials([(open('/etc/lore-auth/tls/server.key','rb').read(),open('/etc/lore-auth/tls/server.crt','rb').read())])
 listen=CONFIG.get('listen','10.8.0.1:8444')
 if not server.add_secure_port(listen,credentials): raise RuntimeError('Could not bind auth adapter')
 server.start(); logging.info('Lore auth adapter listening on VPN %s',listen); server.wait_for_termination()
if __name__=='__main__': main()
