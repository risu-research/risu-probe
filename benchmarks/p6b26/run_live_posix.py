"""B26 end-to-end live OS, HTTP and SQLite test. Run on disposable Linux CI as root.

Root is the fixture administrator, outside the attacker threat model. The
issuer, resource service, agent and second attacker are distinct OS UIDs.
No third-party user or production cloud authority is simulated as real.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

NAMES={'issuer':'risub26iss','service':'risub26svc','agent':'risub26agt','attacker':'risub26atk'}
SOURCE=Path(__file__).resolve().parents[2]/'src/risu_mcp_resource_guard.py'

def sha(b):return hashlib.sha256(b).hexdigest()
def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def write(path,obj,uid=None):
    path.write_bytes(canonical(obj)+b'\n')
    if uid is not None:os.chown(path,uid,pwd.getpwnam(NAMES['agent']).pw_gid if uid==pwd.getpwnam(NAMES['agent']).pw_uid else pwd.getpwuid(uid).pw_gid)
    os.chmod(path,0o600 if uid is not None else 0o644)

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--out',required=True)
    args=parser.parse_args()
    if os.geteuid()!=0 or sys.platform!='linux':raise SystemExit('B26 requires ephemeral disposable Linux root runner')
    for name in NAMES.values():
        try:pwd.getpwnam(name)
        except KeyError:subprocess.run(['useradd','--system','--no-create-home','--shell','/usr/sbin/nologin',name],check=True)
    people={k:pwd.getpwnam(v) for k,v in NAMES.items()}
    def drop(role):
        p=people[role]
        def run():
            os.setgroups([])
            os.setgid(p.pw_gid)
            os.setuid(p.pw_uid)
        return run
    def runcmd(role,*argv,timeout=20):
        p=subprocess.run([sys.executable,str(runtime),*argv],
             preexec_fn=drop(role),cwd=str(work),env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'},
             text=True,capture_output=True,timeout=timeout)
        if p.returncode:
            raise RuntimeError(f'B26 {role} process failed: {p.returncode}: {p.stderr[-2000:]}')
        return p.stdout.strip()
    def mkfile(path,data,role):
        path.write_bytes(data if isinstance(data,bytes) else canonical(data)+b'\n')
        os.chown(path,people[role].pw_uid,people[role].pw_gid)
        os.chmod(path,0o600)
        return path
    work=Path(tempfile.mkdtemp(prefix='risu-b26-live-'))
    os.chmod(work,0o755)
    for role in NAMES:
        d=work/role;d.mkdir()
        os.chown(d,people[role].pw_uid,people[role].pw_gid)
        os.chmod(d,0o700)
    shared=work/'shared';shared.mkdir(mode=0o755)
    runtime=work/'b26_service.py';shutil.copy2(SOURCE,runtime);os.chmod(runtime,0o644)
    out=Path(args.out).resolve();out.mkdir(parents=True,exist_ok=True)
    results=[]
    print('B26 live fixture root',work,flush=True)
    issuer=work/'issuer';agent=work/'agent';attacker=work/'attacker';service=work/'service'
    runcmd('issuer','genkey','--key-file',str(issuer/'private.key'),'--public-file',str(issuer/'public.b64'))
    runcmd('agent','genkey','--key-file',str(agent/'private.key'),'--public-file',str(agent/'public.b64'))
    runcmd('attacker','genkey','--key-file',str(attacker/'private.key'),'--public-file',str(attacker/'public.b64'))
    pub=(issuer/'public.b64').read_text().strip()
    holder_pub=(agent/'public.b64').read_text().strip()
    (shared/'issuer_public.b64').write_text(pub+'\n')
    os.chmod(shared/'issuer_public.b64',0o644)
    # Issuer private material is inaccessible to the resource service and agent.
    db=service/'owner_resources.sqlite3'
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    server_log=(out/'resource_server.log').open('w')
    proc=None
    def start_server():
        return subprocess.Popen([sys.executable,str(runtime),'serve',
               '--public-file',str(shared/'issuer_public.b64'),'--db',str(db),
               '--port',str(port)],preexec_fn=drop('service'),cwd=str(work),
               env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'},
               stdin=subprocess.DEVNULL,stdout=server_log,stderr=server_log,
               start_new_session=True)
    def stop_server(process):
        if process and process.poll() is None:
            process.terminate()
            try:process.wait(timeout=7)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=4)
    url=f'http://127.0.0.1:{port}'
    def wait_ready():
        for _ in range(100):
            try:
                with urllib.request.urlopen(url+'/state',timeout=.5) as response:
                    if response.status==200:return json.loads(response.read())
            except Exception:time.sleep(.1)
        raise RuntimeError('owner resource server never ready')
    def signed_grant(case,policy):
        file=shared/f'{case}.policy.json';write(file,policy)
        dest=issuer/f'{case}.grant.json'
        runcmd('issuer','issue','--key-file',str(issuer/'private.key'),
               '--input',str(file),'--output',str(dest))
        return json.loads(dest.read_text())
    def envelope(case,grant,resource='alpha',value='alpha-authorized',role='agent',method='REPLACE'):
        d=work/role
        gf=mkfile(d/f'{case}.grant.json',grant,role)
        request={'schema':'risu-b26-resource-bound-request-v1','resource':resource,
                 'method':method,'url_path':'/effect','desired_value':value,
                 'request_id':secrets.token_hex(32),'grant_sha256':sha(canonical(grant))}
        rf=mkfile(d/f'{case}.request.json',request,role)
        pf=d/f'{case}.envelope.json'
        runcmd(role,'make-proof','--key-file',str(d/'private.key'),
                '--grant',str(gf),'--input',str(rf),'--output',str(pf))
        return json.loads(pf.read_text())
    def send_case(case,payload,expected,role='agent'):
        d=work/role
        inp=mkfile(d/f'{case}.send.json',payload,role)
        outcome=d/f'{case}.out.json'
        runcmd(role,'send','--url',url,'--input',str(inp),'--output',str(outcome))
        val=json.loads(outcome.read_text())
        if val['http_status']!=expected:
            raise RuntimeError(f'{case}: expected HTTP {expected}, got {val}')
        results.append({'case':case,'http_status':val['http_status'],
                        'effect':val['body'].get('status'),
                        'code':val['body'].get('code')})
        print('B26_CASE',case,val['http_status'],val['body'].get('code',val['body'].get('status')),flush=True)
        return val
    try:
        proc=start_server()
        initial=wait_ready()
        assert initial['resources']=={'alpha':'alpha-original','beta':'beta-protected'} and initial['used_nonces']==[]
        agent_uid=people['agent'].pw_uid
        # Verify by real OS UID that no agent credential can access the service DB or issuer secret.
        probe_code='''import json,sys
from pathlib import Path
checks={}
for name,path,mode in (('resource_db_read',sys.argv[1],'rb'),('resource_db_write',sys.argv[1],'ab'),('owner_issuer_private_key',sys.argv[2],'rb')):
 try:
  with open(path,mode) as handle:
   if mode=='rb':handle.read(1)
   else:handle.write(b'B26_UNAUTHORIZED_APPEND')
  checks[name]='UNSAFE_ACCESS_ALLOWED'
 except PermissionError:checks[name]='DENIED_BY_POSIX_DAC'
print(json.dumps(checks))'''
        p=subprocess.run([sys.executable,'-c',probe_code,str(db),str(issuer/'private.key')],
                         preexec_fn=drop('agent'),text=True,capture_output=True,timeout=8)
        assert p.returncode==0,p.stderr
        os_result=json.loads(p.stdout)
        assert set(os_result.values())=={'DENIED_BY_POSIX_DAC'}
        now=int(time.time())
        policy={'schema':'risu-b26-owner-object-grant-v1',
            'audience':'risu-b26-local-owner-resource-service-a',
            'issuer':'risu-b26-posix-owner-issuer','resource':'alpha',
            'subject_public_key':holder_pub,'method':'REPLACE',
            'expected_pre_sha256':sha(b'alpha-original'),
            'desired_sha256':sha(b'alpha-authorized'),
            'nonce':secrets.token_hex(32),'not_before':now-2,
            'expires_at':now+110,'url_path':'/effect'}
        grant=signed_grant('primary',policy)
        approved=envelope('approved',grant)
        send_case('no_grant',{'request':approved['request']},422)
        forged=json.loads(json.dumps(grant));forged['signature']='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=='
        send_case('forged_issuer_signature',envelope('forged',forged),403)
        send_case('stolen_grant_wrong_client_key',envelope('stolen',grant,role='attacker'),403,role='attacker')
        send_case('compromised_client_other_object',envelope('other_object',grant,resource='beta',value='beta-corrupt'),403)
        send_case('compromised_client_other_bytes',envelope('other_bytes',grant,value='alpha-corrupt'),403)
        send_case('compromised_client_other_method',envelope('other_method',grant,method='DELETE'),403)
        future=dict(policy);future['nonce']=secrets.token_hex(32);future['not_before']=now+25;future['expires_at']=now+100
        fgrant=signed_grant('future',future)
        send_case('owner_issued_future_grant',envelope('future',fgrant),403)
        expired=dict(policy);expired['nonce']=secrets.token_hex(32);expired['not_before']=now-110;expired['expires_at']=now-10
        egrant=signed_grant('expired',expired)
        send_case('owner_issued_expired_grant',envelope('expired',egrant),403)
        # Test a race of two genuine calls from two processes with the SAME valid grant.
        ep=mkfile(agent/'concurrent.envelope.json',approved,'agent')
        outs=[agent/f'concurrent.{i}.out.json' for i in range(2)]
        children=[subprocess.Popen([sys.executable,str(runtime),'send',
                 '--url',url,'--input',str(ep),'--output',str(out)],
                 preexec_fn=drop('agent'),cwd=str(work),
                 env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'},
                 stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True) for out in outs]
        for child in children:
            stdout,stderr=child.communicate(timeout=12)
            assert child.returncode==0,(stdout,stderr)
        res=[json.loads(path.read_text()) for path in outs]
        assert sorted(r['http_status'] for r in res)==[200,409],res
        results.extend({'case':f'concurrent_same_grant_{i}','http_status':r['http_status'],
                        'effect':r['body'].get('status'),
                        'code':r['body'].get('code')} for i,r in enumerate(res))
        print('B26_CONCURRENT_SAME_OWNER_GRANT',sorted(r['http_status'] for r in res),flush=True)
        send_case('consumed_grant_replay',approved,409)
        stale=dict(policy);stale['nonce']=secrets.token_hex(32)
        sgrant=signed_grant('stale',stale)
        send_case('fresh_grant_stale_prestate',envelope('stale',sgrant),409)
        before_restart=wait_ready()
        assert before_restart['resources']=={'alpha':'alpha-authorized','beta':'beta-protected'}
        assert before_restart['used_nonces']==[policy['nonce']]
        stop_server(proc);proc=start_server();after_restart=wait_ready()
        assert after_restart==before_restart
        send_case('replay_after_resource_server_restart',approved,409)
        final=wait_ready()
        assert final==before_restart
        status={
            'schema':'risu-b26-real-posix-http-sqlite-resource-side-effect-v1',
            'trust_boundary':'SEPARATE_OS_UID_FIXTURE_ISSUER_SERVICE_AGENT_ATTACKER',
            'claim':'RESOURCE_SERVER_DENIED_OUT_OF_SCOPE_EVEN_FROM_VALID_SUBJECT_KEY',
            'root_fixture_administrator_outside_attacker_model':True,
            'real_external_service_owner':'NOT_TESTED',
            'real_independent_human_authorization':'NOT_TESTED',
            'issuer_uid':people['issuer'].pw_uid,
            'resource_service_uid':people['service'].pw_uid,
            'agent_uid':people['agent'].pw_uid,
            'attacker_uid':people['attacker'].pw_uid,
            'issuer_public_key_b64':pub,
            'resource_db_path':str(db),
            'resource_db_file_owner_uid':db.stat().st_uid,
            'resource_db_file_mode':oct(db.stat().st_mode & 0o777),
            'resource_service_data_dir_mode':oct(service.stat().st_mode & 0o777),
            'posix_agent_access':os_result,
            'owner_grant':grant,
            'successful_request_envelope':approved,
            'expected_before':initial,
            'actual_after':final,
            'expected_authorized_commit_hash':sha(b'alpha-authorized'),
            'cases':results,
            'number_of_http_requests':len(results),
            'number_of_successful_writes':sum(z['http_status']==200 for z in results),
            'number_of_failed_client_requests':sum(z['http_status']!=200 for z in results)}
        write(out/'original_live_result.json',status)
        shutil.copy2(db,out/'owner_resources.sqlite3')
        os.chmod(out/'owner_resources.sqlite3',0o600)
        print('B26_REAL_OWNER_SIDE_EFFECT_AND_BYPASS_DENIAL_PASS',json.dumps({
             'cases':len(results),'allowed':status['number_of_successful_writes'],
             'denied':status['number_of_failed_client_requests']},sort_keys=True),flush=True)
    finally:
        stop_server(proc)
        server_log.close()
        # Do not export signing secrets or credentials; ephemeral fixture is destroyed.
        shutil.rmtree(work)

if __name__=='__main__':main()
