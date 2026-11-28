"""Trusted local relay signs the exact SDK native request ID; captures both boundaries."""
import sys,os,pathlib,threading,subprocess
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import gate64 as G
import lifecycle as L
from issuer64 import issue
from broker65 import call
base=pathlib.Path(sys.argv[1]);name=sys.argv[2];d=base/name
c=G.parse((d/'relay.json').read_bytes());actor=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(c['actor_key']))
p=subprocess.Popen([sys.executable,str(base/'code'/'handler65.py'),str(base/'handler'/(name+'.json'))],stdin=subprocess.PIPE,stdout=subprocess.PIPE,user=65533,group=65533,extra_groups=[],cwd=base)
def pump():
    try:
        with (d/'ingress.jsonl').open('ab') as f,(d/'forwarded.jsonl').open('ab') as g:
            for line in sys.stdin.buffer:
                f.write(line);f.flush();m=G.parse(line)
                if m.get('method')=='tools/call' and m['params']['name']=='plan_reading':
                    a=m['params']['arguments'];md=m['params']['_meta']['risu_b63'];pol=c['policy'];i=dict(scope=pol['body']['scope'],op=pol['body']['op'],attempt=md['model'],model=md['model'],connection=c['connection'],native=m['id'],parent=dict(tool='plan_reading',arguments=a),policy_hash=G.digest(pol))
                    m['params']['_meta']['risu_b63_signed']=dict(policy=pol,intent=G.sign(actor,G.INT,i));env=m['params']['_meta']['risu_b63_signed']
                    observed={k:i[k] for k in ('connection','native','parent','model')}
                    if c.get('retry'):
                        owner=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(c['owner_key']))
                        q,r=c['retry']
                        t=issue(c['client_db'],pol['body']['scope'],c['observer'],owner,q,r,env,observed)
                        m['params']['_meta']['risu_b65_ticket']=t
                        if c.get('intervene'):
                            e=G.sign(owner,L.DOMAIN,dict(scope=pol['body']['scope'],**c['intervene']))
                            decision=call(c['socket'],dict(kind='event',event=e));assert decision['ok'],decision
                            (d/'intervention.json').write_bytes(G.enc(dict(event=e,result=decision)))
                    line=G.enc(m)+b'\n'
                g.write(line);g.flush();p.stdin.write(line);p.stdin.flush()
    except BrokenPipeError:pass
    finally:
        try:p.stdin.close()
        except OSError:pass
threading.Thread(target=pump,daemon=True).start()
with (d/'reply.jsonl').open('ab') as f:
    for line in p.stdout:
        f.write(line);f.flush();sys.stdout.buffer.write(line);sys.stdout.buffer.flush()
rc=p.wait();(d/'exit.txt').write_text(str(rc));os._exit(rc if 0<=rc<=255 else 1)
