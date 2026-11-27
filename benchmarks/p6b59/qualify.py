"""B59: actual Runner + native MCP + original composite service + isolated broker."""
import asyncio,hashlib,json,os,pathlib,shutil,sqlite3,subprocess,sys,tempfile,time,uuid
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as Key
from cryptography.hazmat.primitives import serialization
from broker59 import enc,parse,digest,DOMAIN,INTENT,PATH
from agents import Agent,Runner,RunConfig
from agents.mcp import MCPServerStdio
from agents.tool_context import ToolContext
from agents.testing import ScriptedModel,assistant_message,function_call
PINS={'library_toolkit/service.py':'8dcbc523ff94448f6a89dbf295a52c3a0d0f50b7','library_toolkit/catalog.json':'f87c53fe0b5cd08aa416513c9d8b01ab206c7b45'}
def blob(p):
    b=p.read_bytes();return hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()
def pub(k):return k.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()
def private(k):return k.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption()).hex()
def signed(k,domain,b):return dict(body=b,signature=k.sign(domain+enc(b)).hex())
def rows(p):return [parse(x) for x in pathlib.Path(p).read_bytes().splitlines()]
def dbstate(path):
    with sqlite3.connect(path.as_uri()+'?mode=ro',uri=True) as db:
        return dict(rows=[list(x) for x in db.execute('SELECT * FROM reading_items ORDER BY list_name,book_id')],receipts=[parse(x[0]) for x in db.execute('SELECT result FROM receipts ORDER BY seq')])
async def main(src,out):
    assert os.geteuid()==0
    src=pathlib.Path(src).resolve();out=pathlib.Path(out).resolve();out.mkdir(parents=True,exist_ok=True)
    assert subprocess.check_output(['git','-C',str(src),'rev-parse','HEAD'],text=True).strip()=='99ea07d1074eb06885ec1107029e48d83fe05e78'
    for p,h in PINS.items():assert blob(src/p)==h,p
    with tempfile.TemporaryDirectory(prefix='risu-b59-') as tmp:
        base=pathlib.Path(tmp);base.chmod(0o755)
        up=base/'upstream';shutil.copytree(src,up,ignore=shutil.ignore_patterns('.git','.env','__pycache__'))
        for p in up.rglob('*'):p.chmod(0o755 if p.is_dir() else 0o644)
        code=base/'code';code.mkdir(mode=0o755)
        for p in ('broker59.py','handler.py','relay.py'):shutil.copyfile(pathlib.Path(__file__).with_name(p),code/p)
        for d,uid,mode in [('db',65532,0o700),('socket',65532,0o755),('handler',65533,0o700)]:
            p=base/d;p.mkdir(mode=mode);os.chown(p,uid,uid)
        db=base/'db'/'reading.sqlite3';sock=base/'socket'/'broker.sock'
        owner,actor,path=Key.generate(),Key.generate(),Key.generate()
        scope='campusreads:'+uuid.uuid4().hex;run=uuid.uuid4().hex
        trust=dict(scope=scope,run=run,pub=pub(owner),actor_pub=pub(actor),path_pub=pub(path))
        bc=dict(trust,db=str(db),socket=str(sock),client_uid=65533,books=['B001','B002','B003','B004','B005','B006'],crash='none')
        cfg=base/'broker.json';cfg.write_bytes(enc(bc));cfg.chmod(0o644)
        hc=dict(scope=scope,run=run,owner_pub=pub(owner),actor_pub=pub(actor),path_key=private(path),socket=str(sock),upstream=str(up),log=str(base/'handler'/'events.jsonl'))
        hcfg=base/'handler'/'config.json';hcfg.write_bytes(enc(hc));os.chown(hcfg,65533,65533);hcfg.chmod(0o600)
        (out/'trust.json').write_bytes(enc(trust))
        def envelope(cid,op,args,book='B004'):
            parent=dict(tool='plan_reading',arguments=args)
            p=signed(owner,DOMAIN,dict(scope=scope,op=op,attempt=cid,parent=parent,child=dict(book_id=book,list_name='demo')))
            i=signed(actor,INTENT,dict(call=cid,run=run,permit_sha256=digest(p),parent=parent))
            return dict(permit=p,intent=i)
        args=dict(query='machine learning',list_name='demo')
        cases=[
          ('first',args,envelope('first','op1',args),False),
          ('retry',args,envelope('retry','op1',args),False),
          ('wrong-child',args,envelope('wrong-child','op2',args,'B001'),True),
          ('wrong-parent',dict(query='agents',list_name='demo'),envelope('wrong-parent','op3',args),True),
          ('missing',args,None,True),
          ('bad-intent',args,envelope('bad-intent','op4',args),True),
          ('replay',args,None,True),
          ('no-match',dict(query='underwater basket weaving',list_name='demo'),envelope('no-match','op5',dict(query='underwater basket weaving',list_name='demo')),True)]
        sig=cases[5][2]['intent']['signature'];cases[5][2]['intent']['signature']=('00' if sig[:2]!='00' else '01')+sig[2:]
        cases[6]=('replay',args,cases[0][2],True)
        case_map={cid:(a,e,bad) for cid,a,e,bad in cases};resolution=[];outputs=[]
        def resolver(ctx):
            rc=ctx.run_context
            assert isinstance(rc,ToolContext)
            cid=rc.tool_call_id;a,e,_=case_map[cid]
            assert ctx.tool_name=='plan_reading' and ctx.arguments==a
            resolution.append(dict(call=cid,args=a,envelope=e,context=type(rc).__name__))
            return {'risu_b59':e} if e is not None else None
        proc=None
        def start():
            nonlocal proc
            sock.unlink(missing_ok=True)
            proc=subprocess.Popen([sys.executable,str(code/'broker59.py'),str(cfg)],user=65532,group=65532,extra_groups=[],cwd=base)
            for _ in range(200):
                if proc.poll() is not None:raise RuntimeError('broker start failed')
                if sock.exists():return
                time.sleep(.05)
            raise RuntimeError('broker timeout')
        def stop():
            nonlocal proc
            if proc is not None:proc.terminate();assert proc.wait(timeout=10) in (-15,0);proc=None
        try:
            start()
            async with MCPServerStdio(params={'command':sys.executable,'args':[str(code/'relay.py'),str(base)]},name='B59 native',tool_meta_resolver=resolver,use_structured_content=True,cache_tools_list=True,max_retry_attempts=0) as server:
                tools=await server.list_tools();assert len(tools)==1 and tools[0].name=='plan_reading' and set(tools[0].input_schema['properties'])=={'query','list_name'}
                for cid,a,e,bad in cases:
                    model=ScriptedModel([[function_call('plan_reading',a,call_id=cid)],[assistant_message('fixture finished')]])
                    agent=Agent(name='B59 native',model=model,mcp_servers=[server])
                    await asyncio.wait_for(Runner.run(agent,'Execute fixture.',run_config=RunConfig(tracing_disabled=True)),30)
                    model.assert_complete()
                    o=[x for x in model.last_call.input if isinstance(x,dict) and x.get('type')=='function_call_output']
                    assert len(o)==1 and o[0]['call_id']==cid
                    outputs.extend(o);(out/'outputs.json').write_bytes(enc(outputs))
            ingress=[x for x in rows(base/'ingress.jsonl') if x.get('method')=='tools/call']
            rawreply=rows(base/'reply.jsonl');replies={enc(x['id']):x['result'] for x in rawreply if 'id' in x and 'result'in x}
            events=rows(base/'handler'/'events.jsonl');parents=[x for x in events if x['event']=='PARENT']
            assert len(ingress)==len(parents)==len(outputs)==len(resolution)==8
            assert len({enc(x['id']) for x in ingress})==8
            for (cid,a,e,bad),wire,par,o,res in zip(cases,ingress,parents,outputs,resolution):
                assert wire['id']==par['id'] and wire['params']['arguments']==a==par['arguments']
                assert (wire['params'].get('_meta') or {}).get('risu_b59')==par['envelope']==e==res['envelope']
                r=replies[enc(wire['id'])];assert bool(r.get('isError',False))==bad,(cid,r)
                if not bad:
                    assert json.loads(o['output'])==r['structuredContent']
                else:assert o['output'],cid
                print('B59_NATIVE',cid,wire['id'],'ERROR' if bad else 'SUCCESS',flush=True)
            assert len({x['connection'] for x in parents})==1
            children=[x for x in events if x['event']=='CHILD']
            assert len(children)==4
            state=dbstate(db);assert len(state['rows'])==1 and state['rows'][0][:2]==['demo','B004']
            assert [x['status'] for x in state['receipts']]==['EFFECT_ATTRIBUTED','OTHER_ATTEMPT_WON']
            # Direct bypass checks are actual separate OS processes, not handler invocations.
            def direct(uid,script,input=None):
                x=subprocess.run([sys.executable,'-c',script],input=enc(input) if input is not None else None,capture_output=True,cwd=base,user=uid,group=uid,extra_groups=[],timeout=15)
                return dict(exit=x.returncode,stdout=x.stdout.decode(),stderr=x.stderr.decode())
            req=dict(permit=cases[0][2]['permit'],child=dict(book_id='B004',list_name='demo'),proof=children[0]['proof'])
            callscript="import sys,json;sys.path.insert(0,"+repr(str(code))+");from broker59 import call;q=json.load(sys.stdin);print(json.dumps(call("+repr(str(sock))+",q['permit'],q['child'],q['proof'])))"
            controls=[]
            def check(name,x,token,expected_exit=0):
                assert x['exit']==expected_exit and token in x['stdout']+x['stderr'],(name,x)
                controls.append(dict(name=name,result=x));print('B59_CONTROL',name,flush=True)
            check('untrusted-valid-proof',direct(65534,callscript,req),'PEER_DENIED')
            check('untrusted-raw-db',direct(65534,"import sqlite3;sqlite3.connect("+repr(str(db))+").execute(\"INSERT INTO reading_items VALUES('demo','B006','bypass')\")"),'unable to open database',1)
            check('untrusted-handler-key',direct(65534,"open("+repr(str(hcfg))+").read()"),'PermissionError',1)
            forged=json.loads(json.dumps(req));sig=forged['proof']['signature'];forged['proof']['signature']=('00' if sig[:2]!='00' else '01')+sig[2:]
            check('trusted-peer-forged-proof',direct(65533,callscript,forged),'INVALID_PROOF_SIGNATURE')
            stop();start()
            check('exact-proof-recovery',direct(65533,callscript,req),'"replay": true')
            assert dbstate(db)==state
            stop()
            with sqlite3.connect(db.as_uri()+'?mode=ro',uri=True) as source,sqlite3.connect(out/'destination.sqlite3') as dest:
                assert source.execute('PRAGMA integrity_check').fetchone()==('ok',);source.backup(dest)
            for p,h in PINS.items():assert blob(up/p)==h
            for f,n in [(base/'ingress.jsonl','ingress.jsonl'),(base/'reply.jsonl','reply.jsonl'),(base/'handler'/'events.jsonl','handler.jsonl')]:shutil.copyfile(f,out/n)
            (out/'resolution.json').write_bytes(enc(resolution));(out/'controls.json').write_bytes(enc(controls))
            (out/'summary.json').write_bytes(enc(dict(cases=8,controls=5,rows=1,receipts=2,source_pins=PINS,state=state)))
            print('B59_PASS 8 native cases 5 controls 1 row 2 receipts',flush=True)
        finally:stop()
if __name__=='__main__':asyncio.run(main(*sys.argv[1:]))
