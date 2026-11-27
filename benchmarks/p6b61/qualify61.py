"""B61 actual native calls, crash/reconciliation, role isolation."""
import asyncio,hashlib,json,os,pathlib,shutil,sqlite3,subprocess,sys,tempfile,time,uuid
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as Key
from cryptography.hazmat.primitives import serialization
from lifecycle import enc,parse,digest,DOMAIN
from broker61 import call
from agents import Agent,Runner,RunConfig
from agents.mcp import MCPServerStdio
from agents.tool_context import ToolContext
from agents.testing import ScriptedModel,assistant_message,function_call
POL=b'RISU-B61-parent-policy-v1\0';INT=b'RISU-B61-actor-intent-v1\0'
PINS={'library_toolkit/service.py':'8dcbc523ff94448f6a89dbf295a52c3a0d0f50b7','library_toolkit/catalog.json':'f87c53fe0b5cd08aa416513c9d8b01ab206c7b45'}
def blob(p):
    b=p.read_bytes();return hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()
def pub(k):return k.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()
def private(k):return k.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption()).hex()
def sign(k,d,b):return dict(body=b,signature=k.sign(d+enc(b)).hex())
def frames(p):return [parse(x) for x in p.read_bytes().splitlines()] if p.exists() else []
def state(db):
    with sqlite3.connect(db.as_uri()+'?mode=ro',uri=True) as c:
        return dict(ops=[list(x) for x in c.execute('SELECT op,state,winner FROM ops ORDER BY op')],attempts=[list(x) for x in c.execute('SELECT attempt,op,state,finish,ack FROM attempts ORDER BY attempt')],rows=[list(x) for x in c.execute('SELECT list_name,book_id FROM reading_items ORDER BY book_id')],events=c.execute('SELECT count(*) FROM events').fetchone()[0])
async def main(src,out):
    assert os.geteuid()==0
    src=pathlib.Path(src).resolve();out=pathlib.Path(out).resolve();out.mkdir(parents=True,exist_ok=True)
    assert subprocess.check_output(['git','-C',str(src),'rev-parse','HEAD'],text=True).strip()=='99ea07d1074eb06885ec1107029e48d83fe05e78'
    for p,h in PINS.items():assert blob(src/p)==h
    with tempfile.TemporaryDirectory(prefix='risu-b61-') as tmp:
        base=pathlib.Path(tmp);base.chmod(0o755)
        up=base/'upstream';shutil.copytree(src,up,ignore=shutil.ignore_patterns('.git','.env','__pycache__'))
        for p in up.rglob('*'):p.chmod(0o755 if p.is_dir() else 0o644)
        code=base/'code';code.mkdir(mode=0o755)
        for n in ('lifecycle.py','broker61.py','handler61.py','relay61.py'):shutil.copyfile(pathlib.Path(__file__).with_name(n),code/n)
        for n,uid,mode in [('db',65532,0o700),('socket',65532,0o755),('handler',65533,0o700)]:
            p=base/n;p.mkdir(mode=mode);os.chown(p,uid,uid)
        db=base/'db'/'lifecycle.sqlite3';sock=base/'socket'/'broker.sock';blog=base/'db'/'broker.jsonl'
        owner,actor,handler=Key.generate(),Key.generate(),Key.generate();scope=uuid.uuid4().hex;run=uuid.uuid4().hex
        trust=dict(scope=scope,owner=pub(owner),actor=pub(actor),handler=pub(handler),books=['B001','B002','B003','B004','B005','B006'])
        bc=base/'broker.json';bc.write_bytes(enc(dict(db=str(db),socket=str(sock),log=str(blog),trust=trust)));bc.chmod(0o644)
        (out/'trust.json').write_bytes(enc(trust))
        proc=subprocess.Popen([sys.executable,str(code/'broker61.py'),str(bc)],cwd=base,user=65532,group=65532,extra_groups=[])
        for _ in range(200):
            if proc.poll() is not None:raise RuntimeError('broker failed')
            if sock.exists():break
            time.sleep(.05)
        else:raise RuntimeError('broker timeout')
        policies={};records=[]
        def admin(op,kind,k=owner,**kw):
            r=call(str(sock),sign(k,DOMAIN,dict(scope=scope,op=op,kind=kind,**kw)));assert r['ok'],r;return r['result']
        def opened(op,book):
            args=dict(query=book,list_name='demo');steps=[dict(book_id=book,list_name='demo')]
            admin(op,'OPEN',steps=steps);policies[op]=sign(owner,POL,dict(scope=scope,op=op,args=args,steps=steps));return args
        def envelope(op,cid):
            p=policies[op];return dict(policy=p,intent=sign(actor,INT,dict(run=run,call=cid,policy=digest(p))))
        def attempt(cid):
            with sqlite3.connect(db.as_uri()+'?mode=ro',uri=True) as c:
                r=c.execute('SELECT op,start,state,finish,output FROM attempts WHERE attempt=?',(cid,)).fetchone()
            return r
        async def case(cid,op,args,mode='none',error=None,reuse=None):
            d=base/cid;d.mkdir();hlog=base/'handler'/(cid+'.jsonl')
            cfg=base/'handler'/(cid+'.json');cfg.write_bytes(enc(dict(upstream=str(up),key=private(handler),trust=trust,socket=str(sock),run=run,log=str(hlog),mode=mode)));os.chown(cfg,65533,65533);cfg.chmod(0o600)
            env=envelope(op,cid) if reuse is None else reuse
            seen=[]
            def resolver(ctx):
                assert isinstance(ctx.run_context,ToolContext) and ctx.run_context.tool_call_id==cid
                assert ctx.arguments==args and ctx.tool_name=='plan_reading'
                seen.append(cid);return {'risu_b61':env}
            before=state(db);output=None;exception=None
            model=ScriptedModel([[function_call('plan_reading',args,call_id=cid)],[assistant_message('fixture finished')]])
            try:
                async with MCPServerStdio(params={'command':sys.executable,'args':[str(code/'relay61.py'),str(base),cid]},name='B61',tool_meta_resolver=resolver,use_structured_content=True,cache_tools_list=True,max_retry_attempts=0,client_session_timeout_seconds=10) as server:
                    await server.list_tools()
                    await asyncio.wait_for(Runner.run(Agent(name='B61',model=model,mcp_servers=[server]),'Execute fixture.',run_config=RunConfig(tracing_disabled=True)),20)
                    o=[x for x in model.last_call.input if isinstance(x,dict) and x.get('type')=='function_call_output']
                    if o:assert len(o)==1 and o[0]['call_id']==cid;output=o[0]
            except Exception as ex:exception=type(ex).__name__+':'+str(ex)
            after=state(db);ing=frames(d/'ingress.jsonl');rep=frames(d/'reply.jsonl');events=frames(hlog)
            wire=[x for x in ing if x.get('method')=='tools/call'];assert seen==[cid] and len(wire)==1,(cid,seen,wire,exception)
            rid=wire[0]['id'];parent=[x for x in events if x['stage']=='PARENT'];assert len(parent)==1 and parent[0]['id']==rid and parent[0]['envelope']==env
            assert wire[0]['params']['arguments']==args==parent[0]['args'] and wire[0]['params']['_meta']['risu_b61']==env
            replies=[x for x in rep if x.get('id')==rid and ('result'in x or 'error'in x)]
            rc=int((d/'exit.txt').read_text())
            if mode!='none':
                assert rc=={'START':81,'STEP':82,'FINISH':83}[mode] and not replies,(cid,rc,replies)
                ar=attempt(cid);assert ar and ar[2]==('COMPLETE' if mode=='FINISH' else 'STARTED')
            else:
                assert exception is None and len(replies)==1 and output is not None,(cid,exception,replies,output)
                res=replies[0]['result'];assert bool(res.get('isError',False))==(error is not None)
                if error:assert error in json.dumps(res) and error in json.dumps(output),(cid,res,output)
                else:
                    val=output['output'];val=val[0]['text'] if isinstance(val,list) else val
                    assert json.loads(val)==json.loads(res['content'][0]['text'])
                    ar=attempt(cid);assert ar[2]=='COMPLETE'
                    assert json.loads(val)['output']==parse(ar[4])
                    admin(op,'ACK',k=actor,attempt=cid,finish=ar[3],output_hash=digest(parse(ar[4])))
            record=dict(call=cid,op=op,mode=mode,error=error,exit=rc,exception=exception,output=output,before=before,after=after,native_id=rid,connection=parent[0]['connection'],envelope=env,handler=events)
            records.append(record);(out/'cases.json').write_bytes(enc(records))
            dest=out/cid;dest.mkdir()
            for n in ('ingress.jsonl','reply.jsonl','exit.txt'):shutil.copyfile(d/n,dest/n)
            shutil.copyfile(hlog,dest/'handler.jsonl')
            print('B61_CASE',cid,mode,rc,'rows',len(after['rows']),flush=True)
            return env
        try:
            a=opened('normal','B001');old=await case('normal','normal',a)
            a=opened('start','B002');await case('start-crash','start',a,'START')
            assert len(state(db)['rows'])==1
            admin('start','ABANDON',attempt='start-crash',start=attempt('start-crash')[1]);await case('start-recover','start',a)
            a=opened('child','B003');await case('child-crash','child',a,'STEP')
            assert len(state(db)['rows'])==3
            admin('child','ABANDON',attempt='child-crash',start=attempt('child-crash')[1]);await case('child-recover','child',a)
            assert len(state(db)['rows'])==3
            a=opened('finish','B004');await case('finish-crash','finish',a,'FINISH')
            assert len(state(db)['rows'])==4
            # Read original persisted completion without claiming original wire delivery.
            ar=attempt('finish-crash');(out/'recovery.json').write_bytes(enc(dict(attempt='finish-crash',finish=ar[3],output=parse(ar[4]),original_delivery=False)))
            a=opened('revoke','B005');await case('revoke-crash','revoke',a,'STEP')
            admin('revoke','REVOKE');await case('revoke-retry','revoke',a,error='OP_CLOSED')
            a=opened('bad','B006');await case('wrong-parent','bad',dict(query='B001',list_name='demo'),error='PARENT_BINDING')
            await case('old-intent','normal',dict(query='B001',list_name='demo'),error='OP_CLOSED',reuse=old)
            # Real UID bypass, with valid handler event captured in preceding record.
            e=next(x['event'] for x in records[0]['handler'] if x['stage']=='STEP')
            script="import sys,json;sys.path.insert(0,"+repr(str(code))+");from broker61 import call;print(json.dumps(call("+repr(str(sock))+",json.load(sys.stdin))))"
            x=subprocess.run([sys.executable,'-c',script],input=enc(e),capture_output=True,user=65534,group=65534,extra_groups=[],cwd=base);assert x.returncode==0 and parse(x.stdout)['error']=='PEER_DENIED'
            y=subprocess.run([sys.executable,'-c',"import sqlite3;sqlite3.connect("+repr(str(db))+").execute(\"INSERT INTO reading_items VALUES('demo','B006')\")"],capture_output=True,user=65534,group=65534,extra_groups=[],cwd=base);assert y.returncode!=0 and b'unable to open database'in y.stderr
            (out/'controls.json').write_bytes(enc(dict(peer=parse(x.stdout),db_exit=y.returncode,db_error=y.stderr.decode())))
            s=state(db);assert s['rows']==[['demo','B00'+str(i)] for i in range(1,6)]
            assert len([r for r in s['attempts'] if r[2]=='COMPLETE'])==4
            assert len([r for r in s['attempts'] if r[4] is not None])==3
            assert len([r for r in s['attempts'] if r[2]=='ABANDONED'])==2
            assert len([r for r in s['attempts'] if r[2]=='STARTED'])==1
            with sqlite3.connect(db.as_uri()+'?mode=ro',uri=True) as c,sqlite3.connect(out/'destination.sqlite3') as dst:c.backup(dst)
            for p,h in PINS.items():assert blob(up/p)==h
            (out/'summary.json').write_bytes(enc(dict(cases=len(records),controls=2,state=s,source_pins=PINS)))
            print('B61_PASS',len(records),'native cases 2 controls',s,flush=True)
        finally:
            proc.terminate();proc.wait(timeout=10)
            if blog.exists():shutil.copyfile(blog,out/'broker.jsonl')
if __name__=='__main__':asyncio.run(main(*sys.argv[1:]))
