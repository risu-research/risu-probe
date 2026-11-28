"""B63 actual native SDK recovery: trusted client verifies before model-visible return."""
import asyncio,hashlib,json,os,pathlib,shutil,sqlite3,subprocess,sys,tempfile,time,uuid
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as Key
from cryptography.hazmat.primitives import serialization
import gate64 as G
import lifecycle as L
from client62 import RecoveryClient
from broker65 import call
from agents import Agent,Runner,RunConfig,function_tool
from agents.mcp import MCPServerStdio
from agents.tool_context import ToolContext
from agents.testing import ScriptedModel,assistant_message,function_call
from mcp import Client,StdioServerParameters
PINS={'library_toolkit/service.py':'8dcbc523ff94448f6a89dbf295a52c3a0d0f50b7','library_toolkit/catalog.json':'f87c53fe0b5cd08aa416513c9d8b01ab206c7b45'}
def blob(p):
    b=p.read_bytes();return hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()
def pub(k):return k.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()
def private(k):return k.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption()).hex()
def frames(p):return [G.parse(x) for x in p.read_bytes().splitlines()] if p.exists() else []
def read(p):return G.parse(p.read_bytes())
async def main(src,out):
    assert os.geteuid()==0
    src=pathlib.Path(src).resolve();out=pathlib.Path(out).resolve();out.mkdir(parents=True,exist_ok=True)
    assert subprocess.check_output(['git','-C',str(src),'rev-parse','HEAD'],text=True).strip()=='99ea07d1074eb06885ec1107029e48d83fe05e78'
    for p,h in PINS.items():assert blob(src/p)==h
    with tempfile.TemporaryDirectory(prefix='risu-b63-') as tmp:
        base=pathlib.Path(tmp);base.chmod(0o755);up=base/'upstream';shutil.copytree(src,up,ignore=shutil.ignore_patterns('.git','.env','__pycache__'))
        for p in up.rglob('*'):p.chmod(0o755 if p.is_dir() else 0o644)
        code=base/'code';code.mkdir(mode=0o755)
        for n in ('lifecycle.py','gate62.py','gate64.py','issuer64.py','client62.py','broker65.py','handler65.py','relay65.py'):shutil.copyfile(pathlib.Path(__file__).with_name(n),code/n)
        for n,uid,mode in [('db',65532,0o700),('socket',65532,0o755),('handler',65533,0o700)]:
            p=base/n;p.mkdir(mode=mode);os.chown(p,uid,uid)
        db=base/'db'/'gate.sqlite3';sock=base/'socket'/'broker.sock';owner,actor,handler,observer=[Key.generate() for _ in range(4)];scope=uuid.uuid4().hex
        trust=dict(scope=scope,owner=pub(owner),actor=pub(actor),handler=pub(handler),observer=pub(observer),books=['B001','B002','B003','B004','B005','B006'])
        cfg=base/'db'/'broker.json';cfg.write_bytes(G.enc(dict(db=str(db),socket=str(sock),trust=trust,observer_key=private(observer))));os.chown(cfg,65532,65532);cfg.chmod(0o600)
        (out/'trust.json').write_bytes(G.enc(trust))
        proc=subprocess.Popen([sys.executable,str(code/'broker65.py'),str(cfg)],cwd=base,user=65532,group=65532,extra_groups=[])
        for _ in range(200):
            if proc.poll() is not None:raise RuntimeError('broker failed')
            if sock.exists():break
            time.sleep(.05)
        else:raise RuntimeError('broker timeout')
        client=RecoveryClient(str(out/'client.sqlite3'),scope,actor,pub(observer));policies={};records=[];query_records=[];counter=0
        def rpc(req):
            x=call(str(sock),req);assert x['ok'],x;return x['result']
        def admin(op,kind,**kw):return rpc(dict(kind='event',event=G.sign(owner,L.DOMAIN,dict(scope=scope,op=op,kind=kind,**kw))))
        def opened(op,book):
            a=dict(query=book,list_name='demo');steps=[dict(book_id=book,list_name='demo')]
            admin(op,'OPEN',steps=steps);policies[op]=G.sign(owner,G.POL,dict(scope=scope,op=op,actor=pub(actor),parent=dict(tool='plan_reading',arguments=a),steps=steps));return a
        def rowcount():
            with sqlite3.connect(db.as_uri()+'?mode=ro',uri=True) as d:return d.execute('SELECT count(*) FROM reading_items').fetchone()[0]
        def conn(name,op=None,mode='none',retry=None,intervene=None):
            d=base/name;d.mkdir(mode=0o700);hlog=base/'handler'/(name+'.jsonl');c=uuid.uuid4().hex
            (d/'relay.json').write_bytes(G.enc(dict(connection=c,actor_key=private(actor),policy=policies.get(op),retry=retry,intervene=intervene,owner_key=private(owner) if retry else None,client_db=str(out/'client.sqlite3'),observer=pub(observer),socket=str(sock))))
            h=base/'handler'/(name+'.json');h.write_bytes(G.enc(dict(scope=scope,connection=c,mode=mode,upstream=str(up),handler_key=private(handler),socket=str(sock),log=str(hlog))));os.chown(h,65533,65533);h.chmod(0o600)
            return d,hlog,c
        def collect(name,d,hlog):
            dest=out/name;dest.mkdir()
            for n in ('ingress.jsonl','forwarded.jsonl','reply.jsonl','exit.txt'):shutil.copyfile(d/n,dest/n)
            if (d/'intervention.json').exists():shutil.copyfile(d/'intervention.json',dest/'intervention.json')
            if hlog.exists():shutil.copyfile(hlog,dest/'handler.jsonl')
            return frames(d/'ingress.jsonl'),frames(d/'forwarded.jsonl'),frames(d/'reply.jsonl'),frames(hlog),int((d/'exit.txt').read_text())
        async def query(op,attempt,expected,mode='valid',provided=None):
            nonlocal counter
            counter+=1;name='query-%02d'%counter;d,h,c=conn(name)
            q=client.begin(op,attempt) if provided is None else provided
            before=rowcount()
            async with Client(StdioServerParameters(command=sys.executable,args=[str(code/'relay65.py'),str(base),name])) as cl:
                await cl.list_tools();res=await asyncio.wait_for(cl.call_tool('recover_signed',{'query':q}),20)
                error=res.is_error
                response=None if error else (res.structured_content or json.loads(res.content[0].text))
                if error:
                    assert expected in ' '.join(x.text for x in res.content if x.type=='text');value=dict(error=expected)
                else:
                    actual=response
                    if mode=='tamper':
                        actual=json.loads(json.dumps(response));actual['body']['action']='RETURN_STORED_COMPLETION'
                        # Guarantee mutation even if the action happened to be completion.
                        actual['body']['nonce']='tampered'
                        try:client.accept(q,actual)
                        except ValueError:pass
                        else:raise AssertionError('tampered response accepted')
                        value=dict(error='INVALID_RECOVERY_RESPONSE')
                    else:
                        value=client.accept(q,response);assert value['action']==expected,(value,expected)
            ing,fwd,rep,events,rc=collect(name,d,h)
            native=[x for x in ing if x.get('method')=='tools/call'];assert len(native)==1 and native[0]['params']['arguments']=={'query':q}
            assert native[0] in fwd and events[0]['native']==native[0]['id'] and events[0]['query']==q
            assert rc==0 and rowcount()==before
            query_records.append(dict(name=name,query=q,response=response,error=error,mode=mode,verified=value,native_id=native[0]['id'],connection=c))
            (out/'queries.json').write_bytes(G.enc(query_records))
            print('B63_QUERY',name,attempt,expected,flush=True);return value,q,response
        async def run_case(name,cid,op,args,expected,crash='none',tool_error=None,retry=None,intervene=None):
            d,h,c=conn(name,op,crash,retry,intervene);seen=[];qval=[]
            def resolver(ctx):
                assert isinstance(ctx.run_context,ToolContext) and ctx.run_context.tool_call_id==cid
                assert ctx.tool_name=='plan_reading' and ctx.arguments==args
                seen.append(cid);return {'risu_b63':{'model':cid}}
            @function_tool
            async def recover_operation(ctx:ToolContext,operation:str,attempt:str)->str:
                """Read a signed recovery decision. Never repeat the operation."""
                assert ctx.tool_call_id==name+'-q' and operation==op and attempt==cid
                v,_,_=await query(op,cid,expected);qval.append(v)
                return G.enc(v).decode()
            model=ScriptedModel([[function_call('plan_reading',args,call_id=cid)],[function_call('recover_operation',{'operation':op,'attempt':cid},call_id=name+'-q')],[assistant_message('fixture finished')]])
            before=rowcount()
            async with MCPServerStdio(params={'command':sys.executable,'args':[str(code/'relay65.py'),str(base),name]},name='B63-native',tool_filter={'allowed_tool_names':['plan_reading']},tool_meta_resolver=resolver,use_structured_content=True,cache_tools_list=True,max_retry_attempts=0,client_session_timeout_seconds=10) as server:
                exposed=await server.list_tools();assert [t.name for t in exposed]==['plan_reading']
                await asyncio.wait_for(Runner.run(Agent(name='B63',model=model,mcp_servers=[server],tools=[recover_operation]),'Execute then inspect the result.',run_config=RunConfig(tracing_disabled=True)),45)
                model.assert_complete()
                outputs=[x for x in model.last_call.input if isinstance(x,dict) and x.get('type')=='function_call_output']
            assert seen==[cid] and len(qval)==1
            outputs={x['call_id']:x['output'] for x in outputs}
            assert set(outputs)=={cid,name+'-q'},outputs
            def val(x):return x[0]['text'] if isinstance(x,list) else x
            assert json.loads(val(outputs[name+'-q']))==qval[0]
            ing,fwd,rep,events,rc=collect(name,d,h)
            a=[x for x in ing if x.get('method')=='tools/call'];b=[x for x in fwd if x.get('method')=='tools/call'];assert len(a)==len(b)==1
            signed=b[0]['params']['_meta']['risu_b63_signed'];obs=events[0]['observed']
            assert a[0]['id']==b[0]['id']==obs['native'] and obs['connection']==c and obs['model']==cid and obs['parent']['arguments']==args
            assert G.verify(pub(actor),G.INT,signed['intent'])['native']==obs['native']
            replies=[x for x in rep if x.get('id')==a[0]['id'] and ('result'in x or 'error'in x)]
            if crash!='none':assert rc=={'ADMISSION':91,'STEP':82,'FINISH':83}[crash] and not replies and 'error' in json.dumps(outputs[cid]).lower()
            else:
                assert rc==0 and len(replies)==1
                r=replies[0]['result'];assert bool(r.get('isError',False))==bool(tool_error)
                if tool_error:assert tool_error in json.dumps(r) and tool_error in json.dumps(outputs[cid])
                else:assert json.loads(val(outputs[cid]))==json.loads(r['content'][0]['text'])
            ticket=b[0]['params']['_meta'].get('risu_b65_ticket');assert (ticket is not None)==(retry is not None)
            if ticket is not None:
                assert ticket['query']==retry[0] and ticket['response']==retry[1] and G.verify(pub(owner),G.RETRY,ticket['authorization'])['request_hash']==G.digest(dict(envelope=signed,observed=obs))
            records.append(dict(ticket=ticket,exposed_tools=[t.name for t in exposed],name=name,call=cid,op=op,crash=crash,exit=rc,outputs=outputs,observation=qval[0],envelope=signed,observed=obs,before=before,after=rowcount()))
            (out/'cases.json').write_bytes(G.enc(records));print('B63_CASE',name,crash,expected,'rows',rowcount(),flush=True)
        try:
            a=opened('admit','B001')
            await run_case('admit-crash','a','admit',a,'HOLD_UNRESOLVED','ADMISSION')
            assert rowcount()==0
            await run_case('active-denied','denied','admit',a,'DENIED_NO_DISPATCH',tool_error='ACTIVE_ATTEMPT')
            old=records[-1]
            h=G.digest(dict(envelope=records[0]['envelope'],observed=records[0]['observed']))
            rpc(dict(kind='seal',seal=G.sign(owner,G.SEAL,dict(scope=scope,op='admit',attempt='a',admission_hash=h))))
            await query('admit','a','NEW_AUTHORIZED_ATTEMPT_ONLY')
            # Same model/attempt reused with a genuinely new native connection.
            await run_case('denied-rebind','denied','admit',a,'DENIED_NO_DISPATCH',tool_error='IDENTITY_CONFLICT')
            await run_case('missing-ticket','missing-ticket','admit',a,'DENIED_NO_DISPATCH',tool_error='RETRY_REQUIRED')
            _,q,r=await query('admit','a','NEW_AUTHORIZED_ATTEMPT_ONLY')
            await run_case('stale-ticket','stale-ticket','admit',a,'DENIED_NO_DISPATCH',tool_error='STALE_OBSERVATION',retry=[q,r],intervene=dict(op='unrelated',kind='OPEN',steps=[dict(book_id='B006',list_name='demo')]))
            _,q,r=await query('admit','a','NEW_AUTHORIZED_ATTEMPT_ONLY')
            await run_case('admit-new','a-new','admit',a,'RETURN_STORED_COMPLETION',retry=[q,r])
            assert rowcount()==1
            await query('admit','a','RETURN_STORED_COMPLETION')
            b=opened('child','B002');await run_case('child-crash','b','child',b,'HOLD_UNRESOLVED','STEP')
            assert rowcount()==2
            with sqlite3.connect(db.as_uri()+'?mode=ro',uri=True) as d:start=d.execute("SELECT start FROM attempts WHERE attempt='b'").fetchone()[0]
            admin('child','ABANDON',attempt='b',start=start)
            _,q,r=await query('child','b','NEW_AUTHORIZED_ATTEMPT_ONLY')
            await run_case('child-new','b-new','child',b,'RETURN_STORED_COMPLETION',retry=[q,r])
            assert rowcount()==2
            c=opened('finish','B003');await run_case('finish-crash','c','finish',c,'RETURN_STORED_COMPLETION','FINISH')
            assert rowcount()==3
            d=opened('revoke','B004');await run_case('revoke-crash','d','revoke',d,'HOLD_UNRESOLVED','STEP');admin('revoke','REVOKE')
            await query('revoke','d','NO_FURTHER_EXECUTION')
            await run_case('revoke-denied','d-new','revoke',d,'DENIED_NO_DISPATCH',tool_error='OP_CLOSED')
            e=opened('late-revoke','B005')
            await run_case('late-revoke-crash','e','late-revoke',e,'HOLD_UNRESOLVED','ADMISSION')
            ar=records[-1]
            h=G.digest(dict(envelope=ar['envelope'],observed=ar['observed']))
            rpc(dict(kind='seal',seal=G.sign(owner,G.SEAL,dict(scope=scope,op='late-revoke',attempt='e',admission_hash=h))))
            _,q,r=await query('late-revoke','e','NEW_AUTHORIZED_ATTEMPT_ONLY')
            await run_case('late-revoke-denied','e-new','late-revoke',e,'DENIED_NO_DISPATCH',tool_error='OP_CLOSED',retry=[q,r],intervene=dict(op='late-revoke',kind='REVOKE'))
            await query('late-revoke','e','NO_FURTHER_EXECUTION')
            # Exact prior signed denial via actual authorized peer, not a new native request.
            script="import sys,json;sys.path.insert(0,"+repr(str(code))+");from broker65 import call;print(json.dumps(call("+repr(str(sock))+",json.load(sys.stdin))))"
            def direct(uid,r):
                x=subprocess.run([sys.executable,'-c',script],input=G.enc(r),capture_output=True,user=uid,group=uid,extra_groups=[],cwd=base,timeout=15);assert x.returncode==0,x.stderr;return G.parse(x.stdout)
            exact=direct(65533,dict(kind='admit',envelope=old['envelope'],observed=old['observed']));assert exact['result']['decision']=='DENIAL_REPLAY'
            q=client.begin('finish','c');peer=direct(65534,dict(kind='recover',query=q));assert peer['error']=='PEER_DENIED'
            # Real native query, then replay the same nonce via another actual connection.
            v,q,r=await query('finish','c','RETURN_STORED_COMPLETION',provided=q)
            await query('finish','c','NONCE_USED',provided=q)
            await query('finish','c','RETURN_STORED_COMPLETION',mode='tamper')
            wrong=G.sign(Key.generate(),G.QUERY,dict(scope=scope,op='finish',attempt='c',nonce=uuid.uuid4().hex))
            await query('finish','c','DENIED',provided=wrong)
            assert rowcount()==4
            with sqlite3.connect(db.as_uri()+'?mode=ro',uri=True) as chk:
                assert chk.execute('SELECT attempt FROM consumed_retry ORDER BY attempt').fetchall()==[('a-new',),('b-new',)]
                assert chk.execute('SELECT count(*) FROM retry_log').fetchone()[0]==chk.execute('SELECT count(*) FROM admission_log').fetchone()[0]
            (out/'controls.json').write_bytes(G.enc(dict(exact=exact,peer=peer)))
            with sqlite3.connect(db.as_uri()+'?mode=ro',uri=True) as source,sqlite3.connect(out/'destination.sqlite3') as dest:
                assert source.execute('PRAGMA integrity_check').fetchone()==('ok',);source.backup(dest)
            for p,h in PINS.items():assert blob(up/p)==h
            (out/'summary.json').write_bytes(G.enc(dict(cases=len(records),queries=len(query_records),rows=rowcount(),source_pins=PINS)))
            print('B65_PASS',len(records),'native executions',len(query_records),'native recovery queries',rowcount(),'rows',flush=True)
        finally:proc.terminate();proc.wait(timeout=10)
if __name__=='__main__':asyncio.run(main(*sys.argv[1:]))
