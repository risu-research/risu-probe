"""B56: native Agents MCPServerStdio, public meta resolver, narrow tool schema."""
import asyncio, importlib.metadata, json, os, pathlib, sqlite3, subprocess, sys, threading, uuid
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as Key, Ed25519PublicKey as PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from auth50 import init, grant, request, public, enc, git, REF
from bridge51 import dispatch, typed_id, decode, setup, TOOL
from bridge52 import inspect
from effect52 import attribute, recover
from sdk_probe import HERE, save, rows, tool_calls
DOMAIN=b'RISU-B56-intent-v1\x00'
META='risu_intent'
SCHEMA={'type':'object','properties':{'operation':{'type':'string','enum':['op1','op2','op3']}},'required':['operation'],'additionalProperties':False}
def raw_key(k):
    return k.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption()).hex()
def pub_key(k):
    return k.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()
def body(run,conn,call,op):
    return dict(run=run,connection=conn,call=call,operation=op,tool=TOOL)
def proxy(config):
    c=json.loads(pathlib.Path(config).read_text());sc=json.loads(pathlib.Path(c['server_config']).read_text())
    actor=Key.from_private_bytes(bytes.fromhex(c['fixture_key']))
    meta_key=PublicKey.from_public_bytes(bytes.fromhex(c['meta_public']))
    p=subprocess.Popen([sys.executable,str(HERE/'sdk_probe.py'),'server',c['server_config']],stdin=subprocess.PIPE,stdout=subprocess.PIPE)
    lock=threading.Lock();used=set();errors=[]
    def send(raw):
        with lock:
            save(c['delivered_reply'],raw);sys.stdout.buffer.write(raw);sys.stdout.buffer.flush()
    def refuse(rid,reason):
        msg=dict(jsonrpc='2.0',id=rid,result=dict(isError=True,resultType='complete',_meta={'io.modelcontextprotocol/serverInfo':{'name':'risu-b56-proxy','version':'0.1.0'}},content=[dict(type='text',text='RISU_DENIED:'+reason)]))
        send(enc(msg)+b'\n')
    def pump():
        try:
            for raw in sys.stdin.buffer:
                save(c['client_wire'],raw);m=decode(raw)
                if m.get('method')=='tools/call':
                    rid=m['id'];typed_id(rid);a=m['params'].get('arguments',{})
                    envelope=m['params'].get('_meta',{}).get(META)
                    reason=None
                    if m['params']['name']!=TOOL or not isinstance(a,dict) or set(a)!={'operation'} or a.get('operation') not in c['grants']:
                        reason='ARGUMENTS'
                    elif not isinstance(envelope,dict):reason='MISSING_IDENTITY'
                    else:
                        try:
                            b=envelope['body'];call=b['call']
                            if not isinstance(call,str) or not call or b!=body(c['agent_run'],sc['connection'],call,a['operation']):raise ValueError('binding')
                            meta_key.verify(bytes.fromhex(envelope['signature']),DOMAIN+enc(b))
                            if call in used:reason='REUSED_IDENTITY'
                        except (KeyError,TypeError,ValueError,InvalidSignature):reason='INVALID_IDENTITY'
                    if reason:
                        save(c['decisions'],enc(dict(id=rid,decision=reason))+b'\n');refuse(rid,reason);continue
                    used.add(call)
                    g=c['grants'][a['operation']]
                    a=dict(grant=g,execute=request(actor,g),dispatch=dispatch(actor,sc['scope'],g,sc['connection'],rid,c['agent_run'],call),agent_run=c['agent_run'],model_call=call)
                    m['params']=dict(name=TOOL,arguments=a,_meta={k:v for k,v in m['params']['_meta'].items() if k!=META})
                    raw=enc(m)+b'\n'
                    save(c['decisions'],enc(dict(id=rid,decision='FORWARD',call=call))+b'\n')
                save(c['server_wire'],raw);p.stdin.write(raw);p.stdin.flush()
        except Exception as e:
            errors.append(repr(e));save(c['exit_log'],enc({'pump_error':repr(e)})+b'\n')
        finally:
            try:p.stdin.close()
            except OSError:pass
    threading.Thread(target=pump,daemon=True).start()
    for raw in p.stdout:
        save(c['original_reply'],raw);m=decode(raw)
        if 'result' in m and isinstance(m['result'],dict) and 'tools' in m['result']:
            tools=m['result']['tools'];t=next(t for t in tools if t['name']==TOOL)
            t['inputSchema']=SCHEMA;t.pop('outputSchema',None)
            m['result']['tools']=[t];raw=enc(m)+b'\n'
        send(raw)
    code=p.wait(timeout=5);save(c['exit_log'],enc(dict(server_exit=code,errors=errors))+b'\n')
    os._exit(code if not errors and 0<=code<=255 else 1)

async def exercise(out):
    from agents import Agent, Runner, RunConfig
    from agents.tool_context import ToolContext
    from agents.mcp import MCPServerStdio
    from agents.testing import ScriptedModel, assistant_message, function_call
    d=pathlib.Path(out).resolve();d.mkdir(parents=True,exist_ok=True)
    assert importlib.metadata.version('openai-agents')=='0.26.0'
    assert importlib.metadata.version('mcp')=='2.3.0'
    owner=Key.generate();actor=Key.generate();meta=Key.generate()
    scope=init(d/'effect.git');pub=public(owner);grants={op:grant(scope,owner,actor,op,delta,'grant-'+op) for op,delta in [('op1',7),('op2',11),('op3',100)]}
    calls={'model-a':'op1','model-b':'op1','model-c':'op2','model-d':'op3','model-e':'op3'}
    conn=uuid.uuid4().hex;run='b56-native-run';journal=str(d/'journal.sqlite');setup(journal)
    ep=d/'ephemeral';ep.mkdir()
    logs={k:str(d/(k+'.jsonl')) for k in ('client_wire','server_wire','original_reply','delivered_reply','context_log','exit_log','decisions','resolver_log')}
    sc=dict(scope=scope,owner=pub,connection=conn,journal=journal,mode='normal',context_log=logs['context_log'])
    sp=ep/'server.json';sp.write_bytes(enc(sc));cp=ep/'proxy.json'
    pc=dict(**{k:v for k,v in logs.items() if k not in ('context_log','resolver_log')},server_config=str(sp),fixture_key=raw_key(actor),meta_public=pub_key(meta),grants=grants,agent_run=run)
    cp.write_bytes(enc(pc));seen={}
    def resolver(c):
        rc=c.run_context
        # Never infer identity from tool arguments or call order.
        if not isinstance(rc,ToolContext) or not isinstance(rc.tool_call_id,str) or not rc.tool_call_id:
            save(logs['resolver_log'],enc(dict(error='NO_TOOL_CONTEXT',type=type(rc).__name__))+b'\n');return None
        cid=rc.tool_call_id;op=c.arguments['operation']
        assert c.tool_name==TOOL and cid not in seen
        b=body(run,conn,cid,op)
        signature=meta.sign(DOMAIN+enc(b)).hex()
        envelope=dict(body=b,signature=signature)
        if cid=='model-d':result=None
        elif cid=='model-e':
            envelope['signature']=('00' if signature[:2]!='00' else '01')+signature[2:];result={META:envelope}
        else:result={META:envelope}
        seen[cid]=dict(call=cid,operation=op,context=type(rc).__name__,meta=result)
        save(logs['resolver_log'],enc(seen[cid])+b'\n')
        return result
    try:
        async with MCPServerStdio(params={'command':sys.executable,'args':[str(HERE/'native.py'),'proxy',str(cp)]},name='risu-native',tool_meta_resolver=resolver,use_structured_content=True,cache_tools_list=True,max_retry_attempts=0) as server:
            discovered=await server.list_tools()
            assert len(discovered)==1 and discovered[0].name==TOOL
            assert discovered[0].input_schema==SCHEMA
            model=ScriptedModel([[function_call(TOOL,{'operation':op},call_id=cid) for cid,op in calls.items()],[assistant_message('fixture finished')]])
            agent=Agent(name='B56 native agent',model=model,mcp_servers=[server])
            assert not agent.tools
            await asyncio.wait_for(Runner.run(agent,'Execute fixture calls.',run_config=RunConfig(tracing_disabled=True)),40)
            model.assert_complete()
            outputs=[x for x in model.last_call.input if isinstance(x,dict) and x.get('type')=='function_call_output']
        (d/'model_outputs.json').write_bytes(enc(outputs))
        assert len(outputs)==5 and {x['call_id'] for x in outputs}==set(calls)
        assert set(seen)==set(calls)
        pre=tool_calls(logs['client_wire']);post=tool_calls(logs['server_wire']);cx=rows(logs['context_log']);decisions=rows(logs['decisions'])
        assert len(pre)==5 and len(post)==len(cx)==3 and len(decisions)==5
        ids=[typed_id(x['id']) for x in pre];assert len(set(ids))==5
        def by_id(seq):return {typed_id(x['id']):x for x in seq}
        pm=by_id(post);cm=by_id(cx);dm=by_id(decisions)
        delivered=by_id([x for x in rows(logs['delivered_reply']) if 'id'in x and typed_id(x['id']) in ids])
        original=by_id([x for x in rows(logs['original_reply']) if 'id'in x and typed_id(x['id']) in ids])
        assert len(delivered)==5 and len(original)==3
        outputs_by_call={x['call_id']:x['output'] for x in outputs}
        cases=[];unidentified=[]
        for x in pre:
            tid=typed_id(x['id']);a=x['params']['arguments'];md=x['params'].get('_meta',{}).get(META);rr=delivered[tid]['result']
            assert set(a)=={'operation'}
            if md is None:
                unidentified.append(x['id'])
                assert dm[tid]['decision']=='MISSING_IDENTITY' and tid not in pm and rr['isError']
                continue
            cid=md['body']['call'];assert calls[cid]==a['operation'] and seen[cid]['meta'][META]==md
            if cid=='model-e':
                assert dm[tid]['decision']=='INVALID_IDENTITY' and tid not in pm and rr['isError']
                assert 'RISU_DENIED:INVALID_IDENTITY' in json.dumps(outputs_by_call[cid])
                cases.append(dict(call=cid,id=x['id'],status='INVALID_IDENTITY'));continue
            assert dm[tid]['decision']=='FORWARD' and original[tid]==delivered[tid] and not rr.get('isError',False)
            p=pm[tid];m=cm[tid]['projection'];assert cm[tid]['connection']==conn and p['params']['arguments']==m['params']['arguments']
            assert m['params']['arguments']['model_call']==cid and m['params']['arguments']['grant']==grants[a['operation']]
            att=attribute(scope,pub,conn,m);audit=inspect(scope,pub,journal,conn,enc(m)+b'\n')
            assert audit['model_call']==cid and audit['attempt_status']=='TERMINAL_RECORDED'
            assert json.loads(outputs_by_call[cid])==rr['structuredContent'] and rr['structuredContent']['receipt']==att['receipt']
            cases.append(dict(call=cid,id=x['id'],status=att['attribution'],journal=audit))
        # Without metadata there is deliberately no positive wire-level model identity claim.
        assert len(unidentified)==1 and 'RISU_DENIED:MISSING_IDENTITY' in json.dumps(outputs_by_call['model-d'])
        assert sorted(x['status'] for x in cases)==['EFFECT_ATTRIBUTED','EFFECT_ATTRIBUTED','INVALID_IDENTITY','OTHER_ATTEMPT_WON']
        assert recover(scope,pub,grants['op1'])['value']==recover(scope,pub,grants['op2'])['value']==18 and recover(scope,pub,grants['op3'])['status']=='UNKNOWN'
        with sqlite3.connect(journal) as db:assert db.execute('SELECT count(*),count(response) FROM calls').fetchone()==(3,3)
        assert len(git(scope['repo'],'rev-list',REF).splitlines())==3
        git(scope['repo'],'bundle','create',str(d/'EFFECT.bundle'),REF);git(scope['repo'],'fsck','--full')
        summary=dict(scope=scope,owner_public=pub,meta_public=pub_key(meta),grants=grants,connection=conn,run=run,outputs=outputs,cases=cases,unidentified_wire_ids=unidentified,final_value=18,schema=SCHEMA)
        (d/'summary.json').write_bytes(enc(summary))
        for item in cases:print('B56_CASE',json.dumps(item),flush=True)
        print('B56_UNIDENTIFIED',unidentified,flush=True)
        print('B56_NATIVE_PASS',flush=True)
    finally:
        import shutil;shutil.rmtree(ep)
if __name__=='__main__':
    if sys.argv[1]=='proxy':proxy(sys.argv[2])
    else:asyncio.run(exercise(sys.argv[1]))
