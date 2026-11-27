"""B54: unchanged external Runner -> public ToolContext -> B53 bridge.
Only normalized model responses are scripted. No live model/API calls."""
import asyncio, importlib.metadata, json, pathlib, sqlite3, sys, uuid
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as Key
from cryptography.hazmat.primitives import serialization
from agents import Agent, Runner, RunConfig, function_tool
from agents.tool_context import ToolContext
from agents.testing import ScriptedModel, assistant_message, function_call
from mcp import Client, StdioServerParameters
from sdk_probe import HERE, rows, tool_calls
from auth50 import init, grant, request, public, enc, git, REF, withdrawal
from bridge51 import setup, typed_id, TOOL
from bridge52 import inspect
from effect52 import change, recover, attribute

async def main(d):
    d=pathlib.Path(d).resolve(); d.mkdir(parents=True,exist_ok=True)
    assert importlib.metadata.version('openai-agents')=='0.26.0'
    assert importlib.metadata.version('mcp')=='2.3.0'
    owner=Key.generate(); actor=Key.generate(); scope=init(d/'effect.git')
    pub=public(owner); g=grant(scope,owner,actor,'op',7,'grant1')
    g2=grant(scope,owner,actor,'op2',9,'grant2')
    journal=str(d/'journal.sqlite'); setup(journal)
    ep=d/'ephemeral'; ep.mkdir(); results=[]
    async def case(name,mode,grant_,call,expected,attribution):
        record={}
        conn=uuid.uuid4().hex
        logs={k:str(d/(name+'.'+k+'.jsonl')) for k in ('client_wire','server_wire','reply_wire','context_log','exit_log')}
        # The tool has no model_call parameter. Identity comes only from official Runner context.
        @function_tool
        async def apply_approved(ctx: ToolContext, operation: str)->str:
            """Execute a preapproved disposable test operation."""
            assert operation=='approved'
            cid=ctx.tool_call_id
            record.update(context_id=cid,context_type=type(ctx).__name__)
            sc=dict(scope=scope,owner=pub,connection=conn,journal=journal,mode=mode,context_log=logs['context_log'])
            sp=ep/(name+'.server.json'); sp.write_bytes(enc(sc))
            cp=ep/(name+'.proxy.json')
            pc=dict(**{k:v for k,v in logs.items() if k!='context_log'},server_config=str(sp),fixture_key=actor.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption()).hex(),grant=grant_,agent_run='b54-controlled-run',model_call=cid)
            cp.write_bytes(enc(pc))
            args=dict(grant=grant_,execute=request(actor,grant_),dispatch={},agent_run='b54-controlled-run',model_call=cid)
            try:
                async with Client(StdioServerParameters(command=sys.executable,args=[str(HERE/'sdk_probe.py'),'proxy',str(cp)])) as cl:
                    record['protocol']=cl.protocol_version
                    await cl.list_tools()
                    res=await asyncio.wait_for(cl.call_tool(TOOL,args),15)
                    record['sdk_result']={'is_error':res.is_error,'structured':res.structured_content}
                    status='SDK_ERROR' if res.is_error else 'SDK_SUCCESS'
            except Exception as e:
                record['exception']=type(e).__name__
                status='TRANSPORT_UNKNOWN'
            record['tool_status']=status
            return status
        fc=function_call('apply_approved',{'operation':'approved'},call_id=call)
        model=ScriptedModel([[fc],[assistant_message('fixture finished')]])
        result=await Runner.run(Agent(name='B54 external runner',model=model,tools=[apply_approved]),'Execute the authorized fixture.',run_config=RunConfig(tracing_disabled=True))
        model.assert_complete()
        outputs=[x for x in model.last_call.input if isinstance(x,dict) and x.get('type')=='function_call_output']
        assert len(outputs)==1,outputs
        assert outputs[0]['call_id']==call and outputs[0]['output']==expected,outputs
        assert record['context_id']==fc.call_id==call and record['tool_status']==expected
        pre=tool_calls(logs['client_wire']); post=tool_calls(logs['server_wire']); cx=rows(logs['context_log'])
        assert len(pre)==len(post)==len(cx)==1,(name,record,pre,post,cx)
        assert typed_id(pre[0]['id'])==typed_id(post[0]['id'])==typed_id(cx[0]['id'])
        projection=cx[0]['projection']
        assert pre[0]['params']['arguments']['model_call']==post[0]['params']['arguments']['model_call']==projection['params']['arguments']['model_call']==call
        assert projection['params']['arguments']==post[0]['params']['arguments']
        att=attribute(scope,pub,conn,projection)
        audit=inspect(scope,pub,journal,conn,enc(projection)+b'\n')
        replies=[r for r in rows(logs['reply_wire']) if 'id' in r and typed_id(r['id'])==typed_id(post[0]['id'])]
        assert att['attribution']==attribution,att
        assert len(replies)==(0 if expected=='TRANSPORT_UNKNOWN' else 1)
        if mode=='wrong_id': assert audit['status']=='UNLINKED'
        else: assert audit['model_call']==call
        if mode in ('before_effect','after_effect'):
            assert audit['attempt_status']=='START_ONLY'
            assert int(pathlib.Path(logs['exit_log']).read_text())==({'before_effect':81,'after_effect':82}[mode])
        elif mode!='wrong_id': assert audit['attempt_status']=='TERMINAL_RECORDED'
        item=dict(name=name,model_call=call,model_output=outputs[0],agent_context=record,native_id=post[0]['id'],connection=conn,raw_reply_count=len(replies),attribution=att,journal=audit)
        results.append(item); (d/'results.json').write_bytes(enc(results))
        print('B54_CASE',json.dumps(item),flush=True)
    try:
        await case('01_wrong_id','wrong_id',g,'model-a','SDK_ERROR','UNPROVEN')
        await case('02_before_effect','before_effect',g,'model-b','TRANSPORT_UNKNOWN','UNPROVEN')
        assert recover(scope,pub,g)['value']==0
        await case('03_after_effect','after_effect',g,'model-c','TRANSPORT_UNKNOWN','EFFECT_ATTRIBUTED')
        winner=recover(scope,pub,g)['winning_attempt']
        await case('04_retry','normal',g,'model-d','SDK_SUCCESS','OTHER_ATTEMPT_WON')
        assert recover(scope,pub,g)['winning_attempt']==winner and recover(scope,pub,g)['value']==7
        change(scope,pub,g2,withdrawal(owner,g2),kind='withdraw')
        await case('05_withdrawn','normal',g2,'model-e','SDK_ERROR','NO_EFFECT_WITHDRAWN')
        with sqlite3.connect(journal) as db: counts=db.execute('SELECT count(*),count(response) FROM calls').fetchone()
        assert counts==(4,2),counts
        assert len(git(scope['repo'],'rev-list',REF).splitlines())==3
        git(scope['repo'],'bundle','create',str(d/'EFFECT.bundle'),REF);git(scope['repo'],'fsck','--full')
        (d/'summary.json').write_bytes(enc(dict(cases=5,journal_counts=list(counts),value=7,winner=winner,owner_public=pub,scope=scope,grant=g,withdrawn_grant=g2)))
        print('B54_EXTERNAL_RUNNER_PASS',flush=True)
    finally:
        import shutil; shutil.rmtree(ep)
if __name__=='__main__': asyncio.run(main(sys.argv[1]))
