"""Test harness only: invokes original external host, substitutes deterministic model."""
import asyncio, difflib, json, os, pathlib, shutil, subprocess, sys, types, uuid
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from agents import Agent, Runner
from agents.testing import ScriptedModel, assistant_message, function_call
import risu_b57 as kit
CASES=[
 ('search','search_catalog',{'query':'agents','limit':5},'FORWARD'),
 ('save','save_reading_item',{'book_id':'B001','list_name':'demo'},'FORWARD'),
 ('plan','plan_reading',{'query':'machine learning','list_name':'demo'},'FORWARD'),
 ('repeat','plan_reading',{'query':'machine learning','list_name':'demo'},'FORWARD'),
 ('no-match','plan_reading',{'query':'underwater basket weaving','list_name':'demo'},'FORWARD'),
 ('invalid-book','save_reading_item',{'book_id':'B999','list_name':'demo'},'FORWARD'),
 ('missing','save_reading_item',{'book_id':'B002','list_name':'demo'},'MISSING_IDENTITY'),
 ('wrong-scope','save_reading_item',{'book_id':'B002','list_name':'demo'},'WRONG_SCOPE'),
 ('replay','save_reading_item',{'book_id':'B001','list_name':'demo'},'REUSED_IDENTITY'),
 ('rebind','save_reading_item',{'book_id':'B002','list_name':'demo'},'ARGUMENT_REBIND'),
 ('unauthorized','save_reading_item',{'book_id':'B002','list_name':'private'},'UNAUTHORIZED')]
def git(root,*args):return subprocess.check_output(['git','-C',str(root),*args],text=True).strip()
def patch(root,out):
    f=root/'library_toolkit/agent.py';old=f.read_text();new=old.replace('from dotenv import load_dotenv','from dotenv import load_dotenv\nimport risu_b57').replace('["-m", "library_toolkit.server"]','["-m", "risu_b57", "proxy"]').replace('            client_session_timeout_seconds=30,','            client_session_timeout_seconds=30,\n            tool_meta_resolver=risu_b57.resolver,')
    assert old!=new and new.count('tool_meta_resolver=risu_b57.resolver')==1 and '"risu_b57", "proxy"' in new
    delta=list(difflib.unified_diff(old.splitlines(True),new.splitlines(True),fromfile='a/library_toolkit/agent.py',tofile='b/library_toolkit/agent.py'))
    (out/'host.patch').write_text(''.join(delta));assert sum(x.startswith('+') and not x.startswith('+++') for x in delta)==3 and sum(x.startswith('-') and not x.startswith('---') for x in delta)==1
    f.write_text(new)
async def main(root,out):
    root=pathlib.Path(root).resolve();out=pathlib.Path(out).resolve();out.mkdir(parents=True,exist_ok=True)
    assert git(root,'rev-parse','HEAD')=='99ea07d1074eb06885ec1107029e48d83fe05e78'
    pins={'library_toolkit/agent.py':'c41ef385e99e11bcdc5cac63686bef42a4b09078','library_toolkit/server.py':'f7b8f2e916f9df6409f83a2663a4d00d3d9061a0','library_toolkit/service.py':'8dcbc523ff94448f6a89dbf295a52c3a0d0f50b7','library_toolkit/catalog.json':'f87c53fe0b5cd08aa416513c9d8b01ab206c7b45','requirements.txt':'1981140e8d4369523c50e078a95daad99af25a03'}
    for p,h in pins.items():assert git(root,'hash-object',p)==h,p
    patch(root,out)
    shutil.copyfile(pathlib.Path(kit.__file__),root/'risu_b57.py')
    sys.path.insert(0,str(root))
    from library_toolkit import agent as app
    db=(out/'demo.sqlite3').resolve()
    key=Ed25519PrivateKey.generate()
    c=dict(run=uuid.uuid4().hex,destination='campusreads:'+str(db),db=str(db),dir=str(out),public=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex(),allow=[{'tool':t,'arguments':a} for _,t,a,status in CASES if status=='FORWARD']+[{'tool':'save_reading_item','arguments':{'book_id':'B002','list_name':'demo'}}])
    kit.CONFIG=c;kit.KEY=key;kit.CACHE.clear()
    config=out/'config.json';config.write_bytes(kit.enc(c));os.environ['RISU_B57_CONFIG']=str(config)
    os.environ['OPENAI_API_KEY']='offline-test-only-not-a-real-key'
    original_prompts=list(app.PROMPTS);assert len(original_prompts)==6
    app.PROMPTS=original_prompts+['Adversarial fixture '+x[0] for x in CASES[6:]]
    scripted=ScriptedModel([response for cid,t,a,_ in CASES for response in [[function_call(t,a,call_id=cid)],[assistant_message('fixture finished')]]])
    app.Agent=lambda **kw:Agent(**dict(kw,model=scripted))
    # Persist the original demo's temporary database only for forensic analysis.
    class Keep:
        def __init__(self,**kwargs):pass
        def __enter__(self):return str(out)
        def __exit__(self,*args):return False
    app.tempfile=types.SimpleNamespace(TemporaryDirectory=Keep)
    outputs=[]
    class RecordingRunner:
        @staticmethod
        async def run(*args,**kwargs):
            result=await Runner.run(*args,**kwargs)
            last=[x for x in scripted.last_call.input if isinstance(x,dict) and x.get('type')=='function_call_output']
            assert len(last)==1,last
            outputs.extend(last);(out/'outputs.json').write_bytes(kit.enc(outputs))
            return result
    app.Runner=RecordingRunner
    await asyncio.wait_for(app.run_host(types.SimpleNamespace(demo=True)),80)
    scripted.assert_complete()
    for p,h in pins.items():
        if p!='library_toolkit/agent.py':assert git(root,'hash-object',p)==h,p
    assert [x['call_id'] for x in outputs]==[x[0] for x in CASES]
    final=kit.snapshot(str(db));assert [(r[0],r[1]) for r in final]==[('demo','B001'),('demo','B004')],final
    (out/'summary.json').write_bytes(kit.enc(dict(cases=CASES,source_pins=pins,final_rows=final,host_added_lines=3,host_removed_lines=1)))
    print('B57_ORIGINAL_HOST_PASS',len(outputs),flush=True)
if __name__=='__main__':asyncio.run(main(*sys.argv[1:]))
