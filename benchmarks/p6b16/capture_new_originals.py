"""P6-B16 pinned independent source native stdio harness.

Selected external owners and calls are frozen separately. Original server is
never patched; only synthetic local data and a bounded original MCP transport.
"""
from __future__ import annotations
import argparse, asyncio, hashlib, json, os, tempfile
from pathlib import Path


def sha(raw:bytes)->str:
    return hashlib.sha256(raw).hexdigest()

def state(root:Path)->str:
    files=sorted(x for x in root.rglob('*') if x.is_file() and not x.is_symlink())
    if len(files)>64:raise ValueError("Excess synthetic state files")
    obj={}
    for f in files:
        v=f.read_bytes()
        if len(v)>32768:raise ValueError("Synthetic file too large")
        obj[f.relative_to(root).as_posix()]=sha(v)
    return sha(json.dumps(obj,sort_keys=True,separators=(',',':')).encode())

def get_entry(case,source,root):
    if case=='AISH':
        f=source/'scripts/mcp-servers/python/features_server.py'
        return [str(f),'--transport','stdio','--root',str(root)]
    if case=='MM':
        return [str(source/'search_mcp_server.py')]
    raise ValueError('Unknown selected cohort')

async def capture(case,source,executable,manifest,out):
    m=json.loads(manifest.read_text('utf-8'))
    assert m['schema']=='risu-p6b16-independent-original-owners-cohort-v1'
    assert m['frozen_authority_blob']=='be24472b0fea8d8e7a252a7a36158cf8873128de'
    selected=next(x for x in m['cases'] if x['id']==case)
    if out.exists() or not executable.is_file() or not source.is_dir():
        raise ValueError('Missing original runtime or output already exists')
    out.mkdir(parents=True)
    origin={'schema':'risu-b16-external-native-stdio-v1',
            'case':case,'repo':selected['repo'],'source_commit':selected['sha'],
            'selected_steps':len(selected['steps']),'status':'UNVERIFIED'}
    lines=[]
    calls=[]
    proc=None
    with tempfile.TemporaryDirectory(prefix='risu-b16-safe-') as temp:
        root=Path(temp).resolve()
        env={'PATH':os.environ.get('PATH',''),'HOME':str(root),
             'LC_ALL':'C.UTF-8','LANG':'C.UTF-8','CI':'true','NO_COLOR':'1',
             'PYTHONPATH':str(source),'PYTHONDONTWRITEBYTECODE':'1'}
        async def send(m):
            assert proc and proc.stdout and proc.stdin
            wire=(json.dumps(m,ensure_ascii=False,separators=(',',':'))+'\n').encode()
            proc.stdin.write(wire)
            await asyncio.wait_for(proc.stdin.drain(),12)
            lines.append(wire)
            start=len(lines)
            if 'id' not in m:return None,start,None
            for i in range(20):
                raw=await asyncio.wait_for(proc.stdout.readline(),30)
                if not raw or not raw.endswith(b'\n') or len(raw)>524288:
                    raise RuntimeError('Source MCP response missing or oversized')
                lines.append(raw)
                item=json.loads(raw)
                if type(item) is not dict or item.get('jsonrpc')!='2.0':
                    raise RuntimeError('Unexpected original server stdout protocol')
                if item.get('id')==m['id']:return item,start,len(lines)
                if 'id' not in item:continue
                raise RuntimeError('Unexpected server-to-client request')
            raise RuntimeError('Excess native notifications')
        try:
            proc=await asyncio.create_subprocess_exec(str(executable),*get_entry(case,source,root),
                cwd=str(root),env=env,stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,
                limit=524290)
            init,_,_=await send({'jsonrpc':'2.0','id':1,'method':'initialize',
                'params':{'protocolVersion':'2025-11-25','capabilities':{},
                'clientInfo':{'name':'risu-b16-holdout','version':'1'}}})
            if type(init.get('result')) is not dict:
                raise RuntimeError('Pinned source initialization failed')
            origin['protocol']=init['result'].get('protocolVersion')
            await send({'jsonrpc':'2.0','method':'notifications/initialized'})
            initial,_,_=await send({'jsonrpc':'2.0','id':2,'method':'tools/list','params':{}})
            if type(initial.get('result')) is not dict or type(initial['result'].get('tools')) is not list:
                raise RuntimeError('Pinned source initial catalog failed')
            names={x['name'] for x in initial['result']['tools']}
            origin['initial_catalog_tool_count']=len(names)
            count=0
            for i,step in enumerate(selected['steps']):
                if step['method']=='tools/list':
                    res,request_line,response_line=await send({
                        'jsonrpc':'2.0','id':30+i,'method':'tools/list','params':{}})
                    if type(res.get('result')) is not dict or type(res['result'].get('tools')) is not list:
                        raise RuntimeError('Source changed catalog refresh failed')
                    names={x.get('name') for x in res['result']['tools']}
                    origin['refreshed_catalog_tool_count']=len(names)
                    continue
                if step['method']!='tools/call':
                    raise ValueError('Unapproved operation in locked cohort')
                if step['name'] not in names:
                    calls.append({'label':step['id'],'status':'UNVERIFIED_TOOL_NOT_ADVERTISED'})
                    continue
                args=step['arguments']
                before=state(root)
                res,request_line,response_line=await send({
                    'jsonrpc':'2.0','id':20+i,'method':'tools/call',
                    'params':{'name':step['name'],'arguments':args}})
                after=state(root)
                count+=1
                calls.append({'label':step['id'],'status':'CAPTURED',
                    'tool':step['name'],'request_line':request_line,
                    'response_line':response_line,'arguments':args,'before_sha256':before,
                    'after_sha256':after,'response':res})
                if case=='AISH' and step['name']=='list_added':
                    # This native server emits a post-response notification.
                    # Drain before next request so stale metadata is correctly
                    # time-ordered at the MCP client boundary.
                    try:
                        extra=await asyncio.wait_for(proc.stdout.readline(),2.0)
                    except asyncio.TimeoutError:
                        extra=b''
                    if extra:
                        if len(extra)>524288 or not extra.endswith(b'\n'):
                            raise RuntimeError('Invalid post-response notification framing')
                        notification=json.loads(extra)
                        if notification.get('method')!='notifications/tools/list_changed':
                            raise RuntimeError('Unexpected original post-response message')
                        lines.append(extra)
                        origin['catalog_change_notifications_seen']=origin.get(
                            'catalog_change_notifications_seen',0)+1
            origin['calls_executed']=count
            origin['status']='CAPTURED_ORIGINAL' if len(calls)==sum(
                s['method']=='tools/call' for s in selected['steps']) else 'UNVERIFIED_PARTIAL'
        except Exception as e:
            origin['status']='UNVERIFIED_CAPTURE_ERROR'
            origin['error_kind']=type(e).__name__
            origin['error_detail']=str(e)[:280]
        finally:
            if proc and proc.returncode is None:
                proc.terminate()
                try:await asyncio.wait_for(proc.wait(),7)
                except asyncio.TimeoutError:
                    proc.kill();await proc.wait()
            if proc and proc.stderr:
                try:
                    err=(await asyncio.wait_for(proc.stderr.read(4096),3)).decode('utf-8','replace')
                    origin['stderr_tail']=err[-600:]
                except (OSError,asyncio.TimeoutError):pass
    raw=b''.join(lines)
    origin['trace_sha256']=sha(raw)
    origin['original_stdio_lines']=len(lines)
    (out/'original_stdio.jsonl').write_bytes(raw)
    (out/'origin.json').write_text(json.dumps(origin,indent=2,sort_keys=True,ensure_ascii=False)+'\n')
    (out/'calls.json').write_text(json.dumps(calls,indent=2,sort_keys=True,ensure_ascii=False)+'\n')
    spec={'schema':'risu-mcp-observation-contract-v1','rules':selected['contracts']}
    (out/'contract.json').write_text(json.dumps(spec,indent=2,sort_keys=True,ensure_ascii=False)+'\n')
    state_wits=[{'session':'default','request_line':c['request_line'],
                 'response_line':c['response_line'],'tool':c['tool'],
                 'before_sha256':c['before_sha256'],'after_sha256':c['after_sha256']}
                 for c in calls if c.get('status')=='CAPTURED'
                 and any(r['tool']==c['tool'] and r['kind'].startswith('state-')
                         for r in selected['contracts'])]
    evidence={'schema':'risu-mcp-state-witness-v1','trace_sha256':sha(raw),'records':state_wits}
    (out/'state_witness.json').write_text(
        json.dumps(evidence,indent=2,sort_keys=True,ensure_ascii=False)+'\n')
    print('B16_INDEPENDENT_NATIVE_SOURCE',json.dumps({k:origin.get(k) for k in (
        'case','status','source_commit','calls_executed',
        'catalog_change_notifications_seen','trace_sha256','error_kind')},sort_keys=True))

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--case',choices=('AISH','MM'),required=True)
    p.add_argument('--source',required=True,type=Path)
    p.add_argument('--executable',required=True,type=Path)
    p.add_argument('--manifest',type=Path,default=Path('benchmarks/p6b16/FROZEN_NEW_ORIGINAL_SERVERS.json'))
    p.add_argument('--out',required=True,type=Path)
    a=p.parse_args()
    asyncio.run(capture(a.case,a.source.resolve(),a.executable.resolve(),a.manifest,a.out))
if __name__=='__main__':
    main()
