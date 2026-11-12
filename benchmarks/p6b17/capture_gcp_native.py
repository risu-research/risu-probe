"""B17 prelocked original GoogleCloudPlatform MCP server stdio capture.

Runs only exact frozen source, two synthetic location requests, and original
JSON-RPC. No replacement tool handler or network in the server process.
"""
from __future__ import annotations
import argparse,asyncio,hashlib,json,os,tempfile
from pathlib import Path

PIN='cedc20fdc8fdf22fc8b411a3947ae03c71cbc926'
SOURCE='examples/servers/structured_output_lowlevel.py'
TOOL='get_weather'

async def capture(executable:Path,source:Path,manifest:Path,out:Path):
    m=json.loads(manifest.read_text('utf-8'))
    claim=m['heldout']
    assert m['schema']=='risu-p6b17-origin-and-unseen-source-cohort-v1'
    assert m['frozen_product_blob']=='75180de2dbd78165d2e970ee15e99df14804e7f1'
    assert (claim['revision'],claim['path'],claim['tool'])==(PIN,SOURCE,TOOL)
    if out.exists() or not (source/SOURCE).is_file() or not executable.is_file():
        raise ValueError('No native source or refusing to overwrite firstpass')
    out.mkdir(parents=True)
    origin={'schema':'risu-b17-native-original-gcp-v1','repository':claim['repository'],
            'full_revision':PIN,'source_file':SOURCE,
            'predeclared_calls':len(claim['original_calls']),
            'original_source_unmodified':True,'status':'UNVERIFIED'}
    lines=[]
    call_log=[]
    proc=None
    with tempfile.TemporaryDirectory(prefix='risu-b17-native-gcp-') as d:
        root=Path(d).resolve()
        env={'PATH':os.environ.get('PATH',''),'HOME':str(root),
             'LANG':'C.UTF-8','LC_ALL':'C.UTF-8','CI':'true',
             'PYTHONDONTWRITEBYTECODE':'1','NO_COLOR':'1'}
        async def transact(request):
            assert proc and proc.stdin and proc.stdout
            req=(json.dumps(request,ensure_ascii=False,separators=(',',':'))+chr(10)).encode()
            proc.stdin.write(req)
            await asyncio.wait_for(proc.stdin.drain(),12)
            lines.append(req)
            begin=len(lines)
            if 'id' not in request:return None,begin,None
            for _ in range(20):
                raw=await asyncio.wait_for(proc.stdout.readline(),30)
                if not raw or not raw.endswith(bytes([10])) or len(raw)>524288:
                    raise RuntimeError('Original MCP server missing complete JSON-RPC line')
                lines.append(raw)
                value=json.loads(raw)
                if type(value) is not dict or value.get('jsonrpc')!='2.0':
                    raise RuntimeError('Original server stdout was not protocol JSON-RPC')
                if value.get('id')==request['id']:return value,begin,len(lines)
                if 'id' not in value:continue
                raise RuntimeError('Unsupported upstream server-to-client request')
            raise RuntimeError('Too many unmatched MCP notifications')
        try:
            proc=await asyncio.create_subprocess_exec(str(executable),str((source/SOURCE).resolve()),
                cwd=str(root),env=env,stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,limit=524290)
            initialized,_,_=await transact({'jsonrpc':'2.0','id':1,'method':'initialize',
                'params':{'protocolVersion':'2025-11-25','capabilities':{},
                'clientInfo':{'name':'risu-b17-frozen-source','version':'1'}}})
            if type(initialized.get('result')) is not dict:
                raise RuntimeError('Original source rejected initialize')
            origin['negotiated_protocol']=initialized['result'].get('protocolVersion')
            await transact({'jsonrpc':'2.0','method':'notifications/initialized'})
            catalog,_,_=await transact({'jsonrpc':'2.0','id':2,'method':'tools/list','params':{}})
            advertised=catalog.get('result',{}).get('tools',[])
            if type(advertised) is not list or len(advertised)>128:
                raise RuntimeError('Original source catalog invalid')
            source_entry=next((x for x in advertised if type(x) is dict and x.get('name')==TOOL),None)
            origin['advertised_tool_present']=source_entry is not None
            if source_entry is None:raise RuntimeError('Declared source tool absent')
            origin['source_advertised_output_schema']=type(source_entry.get('outputSchema')) is dict
            for idx,item in enumerate(claim['original_calls']):
                args=item['arguments']
                original,start,end=await transact({'jsonrpc':'2.0','id':20+idx,
                    'method':'tools/call','params':{'name':TOOL,'arguments':args}})
                call_log.append({'case':item['id'],'request_line':start,
                    'response_line':end,'original_response_id':20+idx,
                    'tool':TOOL,'arguments':args,
                    'original_result_error':original.get('result',{}).get('isError'),
                    'has_structured_content':type(original.get('result',{}).get('structuredContent')) is dict})
            origin['status']='CAPTURED_ORIGINAL'
        except Exception as e:
            origin['status']='UNVERIFIED_NATIVE_EXECUTION'
            origin['failure_kind']=type(e).__name__
            origin['failure_note']=str(e)[:300]
        finally:
            if proc and proc.returncode is None:
                proc.terminate()
                try:await asyncio.wait_for(proc.wait(),7)
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
            if proc and proc.stderr:
                try:
                    err=(await asyncio.wait_for(proc.stderr.read(4096),3)).decode('utf-8','replace')
                    origin['original_stderr_for_setup_only']=err[-1000:]
                except (OSError,asyncio.TimeoutError):pass
    raw=b''.join(lines)
    origin['trace_sha256']=hashlib.sha256(raw).hexdigest()
    origin['calls_captured']=len(call_log)
    origin['stdio_line_count']=len(lines)
    (out/'original_stdio.jsonl').write_bytes(raw)
    (out/'origin.json').write_text(json.dumps(origin,indent=2,sort_keys=True,ensure_ascii=False)+chr(10))
    (out/'call_log.json').write_text(json.dumps(call_log,indent=2,sort_keys=True,ensure_ascii=False)+chr(10))
    (out/'contract.json').write_text(json.dumps(claim['result_contract'],indent=2,
                                  sort_keys=True,ensure_ascii=False)+chr(10))
    print('B17_GCP_PINNED_NATIVE_FIRSTPASS',json.dumps({
        k:origin.get(k) for k in ('status','full_revision','trace_sha256',
          'predeclared_calls','calls_captured','failure_kind')},sort_keys=True))

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--executable',required=True,type=Path)
    p.add_argument('--source',required=True,type=Path)
    p.add_argument('--manifest',type=Path,default=Path('benchmarks/p6b17/FROZEN_UPSTREAM_ORIGIN_COHORT.json'))
    p.add_argument('--out',required=True,type=Path)
    a=p.parse_args()
    asyncio.run(capture(a.executable.resolve(),a.source.resolve(),a.manifest,a.out))
if __name__=='__main__':
    main()
