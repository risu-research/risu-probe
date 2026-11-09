"""Capture authentic original stdout MCP messages from pinned public upstream process.

Only predetermined synthetic cases; preserves the server's exact stdout byte lines.
The trace interleaves our own actual stdin request bytes and original stdout bytes.
This is not a remote target, external network call or production attestation.
"""
from __future__ import annotations
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import tempfile

MAX_LINE=524_288
MAX_CAPTURE=3_000_000
SUPPORTED={'PARTICULARS15':('workspace_status','topics_list'),
           'ROBOT682':('literal_code','normal_code'),
           'HITCH60':('missing_text','explicit_text','text_only')}

async def execute(binary:Path,server_args:list[str],family:str,version:str,
                  out:Path,pythonpath:Path|None,hitch_source:Path|None)->dict:
    if family not in SUPPORTED or version not in ('old','fixed'):
        raise ValueError('Only two preregistered synthetic families and revisions')
    exe=binary.resolve(strict=True)
    if not exe.is_file() or not os.access(exe,os.X_OK):
        raise RuntimeError('Executable does not exist or is not executable')
    if out.exists() or out.is_symlink():
        raise RuntimeError('Refuse overwrite of evidence output')
    with tempfile.TemporaryDirectory(prefix='b11-raw-stdio-public-') as temp:
        env={'PATH':os.environ.get('PATH',''),
             'HOME':temp,'CI':'true','NO_COLOR':'1',
             'PYTHONDONTWRITEBYTECODE':'1'}
        if pythonpath is not None:
            env['PYTHONPATH']=str(pythonpath.resolve(strict=True))
        if family=='HITCH60':
            if hitch_source is None or hitch_source.is_symlink() or not hitch_source.is_file():
                raise RuntimeError('Original Ruby canonical result path required')
            env['RISU_B11_HITCH_SOURCE_JSON']=str(hitch_source.resolve(strict=True))
        proc=await asyncio.create_subprocess_exec(str(exe),*server_args,
            cwd=temp,env=env,stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=MAX_LINE+2)
        trace=[]
        async def send(message):
            assert proc.stdin and proc.stdout
            raw=(json.dumps(message,ensure_ascii=False,separators=(',',':'))+'\n').encode()
            if len(raw)>8192:raise RuntimeError('Unexpectedly large synthetic call')
            proc.stdin.write(raw)
            await asyncio.wait_for(proc.stdin.drain(),15)
            trace.append(raw)
            if 'id' not in message:return None
            answer=await asyncio.wait_for(proc.stdout.readline(),25)
            if not answer or len(answer)>MAX_LINE or not answer.endswith(b'\n'):
                if family in ('ROBOT682','HITCH60') and proc.stderr is not None:
                    # These are locally authored synthetic wrappers. Bound the
                    # import/SDK startup error to assist debugging; no user
                    # data or production logs are used in these test runs.
                    startup=await asyncio.wait_for(proc.stderr.read(2048),3)
                    raise RuntimeError('Synthetic MCP SDK wrapper startup failed: '+
                                       startup.decode('utf-8','replace')[-1500:])
                raise RuntimeError('Upstream stdio response absent/over-sized/truncated')
            obj=json.loads(answer)
            if type(obj) is not dict or obj.get('jsonrpc')!='2.0' or obj.get('id')!=message['id']:
                raise RuntimeError('Upstream JSON-RPC correlation failed')
            trace.append(answer)
            return obj
        try:
            init=await send({'jsonrpc':'2.0','id':1,'method':'initialize',
                'params':{'protocolVersion':'2025-11-25',
                          'capabilities':{},'clientInfo':{'name':'b11-public','version':'1'}}})
            if type(init.get('result')) is not dict:
                raise RuntimeError('Pinned upstream MCP initialization failed')
            await send({'jsonrpc':'2.0','method':'notifications/initialized'})
            listing=await send({'jsonrpc':'2.0','id':2,'method':'tools/list','params':{}})
            if type(listing.get('result')) is not dict:
                raise RuntimeError('Pinned upstream tools/list failed')
            result=listing['result']
            if result.get('nextCursor'):
                raise RuntimeError('Uncompleted native tool catalog; use a cursor-aware capture')
            names={item.get('name') for item in result.get('tools',[]) if type(item) is dict}
            if not set(SUPPORTED[family]).issubset(names):
                raise RuntimeError('Frozen expected tool missing from upstream catalog')
            outcomes={}
            for i,name in enumerate(SUPPORTED[family],10):
                call=await send({'jsonrpc':'2.0','id':i,'method':'tools/call',
                                 'params':{'name':name,'arguments':{}}})
                result=call.get('result')
                if type(result) is not dict:
                    raise RuntimeError('Unexpected tool-level JSON-RPC error')
                outcomes[name]={
                    'is_error':result.get('isError',False),
                    'structured_present':'structuredContent' in result,
                    'text_blocks':sum(type(x) is dict and x.get('type')=='text'
                                      for x in result.get('content',[]))
                }
            raw=b''.join(trace)
            if len(raw)>MAX_CAPTURE:
                raise RuntimeError('Original session exceeded local evidence budget')
            out.mkdir(parents=True)
            (out/'original_stdio.jsonl').write_bytes(raw)
            info={
                'schema':'risu-b11-original-stdout-mcp-stdio-v1',
                'family':family,'revision':version,
                'server_executable_sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),
                'trace_sha256':hashlib.sha256(raw).hexdigest(),
                'evidence_transport':'ACTUAL_SOURCE_EXECUTION_RAW_UPSTREAM_PROCESS_STDOUT',
                'trace_request_lines':'EXACT_CLIENT_STDIN_BYTES_INTERLEAVED',
                'trace_response_lines':'ORIGINAL_SERVER_STDOUT_BYTES_NO_REENCODING',
                'upstream_native_mcp_server':family=='PARTICULARS15',
                'formatter_in_mcp_sdk_harness':family=='ROBOT682',
                'original_ruby_source_in_mcp_sdk_harness':family=='HITCH60',
                'protocol_negotiated':init['result'].get('protocolVersion'),
                'tool_outcomes':outcomes,
                'synthetic_data_only':True,'external_mcp_calls':False,
                'tool_list_size':len(names)
            }
            (out/'origin.json').write_text(json.dumps(info,indent=2,sort_keys=True)+'\n')
            print('B11_ORIGINAL_STDIO_SOURCE_CAPTURE',family,version,
                  info['protocol_negotiated'],outcomes,info['trace_sha256'])
            return info
        finally:
            if proc.returncode is None:
                proc.terminate()
                try:await asyncio.wait_for(proc.wait(),7)
                except asyncio.TimeoutError:
                    proc.kill();await proc.wait()

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--binary',required=True,type=Path)
    p.add_argument('--server-arg',action='append',default=[])
    p.add_argument('--pythonpath',type=Path)
    p.add_argument('--hitch-source',type=Path)
    p.add_argument('--family',required=True,choices=tuple(SUPPORTED))
    p.add_argument('--revision',required=True,choices=('old','fixed'))
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    asyncio.run(execute(a.binary,a.server_arg,a.family,a.revision,
                        a.out,a.pythonpath,a.hitch_source))
if __name__=='__main__':main()
