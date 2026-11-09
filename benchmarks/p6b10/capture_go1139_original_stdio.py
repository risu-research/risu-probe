"""B10 provenance upgrade: capture *original* unmodified Go SDK stdio response bytes.

This is development followup of B9 GO1139 (NOT a new independent bug family).
Runs a synthetic test tool using the upstream SDK at exact old/fixed commits.
"""
from __future__ import annotations
import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import os
import tempfile

MAX_LINE=524288
MAX_TRACE=3_000_000

async def capture(binary:Path,out:Path,revision:str)->dict:
    if revision not in ('old','fixed'):raise ValueError('Unknown revision')
    exe=binary.expanduser().resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix='risu-b10-go-public-') as td:
        env={'PATH':os.environ.get('PATH',''),'HOME':td,'CI':'true','NO_COLOR':'1'}
        p=await asyncio.create_subprocess_exec(str(exe),cwd=td,env=env,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.DEVNULL,
            limit=MAX_LINE+2)
        trace=[]
        async def request(obj):
            data=(json.dumps(obj,separators=(',',':'))+'\n').encode('utf-8')
            if len(data)>4096:raise RuntimeError('Unexpectedly large synthetic request')
            assert p.stdin and p.stdout
            p.stdin.write(data)
            await asyncio.wait_for(p.stdin.drain(),10)
            trace.append(data)
            if 'id' not in obj:return None
            raw=await asyncio.wait_for(p.stdout.readline(),15)
            if not raw or len(raw)>MAX_LINE or not raw.endswith(b'\n'):
                raise RuntimeError('Incomplete or oversized upstream stdio response')
            message=json.loads(raw)
            if (type(message) is not dict or message.get('jsonrpc')!='2.0'
                    or message.get('id')!=obj['id']):
                raise RuntimeError('Original upstream stdio correlation failed')
            trace.append(raw)
            return message
        try:
            start=await request({'jsonrpc':'2.0','id':1,'method':'initialize','params':{
                'protocolVersion':'2025-11-25','capabilities':{},
                'clientInfo':{'name':'risu-b10-public-capture','version':'1'}}})
            if 'result' not in start:
                raise RuntimeError('Upstream server did not initialize')
            await request({'jsonrpc':'2.0','method':'notifications/initialized'})
            catalog=await request({'jsonrpc':'2.0','id':2,'method':'tools/list','params':{}})
            if not isinstance(catalog.get('result'),dict):
                raise RuntimeError('Upstream did not advertise tools')
            tools={v.get('name') for v in catalog['result'].get('tools',[])}
            if not {'bad_raw','good_raw'}.issubset(tools):
                raise RuntimeError('Pinned server did not list both synthetic controls')
            bad=await request({'jsonrpc':'2.0','id':3,'method':'tools/call',
                               'params':{'name':'bad_raw','arguments':{}}})
            good=await request({'jsonrpc':'2.0','id':4,'method':'tools/call',
                                'params':{'name':'good_raw','arguments':{}}})
            full=b''.join(trace)
            if len(full)>MAX_TRACE:
                raise RuntimeError('Over budget original stdio capture')
            out.mkdir(parents=True,exist_ok=False)
            (out/'original_stdio.jsonl').write_bytes(full)
            record={'schema':'risu-p6b10-go1139-raw-stdio-origin-v1',
                'family':'GO1139','revision':revision,
                'evidence_type':'RAW_STDIO_ORIGINAL_SERVER_JSONRPC_RESPONSE_BYTES',
                'synthetic_stdin_request_and_original_stdout_response_interleaved':True,
                'source':'EXACT_PINNED_PUBLIC_UPSTREAM_MCP_GO_STDIO_SDK',
                'read_only_synthetic_inputs':True,
                'trace_sha256':hashlib.sha256(full).hexdigest(),
                'protocol_negotiated':start['result'].get('protocolVersion'),
                'responses':{
                    'bad_raw':{'error':bad.get('result',{}).get('isError',False),
                               'response_is_jsonrpc_error':'error' in bad},
                    'good_raw':{'error':good.get('result',{}).get('isError',False),
                                'response_is_jsonrpc_error':'error' in good}},
                'preserved_original_stdout_lines':len(trace)//2,
                'original_stdio_but_wrapper':True}
            (out/'origin.json').write_text(json.dumps(record,indent=2,sort_keys=True)+'\n')
            print('RISU_B10_ORIGINAL_GO_STDIO',revision,record['responses'],record['trace_sha256'])
            return record
        finally:
            if p.returncode is None:
                p.terminate()
                try:await asyncio.wait_for(p.wait(),5)
                except asyncio.TimeoutError:
                    p.kill()
                    await p.wait()

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--binary',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--revision',choices=('old','fixed'),required=True)
    a=p.parse_args()
    asyncio.run(capture(a.binary,a.out,a.revision))
if __name__=='__main__':main()
