"""Capture byte-for-byte raw JSON-RPC messages over actual MCP SDK 2.1.0 stdio.

Only spawns this repository's PUBLIC synthetic fixture server; uses bounded
local subprocess I/O, no external API or user-supplied executable.
"""
from __future__ import annotations
import argparse
import asyncio
import hashlib
import importlib.metadata
import json
from pathlib import Path
import sys

async def capture(out_dir:Path) -> dict:
    if importlib.metadata.version('mcp')!='2.1.0' or importlib.metadata.version('mcp-types')!='2.1.0':
        raise RuntimeError('Official SDK 2.1.0 and mcp-types 2.1.0 required')
    server=Path(__file__).with_name('stdio_fixture_server.py').resolve(strict=True)
    proc=await asyncio.create_subprocess_exec(sys.executable,str(server),
          stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,
          stderr=asyncio.subprocess.DEVNULL,cwd=str(server.parent))
    transcript=[]
    async def message(req:dict)->dict:
        raw=(json.dumps(req,ensure_ascii=False,separators=(',',':'))+'\n').encode('utf-8')
        assert len(raw)<8192
        transcript.append(raw)
        assert proc.stdin is not None and proc.stdout is not None
        proc.stdin.write(raw)
        await asyncio.wait_for(proc.stdin.drain(),10)
        if 'id' not in req:return {}
        line=await asyncio.wait_for(proc.stdout.readline(),10)
        if not line or len(line)>524288:raise RuntimeError('MCP stdio response absent or too large')
        obj=json.loads(line)
        if obj.get('jsonrpc')!='2.0' or obj.get('id')!=req['id']:
            raise RuntimeError('Actual MCP stdio response ID mismatch')
        transcript.append(line)
        if 'error' in obj:raise RuntimeError('MCP SDK stdio fixture returned protocol error '+str(obj['error'])[:200])
        return obj
    try:
        init=await message({'jsonrpc':'2.0','id':100,'method':'initialize','params':{
            'protocolVersion':'2025-11-25','capabilities':{},
            'clientInfo':{'name':'risu-p6b4-local-recorder','version':'0.0.1'}}})
        protocol=init['result']['protocolVersion']
        if protocol!='2025-11-25':raise RuntimeError('Unexpected negotiated protocol '+str(protocol))
        await message({'jsonrpc':'2.0','method':'notifications/initialized'})
        catalog=await message({'jsonrpc':'2.0','id':101,'method':'tools/list','params':{}})
        tools=catalog['result']['tools']
        names={t['name'] for t in tools}
        if not {'get_count','get_total'}<=names:raise RuntimeError('Synthetic tools missing from actual stdio listing')
        a=await message({'jsonrpc':'2.0','id':102,'method':'tools/call','params':{'name':'get_count','arguments':{}}})
        b=await message({'jsonrpc':'2.0','id':103,'method':'tools/call','params':{'name':'get_total','arguments':{}}})
        for value in (a,b):
            if value['result'].get('isError',False) or 'structuredContent' not in value['result']:
                raise RuntimeError('Expected official SDK successful structured tool result')
    finally:
        if proc.returncode is None:
            proc.terminate()
            try:await asyncio.wait_for(proc.wait(),5)
            except asyncio.TimeoutError:
                proc.kill();await proc.wait()
    out_dir.mkdir(parents=True,exist_ok=True)
    raw=b''.join(transcript)
    trace=out_dir/'sdk_real_stdio.jsonl'
    trace.write_bytes(raw)
    rows=[json.loads(x) for x in raw.splitlines()]
    assert len(rows)==9, len(rows) # initialize, list, two calls + replies, initialized notification
    missing=[dict(x) for x in rows]
    missing[-3]['result']=dict(missing[-3]['result']) # call 102 response
    missing[-3]['result'].pop('structuredContent',None)
    wrong=[dict(x) for x in rows]
    wrong[-1]['result']=dict(wrong[-1]['result']) # call 103 response
    wrong[-1]['result']['structuredContent']={'value':'not-an-int'}
    for name,data in [('mutation_stdio_missing.jsonl',missing),('mutation_stdio_wrong.jsonl',wrong)]:
        (out_dir/name).write_bytes(b''.join((json.dumps(row,ensure_ascii=False,separators=(',',':'))+'\n').encode('utf-8') for row in data))
    meta={'schema':'risu-p6b4-native-mcp-stdio-v1','official_sdk':'mcp==2.1.0, mcp-types==2.1.0',
          'negotiated_protocol':protocol,'transport':'LITERAL_SEPARATE_PROCESS_STDIO_JSONRPC',
          'original_bytes_captured':True,'server_source':'PUBLIC synthetic SDK fixture in same repository',
          'requests_and_responses':len(rows),'original_sha256':hashlib.sha256(raw).hexdigest(),
          'mutated_controls_are_real_wire':False,'captured_content_authentic_to_external_server':False,
          'external_network_called':False,'secret_data_used':False}
    (out_dir/'stdio_origin.json').write_text(json.dumps(meta,indent=2,sort_keys=True)+'\n')
    print('P6B4_OFFICIAL_SDK_NATIVE_STDIO_CAPTURE',meta['original_sha256'],flush=True)
    return meta

if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--out-dir',type=Path,required=True)
    args=p.parse_args()
    asyncio.run(capture(args.out_dir))
