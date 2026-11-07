"""Capture raw bidirectional stdio JSON-RPC from only our public fixture.

Invokes an isolated Python interpreter provided by CI, never a user-selected command
or remote MCP server. JSONL contains synthetic non-sensitive values only.
"""
from __future__ import annotations
import argparse
import asyncio
import hashlib
import importlib.metadata
import json
from pathlib import Path
import sys

async def capture(out: Path, style: str = 'fastmcp') -> None:
    if style not in ('fastmcp','official-v1'): raise ValueError('Unknown public fixture style')
    script = Path(__file__).with_name('external_server.py' if style=='fastmcp' else 'official_v1_server.py').resolve(strict=True)
    proc = await asyncio.create_subprocess_exec(sys.executable, str(script),
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL, cwd=str(script.parent))
    raw: list[bytes] = []
    async def query(msg: dict) -> dict:
        data=(json.dumps(msg,separators=(',',':'),ensure_ascii=False)+'\n').encode()
        if len(data)>4096: raise AssertionError('oversize fixture request')
        raw.append(data)
        assert proc.stdin is not None and proc.stdout is not None
        proc.stdin.write(data)
        await asyncio.wait_for(proc.stdin.drain(),20)
        if 'id' not in msg:return {}
        line=await asyncio.wait_for(proc.stdout.readline(),20)
        if len(line)>524288 or not line: raise RuntimeError('missing/oversized stdio reply')
        row=json.loads(line)
        if row.get('jsonrpc')!='2.0' or row.get('id')!=msg['id']: raise RuntimeError('mismatched stdio request ID')
        raw.append(line)
        return row
    try:
        reply=await query({'jsonrpc':'2.0','id':100,'method':'initialize','params':{
            'protocolVersion':'2025-11-25','capabilities':{},
            'clientInfo':{'name':'risu-public-matrix','version':'1.0'}}})
        if 'error' in reply: raise RuntimeError('initialize error: '+str(reply['error'])[:160])
        negotiated=reply['result']['protocolVersion']
        await query({'jsonrpc':'2.0','method':'notifications/initialized'})
        tools=await query({'jsonrpc':'2.0','id':101,'method':'tools/list','params':{}})
        if 'error' in tools: raise RuntimeError('tools/list error: '+str(tools['error'])[:160])
        names={x['name'] for x in tools['result']['tools']}
        if not {'get_count','get_label','get_error'} <= names:raise RuntimeError('fixture missing tools')
        for n,id_ in [('get_count',102),('get_label',103),('get_error',104)]:
            result=await query({'jsonrpc':'2.0','id':id_,'method':'tools/call',
                'params':{'name':n,'arguments':{}}})
            if 'error' in result: raise RuntimeError('protocol-level error: '+n)
            if n=='get_error' and result['result'].get('isError') is not True:
                raise RuntimeError('expected tool error has not surfaced')
            if n!='get_error' and result['result'].get('isError',False):
                raise RuntimeError('successful fixture call failed '+n)
        data=b''.join(raw)
        assert len(data)<500_000
        out.mkdir(parents=True,exist_ok=True)
        (out/'raw_stdio.jsonl').write_bytes(data)
        (out/'origin.json').write_text(json.dumps({
            'schema':'risu-p6b5-interop-origin-v1',
            'framework':'fastmcp' if style=='fastmcp' else 'mcp',
            'version':importlib.metadata.version('fastmcp' if style=='fastmcp' else 'mcp'),
            'requested_protocol':'2025-11-25','negotiated_protocol':negotiated,
            'transport':'SEPARATE_PROCESS_LITERAL_STDIO_JSONRPC',
            'trace_sha256':hashlib.sha256(data).hexdigest(),'messages':len(raw),
            'data':'PUBLIC_SYNTHETIC_ONLY','remote_connections':False,
            'no_untrusted_servers':True,'server_code_from_public_fixture':True
        },indent=2,sort_keys=True)+'\n')
        print('P6B5_RAW_STDIO_CAPTURE',style,negotiated,len(raw),flush=True)
    finally:
        if proc.returncode is None:
            proc.terminate()
            try:await asyncio.wait_for(proc.wait(),10)
            except asyncio.TimeoutError:proc.kill();await proc.wait()

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--out',type=Path,required=True)
    ap.add_argument('--style',choices=['fastmcp','official-v1'],default='fastmcp')
    args=ap.parse_args();asyncio.run(capture(args.out,args.style))
