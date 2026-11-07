"""Public benchmark: normalize observed SDK client/server objects to JSON-RPC JSONL.

This is NOT a literal stdio or network wire capture; it is assembled from
completed official MCP SDK 2.1.0 in-memory legacy calls. The negative examples
are controlled synthetic mutations and are never presented as upstream bugs.
"""
from __future__ import annotations
import argparse
import asyncio
import copy
import importlib.metadata
import json
from pathlib import Path


async def record(out_dir: Path) -> None:
    from mcp.client import Client
    from mcp.server.mcpserver import MCPServer
    if importlib.metadata.version('mcp') != '2.1.0' or importlib.metadata.version('mcp-types') != '2.1.0':
        raise RuntimeError('Official MCP 2.1.0 and mcp-types 2.1.0 required')
    server = MCPServer('risu-p6b4-synthetic')
    @server.tool()
    def get_count() -> dict[str,int]:
        return {'value':3}
    @server.tool()
    def get_total() -> dict[str,int]:
        return {'value':17}

    async with Client(server, mode='legacy') as client:
        listed = await client.list_tools()
        first = await client.call_tool('get_count',{})
        second = await client.call_tool('get_total',{})
    tools = [tool.model_dump(by_alias=True,exclude_none=True) for tool in listed.tools]
    def body(o):
        return o.model_dump(by_alias=True,exclude_none=True)
    req=lambda i,m,p:{'jsonrpc':'2.0','id':i,'method':m,'params':p}
    res=lambda i,v:{'jsonrpc':'2.0','id':i,'result':v}
    baseline=[req(101,'tools/list',{}),res(101,{'tools':tools}),
              req(102,'tools/call',{'name':'get_count','arguments':{}}),res(102,body(first)),
              req(103,'tools/call',{'name':'get_total','arguments':{}}),res(103,body(second))]
    def write(name,data):
        p=out_dir/name
        p.write_text(''.join(json.dumps({'session':'sdk-local-fixture', 'message':rec},ensure_ascii=False,sort_keys=True)+'\n' for rec in data),encoding='utf-8')
    out_dir.mkdir(parents=True,exist_ok=True)
    write('sdk_real_normalized.jsonl',baseline)
    missing=copy.deepcopy(baseline)
    missing[3]['result'].pop('structuredContent',None)
    write('mutation_missing_structured.jsonl',missing)
    wrong=copy.deepcopy(baseline)
    wrong[5]['result']['structuredContent']={'value':'not-an-integer'}
    write('mutation_wrong_type.jsonl',wrong)
    error=copy.deepcopy(baseline)
    error[3]['result']['isError']=True
    error[3]['result'].pop('structuredContent',None)
    write('mutation_error_exempt.jsonl',error)
    meta={'schema':'risu-p6b4-official-sdk-normalized-sample-v1',
          'sdk_version':'2.1.0','protocol':'2025-11-25',
          'capture_format':'NORMALIZED_SDK_OBSERVED_OBJECTS_NOT_LITERAL_JSONRPC_WIRE',
          'normal_sample':'SDK produced tools/list and tools/call result objects in actual in-memory legacy session',
          'mutations':['missing structuredContent','wrong structuredContent value type','isError true control'],
          'provenance':'Public synthetic data; no real private server, no external endpoint',
          'origin_authenticated':False}
    (out_dir/'origin.json').write_text(json.dumps(meta,sort_keys=True,indent=2)+'\n')
    assert len(tools)==2 and all('outputSchema' in t for t in tools)
    assert all('structuredContent' in body(x) for x in (first,second))
    print('P6B4_OFFICIAL_SDK_2_1_0_NORMALIZED_CLIENT_SERVER_RECORDS',len(baseline),flush=True)

if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--out-dir',type=Path,required=True)
    a=p.parse_args()
    asyncio.run(record(a.out_dir))
