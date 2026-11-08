"""Run the *original* pinned AG2 MCPToolkit._discover_tools with a local two-page MCP peer.

No real sockets or agents. Only _resolve_config and _mcp_session are replaced with
in-memory test doubles so that actual toolkit discovery code is exercised.
"""
from __future__ import annotations
import argparse
import asyncio
from contextlib import asynccontextmanager
import json
from pathlib import Path
from unittest.mock import patch
from mcp import types
import ag2.tools.toolkits.mcp_server.toolkit as upstream


class PagedPeer:
    def __init__(self,paginated=True):
        self.paginated=paginated
        self.rows=[]
    async def list_tools(self,params=None):
        cursor=getattr(params,'cursor',None) if params is not None else None
        result=(types.ListToolsResult(
            tools=[types.Tool(name='first',description='synthetic',inputSchema={'type':'object'})],
            nextCursor='p2' if self.paginated else None
        ) if cursor is None else
        types.ListToolsResult(
            tools=[types.Tool(name='second',description='synthetic',inputSchema={'type':'object'})]
        ))
        self.rows += [
            {'jsonrpc':'2.0','id':len(self.rows)//2+1,'method':'tools/list',
             'params':{} if cursor is None else {'cursor':cursor}},
            {'jsonrpc':'2.0','id':len(self.rows)//2+1,'result':result.model_dump(by_alias=True,mode='json',exclude_none=True)}
        ]
        return result


async def run_case(paginated):
    peer=PagedPeer(paginated=paginated)
    @asynccontextmanager
    async def session(_resolved,**kwargs):
        yield peer
    toolkit=upstream.MCPToolkit('http://127.0.0.1:1')
    with patch.object(upstream,'_resolve_config',lambda cfg,ctx:cfg),patch.object(upstream,'_mcp_session',session):
        await toolkit._discover_tools(None)
    return {'registered_tool_names':sorted(toolkit._tools),
            'captured_sdk_method_values':peer.rows,
            'actual_list_requests':sum(v.get('method')=='tools/list' for v in peer.rows)}


async def capture():
    return {'schema':'risu-p6b9-ag23262-real-upstream-client-v1',
            'source':'ACTUAL_AG2_TOOLKIT_LOGIC_WITH_IN_MEMORY_MCP_SESSION_TEST_DOUBLE',
            'paginated':await run_case(True),
            'single_page_normal':await run_case(False)}


def main():
    p=argparse.ArgumentParser()
    p.add_argument('output',type=Path)
    a=p.parse_args()
    result=asyncio.run(capture())
    a.output.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
if __name__=='__main__':main()
