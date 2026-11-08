"""Run genuine pinned mcp-proxy list handlers against a local synthetic paged peer.

Imports the original source tree through PYTHONPATH; no sockets or credentials.
This is component-level in-memory execution, not an MCP stdio capture.
"""
from __future__ import annotations
import argparse
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from mcp import types
from mcp_proxy.proxy_server import create_proxy_server


def t(name: str) -> types.Tool:
    return types.Tool(name=name,description="Synthetic public pagination",inputSchema={"type":"object"})


class LocalPagedPeer:
    def __init__(self):
        self.received=[]
    async def initialize(self):
        return SimpleNamespace(
            capabilities=SimpleNamespace(tools=True,resources=False,prompts=False,logging=False),
            serverInfo=SimpleNamespace(name="p6b9-synthetic-paged-peer"))
    async def list_tools(self,params=None):
        cursor=getattr(params,"cursor",None) if params is not None else None
        self.received.append(cursor)
        if cursor is None:
            return types.ListToolsResult(tools=[t("first")],nextCursor="p2")
        if cursor=="p2":
            return types.ListToolsResult(tools=[t("second")])
        raise RuntimeError("Unknown synthetic cursor")


async def capture():
    peer=LocalPagedPeer()
    proxy=await create_proxy_server(peer)
    handler=proxy.request_handlers[types.ListToolsRequest]
    values=[]
    for cursor in (None,"p2"):
        params={} if cursor is None else {"cursor":cursor}
        req=types.ListToolsRequest.model_validate({"method":"tools/list","params":params})
        result=await handler(req)
        actual=result.model_dump(mode="json",by_alias=True,exclude_none=True)
        values.append({"requested_cursor":cursor,"returned":actual})
    return {"schema":"risu-p6b9-proxy253-component-v1",
            "source":"ACTUAL_PINNED_UPSTREAM_PROXY_HANDLER_WITH_SYNTHETIC_REMOTE_PEER",
            "actual_remote_cursors":peer.received,"pages":values}


def main():
    p=argparse.ArgumentParser()
    p.add_argument("output",type=Path)
    args=p.parse_args()
    r=asyncio.run(capture())
    args.output.write_text(json.dumps(r,indent=2,sort_keys=True)+"\n")
if __name__=="__main__":main()
