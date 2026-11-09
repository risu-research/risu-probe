"""Bridge an ORIGINAL executed Ruby Hitch normalizer result through MCP stdio.

The original Ruby result JSON is read verbatim. No reformatting of its content[]
or structuredContent. This Python SDK server is an evaluation wrapper, NOT the
actual Rails HTTP MCP server.
"""
from __future__ import annotations
import asyncio
import json
import os
from pathlib import Path

from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

DATA=Path(os.environ["RISU_B11_HITCH_SOURCE_JSON"]).resolve(strict=True)
if DATA.is_symlink() or DATA.stat().st_size>16384:
    raise RuntimeError("Untrusted or oversized original Ruby source outcome")
record=json.loads(DATA.read_text(encoding="utf-8"))
if record.get("schema")!="risu-b11-hitch60-original-ruby-result-v1" or record.get("source")!="ACTUAL_PINNED_UPSTREAM_RUBY_RESULT_NORMALIZER":
    raise RuntimeError("Original source result is missing")
source=record["records"]
EXPECTED=("missing_text","explicit_text","text_only")
if set(source)!=set(EXPECTED):
    raise RuntimeError("Expected exactly three source results")

server=Server("risu-hitch60-original-ruby-stdio-bridge")

@server.list_tools()
async def list_tools()->list[types.Tool]:
    return [types.Tool.model_validate({
        "name":name,
        "description":"Original pinned Hitch Ruby normalizer output under test",
        "inputSchema":{"type":"object","properties":{},"additionalProperties":False},
        **({"outputSchema":{
            "type":"object","properties":{"value":{"type":"string"}},
            "required":["value"],"additionalProperties":False}}
           if name!="text_only" else {}),
    }) for name in EXPECTED]

@server.call_tool()
async def call_tool(name:str,arguments:dict)->types.CallToolResult:
    if name not in source:
        return types.CallToolResult.model_validate({
            "isError":True,"content":[{"type":"text","text":"Unknown tool"}]})
    # Genuine upstream normalized object, converted only by the protocol
    # serializer. Do not invent a text mirror in this bridge.
    return types.CallToolResult.model_validate(source[name])

async def main():
    async with stdio_server() as (reader,writer):
        await server.run(reader,writer,server.create_initialization_options())

if __name__=="__main__":
    asyncio.run(main())
