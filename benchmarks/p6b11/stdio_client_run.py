"""Official v1 MCP SDK ClientSession over real stdio through the raw-byte tee.

No hand-built JSON-RPC envelopes, no remote service, no credentials.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

CASES = (
 ("render_markdown", "A*p*"),
 ("render_markdown", "_identifier_"),
 ("render_markdown", "서울 [test]"),
 ("render_copy", "cat:astro-ph* AND submittedDate:[202601010000 TO 202602010000]"),
 ("render_copy", "cursor__ABC"),
 ("render_copy", "a`b"),
 ("render_special", "line1\nline2"),
 ("render_special", ""),
 ("render_special", " padded "),
 ("render_special", "tab\there"),
 ("render_bad", "A*p*"),
 ("render_missing", "no line"),
)

async def execute(out:Path):
    out.mkdir(parents=True, exist_ok=True)
    raw=out/"original_raw_stdio.jsonl"
    if raw.exists(): raise RuntimeError("Refuse overwrite of captured raw transport")
    proxy=Path(__file__).resolve().with_name("stdio_tee.py")
    params=StdioServerParameters(
        command=sys.executable,
        args=["-u",str(proxy),"--capture",str(raw)],
    )
    async with stdio_client(params) as (incoming,outgoing):
        async with ClientSession(incoming,outgoing) as session:
            initialized=await session.initialize()
            catalog=await session.list_tools()
            named={t.name for t in catalog.tools}
            if named!={p[0] for p in CASES}:
                raise RuntimeError("Real server discovery does not match declared test tools")
            for name,value in CASES:
                got=await session.call_tool(name,{"value":value})
                if got.isError or got.structuredContent != {"value":value}:
                    raise RuntimeError("Authentic SDK output mismatched actual structured string")
    if not raw.is_file(): raise RuntimeError("MCP stdio tee produced no original bytes")
    result={
        "schema":"risu-b11-real-stdio-sdk-client-safety-v1",
        "transport":"OFFICIAL_MCP_PYTHON_SDK_V1_28_0_OVER_STDIO_SUBPROCESS",
        "real_client_session":True,
        "real_server_stdio":True,
        "synthetic_local_data":True,
        "declared_calls":len(CASES),
        "names":sorted(named),
        "raw_capture_sha256":hashlib.sha256(raw.read_bytes()).hexdigest(),
        "mcp_protocol_negotiated":getattr(initialized,"protocolVersion","UNKNOWN"),
    }
    (out/"client_score.json").write_text(json.dumps(result,indent=2,ensure_ascii=False)+"\n")
    print(json.dumps({k:v for k,v in result.items() if k not in ("names",)},indent=2))

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("output",type=Path)
    a=parser.parse_args()
    asyncio.run(execute(a.output))
