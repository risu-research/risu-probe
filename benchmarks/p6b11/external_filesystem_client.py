"""Real official MCP Python SDK ClientSession against genuine pinned external Node MCP server.

Both original/fixed Filesystem Server source revisions are B7 DEVELOPMENT cases,
not a new independent bug detection set. Synthetic temporary file only.
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

EXPECTED="one\ntwo\nthree\nfour\n"

async def visit(rev:str,root:Path,work:Path,out:Path):
    raw=out/"original_raw_stdio.jsonl"
    tee=Path(__file__).resolve().with_name("external_filesystem_tee.py")
    params=StdioServerParameters(
        command=sys.executable,
        args=["-u",str(tee),"--capture",str(raw),
              "--root",str(root),"--allowed",str(work)],
    )
    sample=work/"sample.txt"
    async with stdio_client(params) as (reader,writer):
        async with ClientSession(reader,writer) as session:
            init=await session.initialize()
            tools=await session.list_tools()
            matches=[t for t in tools.tools if t.name=="read_text_file"]
            if len(matches)!=1:
                raise RuntimeError("Pinned external upstream server failed actual SDK tool discovery")
            outcomes={}
            for label,num in (("head_zero",0),("normal_two",2)):
                result=await session.call_tool("read_text_file",{"path":str(sample),"head":num})
                if result.isError:
                    raise RuntimeError("Original external Filesystem server reported unexpected error")
                text="".join(block.text for block in result.content if getattr(block,"type",None)=="text")
                outcomes[label]={"text":text,"sha256":hashlib.sha256(text.encode()).hexdigest(),
                                 "length":len(text),"isError":False}
    if not raw.exists():
        raise RuntimeError("Actual external SDK wire bytes were not preserved")
    score={
      "schema":"risu-p6b11-external-filesystem-real-sdk-observation-v1",
      "dataset_role":"KNOWN_B7_DEVELOPMENT_PAIR_NOT_NEW_INDEPENDENT_HOLDOUT",
      "revision":rev,"real_original_upstream_source":True,
      "real_mcp_sdk_stdio":True,
      "synthetic_file_content_sha256":hashlib.sha256(EXPECTED.encode()).hexdigest(),
      "protocol_negotiated":getattr(init,"protocolVersion","UNKNOWN"),
      "raw_capture_sha256":hashlib.sha256(raw.read_bytes()).hexdigest(),
      "outcomes":outcomes,
      "claim_boundary":"Only real pinned public original Node Filesystem Server stdio with Python MCP SDK client, synthetic local file, no service/prod data",
    }
    (out/"origin.json").write_text(json.dumps(score,indent=2,sort_keys=True)+"\n")
    print("ORIGINAL_UPSTREAM_STDIO",rev,score["protocol_negotiated"],
          {k:{"isError":v["isError"],"length":v["length"]} for k,v in outcomes.items()})

async def main(out:Path):
    work=Path.cwd()/".b11-external-synthetic-allowed"
    work.mkdir(parents=True,exist_ok=False)
    (work/"sample.txt").write_text(EXPECTED,encoding="utf-8")
    for rev in ("old","fixed"):
        root=Path.cwd()/(".b11-upstream-FS5184-"+rev)
        sub=out/rev
        sub.mkdir(parents=True,exist_ok=True)
        await visit(rev,root,work,sub)

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("out",type=Path)
    a=p.parse_args()
    asyncio.run(main(a.out))
