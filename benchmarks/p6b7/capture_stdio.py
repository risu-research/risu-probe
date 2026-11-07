"""P6-B7 frozen independent upstream stdio capture.

Run ONLY in a disposable read-only-token public GitHub runner, after checking out
the exact approved upstream commit. Node execution is confined to synthetic inputs.
No real user files, credentials, cloud integrations or external MCP URLs.
"""
from __future__ import annotations
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

CASES={
    "A11Y205":{"repo":"Community-Access/accessibility-agents",
               "old":"284865a7e07b847972b63447a6b17020f08bb618",
               "fixed":"decf6bac7f086c19afb242797b4974671ceff597",
               "exec":"mcp-server/stdio.js","tool":"check_contrast",
               "args":{"foreground":"#767676","background":"#ffffff"}},
    "FS5184":{"repo":"modelcontextprotocol/servers",
              "old":"3bd1337713c796ada8a3dbb088dd911aa83dc932",
              "fixed":"0dce8bd9b65d91a6f7afe1d8f99ffea5d5cf8fe4",
              "exec":"src/filesystem/dist/index.js","tool":"read_text_file"}
}
MAX_RESPONSE=524288

async def capture(repo_root:Path, family:str, version:str, result_dir:Path)->dict:
    spec=CASES[family]
    assert version in ("old","fixed")
    # Exact, versioned Git source and executable locations. No path provided by user.
    root=repo_root.resolve(strict=True)
    exe=(root/spec["exec"]).resolve(strict=True)
    if not exe.is_file() or not exe.is_relative_to(root):
        raise RuntimeError("Frozen built upstream executable not present")
    with tempfile.TemporaryDirectory(prefix="risu-b7-public-synthetic-") as work:
        tmp=Path(work)
        env={"PATH":os.environ["PATH"],"HOME":str(tmp),"CI":"true",
             "NODE_ENV":"production","NO_COLOR":"1"}
        argv=["node",str(exe)]
        if family=="FS5184":
            allowed=tmp/"allowed";allowed.mkdir()
            text=allowed/"sample.txt"
            text.write_text("one\ntwo\nthree\nfour\n",encoding="utf-8")
            argv.append(str(allowed))
        p=await asyncio.create_subprocess_exec(*argv,cwd=str(exe.parent),env=env,
            stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,limit=MAX_RESPONSE+2)
        trace:list[bytes]=[]
        async def rpc(message:dict)->dict:
            raw=(json.dumps(message,separators=(",",":"),ensure_ascii=False)+"\n").encode()
            if len(raw)>8192:raise RuntimeError("Unsafe synthetic request")
            trace.append(raw)
            assert p.stdin and p.stdout
            p.stdin.write(raw)
            await asyncio.wait_for(p.stdin.drain(),20)
            if "id" not in message:return {}
            line=await asyncio.wait_for(p.stdout.readline(),25)
            if not line or len(line)>MAX_RESPONSE:
                raise RuntimeError("No bounded, complete MCP response")
            response=json.loads(line)
            if response.get("jsonrpc")!="2.0" or response.get("id")!=message["id"]:
                raise RuntimeError("Protocol response ID mismatch")
            trace.append(line)
            return response
        try:
            a=await rpc({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
                "protocolVersion":"2025-11-25","capabilities":{},
                "clientInfo":{"name":"risu-p6b7-synthetic","version":"1"}}})
            if "result" not in a:raise RuntimeError("Upstream MCP initialize failure")
            negotiated=a["result"].get("protocolVersion")
            await rpc({"jsonrpc":"2.0","method":"notifications/initialized"})
            b=await rpc({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})
            if "result" not in b:raise RuntimeError("Upstream MCP tools/list failure")
            matching=[v for v in b["result"].get("tools",[]) if v.get("name")==spec["tool"]]
            if len(matching)!=1:raise RuntimeError("Frozen tool not advertised")
            catalog=matching[0]
            inputs=[("primary",dict(spec.get("args",{})))]
            if family=="FS5184":
                inputs=[("primary",{"path":str(text),"head":0}),
                        ("normal_two",{"path":str(text),"head":2})]
            outcomes={}
            for i,(label,arguments) in enumerate(inputs,10):
                response=await rpc({"jsonrpc":"2.0","id":i,"method":"tools/call",
                                    "params":{"name":spec["tool"],"arguments":arguments}})
                obj=response.get("result") if isinstance(response.get("result"),dict) else {}
                outcome={"jsonrpc_error":"error" in response,
                         "is_error":obj.get("isError",False),
                         "structured_present":"structuredContent" in obj,
                         "structured":obj.get("structuredContent"),
                         "text":obj.get("content",[]) if isinstance(obj.get("content"),list) else []}
                outcomes[label]=outcome
            raw=b"".join(trace)
            if len(raw)>3_000_000:raise RuntimeError("Bounded synthetic trace too large")
            result_dir.mkdir(parents=True,exist_ok=False)
            (result_dir/"original_stdio.jsonl").write_bytes(raw)
            evidence={
                "schema":"p6b7-upstream-actual-stdio-v1",
                "family":family,"version":version,"repo":spec["repo"],
                "commit":spec[version],"tool":spec["tool"],
                "protocol_requested":"2025-11-25",
                "protocol_negotiated":negotiated,
                "catalog_has_output_schema":"outputSchema" in catalog,
                "output_schema":catalog.get("outputSchema"),
                "trace_sha256":hashlib.sha256(raw).hexdigest(),
                "message_count":len(trace),
                "outcomes":outcomes,
                "source":"PINNED_PUBLIC_UPSTREAM_SOURCE_EXECUTED_WITH_SYNTHETIC_INPUT",
                "production_data_used":False,"external_mcp_endpoint_called":False}
            (result_dir/"origin.json").write_text(json.dumps(evidence,sort_keys=True,indent=2)+"\n")
            safe_summary={k:{"jsonrpc_error":v["jsonrpc_error"],"is_error":v["is_error"],
                    "structured_present":v["structured_present"]} for k,v in outcomes.items()}
            print("P6B7_REAL_UPSTREAM_STDIO",family,version,len(trace),negotiated,
                  safe_summary,flush=True)
            return evidence
        finally:
            if p.returncode is None:
                p.terminate()
                try:await asyncio.wait_for(p.wait(),8)
                except asyncio.TimeoutError:p.kill();await p.wait()

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--repo",type=Path,required=True)
    p.add_argument("--family",choices=tuple(CASES),required=True)
    p.add_argument("--version",choices=("old","fixed"),required=True)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    asyncio.run(capture(a.repo,a.family,a.version,a.out))
