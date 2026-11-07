"""An independent *different real MCP server* negative control for Draft-07.

Executes official unmodified modelcontextprotocol/servers Filesystem Server in an
isolated temporary directory with only synthetic public text. Captures literal
MCP stdio messages and checks both the SDK semantics and RISU predictions.
"""
from __future__ import annotations
import argparse, asyncio, hashlib, json, os, tempfile
from pathlib import Path

FIXED="72e11113edff5919e74de1d69b71203991fe2f05"

async def main(repo:Path,out:Path)->None:
    from jsonschema import Draft7Validator, Draft202012Validator
    server=(repo/"src/filesystem/dist/index.js").resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="risu-public-fs-") as tmp:
        allowed=Path(tmp)/"allowed"
        allowed.mkdir()
        sample=allowed/"public_sample.txt"
        sample.write_text("PUBLIC SYNTHETIC TEXT ONLY\n",encoding="utf-8")
        env={"HOME":tmp,"PATH":os.environ["PATH"],"NODE_ENV":"production","CI":"true"}
        proc=await asyncio.create_subprocess_exec("node",str(server),str(allowed),
            cwd=str(server.parent),env=env,stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.DEVNULL)
        captured=[]
        async def send(msg:dict)->dict:
            raw=(json.dumps(msg,separators=(",",":"))+"\n").encode()
            assert len(raw)<10000
            captured.append(raw)
            proc.stdin.write(raw)
            await asyncio.wait_for(proc.stdin.drain(),12)
            if "id" not in msg:return {}
            data=await asyncio.wait_for(proc.stdout.readline(),12)
            if not data or len(data)>400000:raise RuntimeError("Empty/oversize upstream MCP response")
            ans=json.loads(data)
            assert ans.get("jsonrpc")=="2.0" and ans.get("id")==msg["id"]
            captured.append(data)
            return ans
        try:
            init=await send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
                "protocolVersion":"2025-11-25","capabilities":{},
                "clientInfo":{"name":"risu-public-filesystem-control","version":"1.0"}}})
            assert init.get("result",{}).get("protocolVersion")
            await send({"jsonrpc":"2.0","method":"notifications/initialized"})
            catalog=await send({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})
            assert "result" in catalog
            tools={t["name"]:t for t in catalog["result"]["tools"]}
            names=("list_directory","read_text_file")
            assert set(names)<=set(tools)
            diag={}
            calls=[
                ("list_directory",{"path":str(allowed)}),
                ("read_text_file",{"path":str(sample)})
            ]
            for i,(name,args) in enumerate(calls,10):
                resp=await send({"jsonrpc":"2.0","id":i,"method":"tools/call",
                    "params":{"name":name,"arguments":args}})
                assert "result" in resp and not resp["result"].get("isError",False)
                assert isinstance(resp["result"].get("structuredContent"),dict)
                schema=tools[name]["outputSchema"]
                dialect=schema.get("$schema","https://json-schema.org/draft/2020-12/schema")
                cls=Draft7Validator if "draft-07" in dialect else Draft202012Validator
                cls.check_schema(schema)
                errors=list(cls(schema).iter_errors(resp["result"]["structuredContent"]))
                assert not errors,(name,[str(e) for e in errors[:2]])
                diag[name]={"schema_dialect":dialect,"independent_errors":0}
            raw=b"".join(captured)
            assert len(raw)<400000
            out.mkdir(parents=True,exist_ok=True)
            (out/"raw_stdio.jsonl").write_bytes(raw)
            meta={"schema":"risu-p6b6-filesystem-independent-normal-v1",
                "repo":"https://github.com/modelcontextprotocol/servers",
                "commit":FIXED,"server":"@modelcontextprotocol/server-filesystem",
                "synthetic_only":True,"actual_stdio":True,
                "normal_tool_calls":list(names),"independent_results":diag,
                "sha256":hashlib.sha256(raw).hexdigest()}
            (out/"origin.json").write_text(json.dumps(meta,indent=2,sort_keys=True)+"\n")
            print("P6B6_DIFFERENT_PUBLIC_SERVER_NORMAL",diag,flush=True)
        finally:
            if proc.returncode is None:
                proc.terminate()
                try:await asyncio.wait_for(proc.wait(),6)
                except asyncio.TimeoutError:proc.kill();await proc.wait()

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--repo",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    asyncio.run(main(a.repo,a.out))
