"""Native MCP stdio B14: original stdout + independent logical SQLite state per call.

Only pinned publicly available upstream code and synthetic disposable SQLite inputs.
Source code is executed only in an isolated trusted branch CI, not by RISU's analyzer.
"""
from __future__ import annotations
import argparse
import asyncio
import hashlib
import json
import os
import sqlite3
import tempfile
from pathlib import Path

SCHEMA = "risu-p6b14-preregistered-native-effect-20261112-v1"
FIXTURES = [
    (1, "RISU_B14_ONE"), (2, "RISU_B14_TWO"), (3, "RISU_B14_Ω"),
    (4, "RISU_B14_FOUR"), (5, "RISU_B14_FIVE")
]
MAX_LINE = 524288
MAX_TOTAL = 4194304

def select(manifest: Path, case: str) -> dict:
    m = json.loads(manifest.read_text(encoding="utf-8"))
    assert m["schema"] == SCHEMA
    assert [(v["id"],v["sha"]) for v in m["cohort"]] == [
        ("SP","a6a6f196b315b11e17929aeeb274821f5a0e6ed0"),
        ("ME","05191e95d1ca74f7c26312ae071f5fab42c19601")]
    assert m["denominator"]["predeclared_calls"] == 12
    return next(v for v in m["cohort"] if v["id"] == case)

def snapshot(db: Path) -> list[list]:
    with sqlite3.connect(db,timeout=2) as conn:
        return [list(row) for row in conn.execute("SELECT id,label FROM records ORDER BY id")]

async def run(case: str, executable: Path, source: Path,
              manifest: Path, output: Path) -> None:
    entry = select(manifest, case)
    if output.exists() or not executable.is_file() or not source.is_dir():
        raise ValueError("No overwriting evidence; native source and executable required")
    output.mkdir(parents=True)
    original = []
    calls = []
    origin = {"schema":"risu-p6b14-native-source-stdio-v1",
              "case":case,"repo":entry["repo"],"source_commit":entry["sha"],
              "original_source_executed":False,"status":"UNVERIFIED",
              "stdout_sha256":None,"selected_calls":len(entry["probe"])}
    proc = None
    with tempfile.TemporaryDirectory(prefix="risu-b14-disposable-") as d:
        tmp = Path(d).resolve()
        db = tmp / "b14.sqlite"
        with sqlite3.connect(db) as c:
            c.execute("CREATE TABLE records(id INTEGER PRIMARY KEY, label TEXT NOT NULL)")
            c.executemany("INSERT INTO records VALUES (?,?)", FIXTURES)
        initial = snapshot(db)
        origin["initial_rows"] = initial
        env = {"PATH":os.environ.get("PATH",""),"HOME":str(tmp),
               "LANG":"C.UTF-8","LC_ALL":"C.UTF-8","CI":"true","NO_COLOR":"1",
               "PYTHONDONTWRITEBYTECODE":"1","DB_PATH":str(db),
               "SQLITE_DEFAULT_PATH":str(tmp)}
        if case == "SP":
            entrypoint = source/"dist"/"index.js"
            if not entrypoint.is_file(): raise ValueError("Native SP build missing")
            argv = [str(entrypoint.resolve())]
        elif case == "ME":
            entrypoint = source/"server.py"
            if not entrypoint.is_file(): raise ValueError("Native ME script missing")
            argv = [str(entrypoint.resolve())]
        else: raise ValueError("Unknown case")
        origin["entrypoint_sha256"] = hashlib.sha256(entrypoint.read_bytes()).hexdigest()
        async def transact(message: dict) -> dict|None:
            assert proc and proc.stdin and proc.stdout
            raw=(json.dumps(message,ensure_ascii=False,separators=(",",":"))+"\n").encode()
            proc.stdin.write(raw)
            await asyncio.wait_for(proc.stdin.drain(),15)
            original.append(raw)
            if "id" not in message: return None
            for _ in range(20):
                reply=await asyncio.wait_for(proc.stdout.readline(),40)
                if not reply or len(reply)>MAX_LINE or not reply.endswith(b"\n"):
                    raise RuntimeError("Original MCP stdout missing/invalid/oversized")
                original.append(reply)
                item=json.loads(reply)
                if type(item) is not dict or item.get("jsonrpc")!="2.0":
                    raise RuntimeError("Original stdout includes non-JSON-RPC line")
                if item.get("id")==message["id"]: return item
                if "id" not in item: continue
                raise RuntimeError("Unplanned original server-to-client request")
            raise RuntimeError("Too many unmatched notifications")
        try:
            proc=await asyncio.create_subprocess_exec(str(executable),*argv,
                cwd=str(tmp),env=env,stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,
                limit=MAX_LINE+2)
            origin["original_source_executed"]=True
            res=await transact({"jsonrpc":"2.0","id":1,"method":"initialize",
                  "params":{"protocolVersion":"2025-11-25","capabilities":{},
                  "clientInfo":{"name":"risu-b14-synthetic","version":"1"}}})
            if type(res.get("result")) is not dict:
                raise RuntimeError("Native initialize failed: "+str(res.get("error"))[:250])
            origin["protocol"]=res["result"].get("protocolVersion")
            await transact({"jsonrpc":"2.0","method":"notifications/initialized"})
            catalog=[]
            cursor=None
            for index in range(8):
                params={"cursor":cursor} if cursor else {}
                answer=await transact({"jsonrpc":"2.0","id":2+index,
                    "method":"tools/list","params":params})
                if type(answer.get("result")) is not dict or type(answer["result"].get("tools")) is not list:
                    raise RuntimeError("Native tools/list returned unusable catalog")
                catalog+=answer["result"]["tools"]
                cursor=answer["result"].get("nextCursor")
                if not cursor: break
                if type(cursor) is not str or len(cursor)>256:
                    raise RuntimeError("Invalid native nextCursor")
            else: raise RuntimeError("Native tool catalog exceeds eight pages")
            origin["advertised_tools"] = [x.get("name") for x in catalog if type(x) is dict]
            available=set(origin["advertised_tools"])
            for index,probe in enumerate(entry["probe"],20):
                values=json.loads(json.dumps(probe["args"],ensure_ascii=False).replace("${DB}",str(db)))
                if probe["name"] not in available:
                    calls.append({"case":probe["id"],"tool":probe["name"],"arguments":values,
                                  "status":"UNVERIFIED_TOOL_NOT_ADVERTISED","before":snapshot(db),"after":snapshot(db)})
                    continue
                before=snapshot(db)
                response=await transact({"jsonrpc":"2.0","id":index,"method":"tools/call",
                      "params":{"name":probe["name"],"arguments":values}})
                after=snapshot(db)
                calls.append({"case":probe["id"],"tool":probe["name"],"arguments":values,
                              "response":response,"call_id":index,"before":before,"after":after})
            origin["final_rows"] = snapshot(db)
            origin["status"]="CAPTURED_NATIVE_STDIO"
        except Exception as error:
            origin["status"]="UNVERIFIED_CAPTURE_ERROR"
            origin["failure_kind"]=type(error).__name__
            origin["failure_note"]=str(error)[:350]
        finally:
            if proc and proc.returncode is None:
                proc.terminate()
                try: await asyncio.wait_for(proc.wait(),8)
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
            if proc and proc.stderr:
                # Bounded diagnostic from synthetic no-secret isolated process.
                # stdout is independently preserved byte-for-byte above.
                try:
                    diagnostic=(await asyncio.wait_for(proc.stderr.read(4096),3)).decode("utf-8","replace")
                    origin["stderr_tail_for_setup_diagnosis"]=diagnostic[-1600:]
                except (asyncio.TimeoutError, OSError):
                    origin["stderr_read_status"]="UNAVAILABLE"
    bytes_ = b"".join(original)
    origin["stdout_sha256"]=hashlib.sha256(bytes_).hexdigest()
    origin["original_message_lines"]=len(original)
    origin["calls_attempted"]=len(calls)
    (output/"original_stdio.jsonl").write_bytes(bytes_)
    (output/"unmodified_calls.json").write_text(json.dumps(calls,indent=2,ensure_ascii=False)+"\n")
    (output/"origin.json").write_text(json.dumps(origin,indent=2,ensure_ascii=False,sort_keys=True)+"\n")
    print("B14_SOURCE_FIRST_NATIVE",json.dumps({x:origin.get(x) for x in
          ("case","status","source_commit","stdout_sha256","calls_attempted","failure_kind")},sort_keys=True))

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--case",required=True,choices=["SP","ME"])
    ap.add_argument("--executable",required=True,type=Path)
    ap.add_argument("--source",required=True,type=Path)
    ap.add_argument("--manifest",type=Path,default=Path("benchmarks/p6b14/prelocked_native_effect_cohort.json"))
    ap.add_argument("--out",type=Path,required=True)
    a=ap.parse_args()
    asyncio.run(run(a.case,a.executable.resolve(),a.source.resolve(),a.manifest,a.out))
if __name__=="__main__":
    main()
