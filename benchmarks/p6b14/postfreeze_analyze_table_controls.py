"""Postfreeze native reproduction of B14's unanticipated analyze_table failure.

This is *not* part of the preregistered B14 first-pass score and must never be
reported as a blind first-pass RISU discovery. Executes immutable upstream
source with disposable data using a real subprocess and MCP stdio bytes.
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

REPO="mekanixms/sqlite-mcp-server"
PIN="05191e95d1ca74f7c26312ae071f5fab42c19601"

def output_text(response:dict)->str:
    result=response.get("result",{})
    if type(result) is not dict:return ""
    return "\n".join(b["text"] for b in result.get("content",[])
        if type(b) is dict and b.get("type")=="text" and type(b.get("text")) is str)

async def qualify(executable:Path,source:Path,out:Path):
    if out.exists():raise ValueError("Refusing to overwrite earlier evidence")
    src=source/"server.py"
    if not src.is_file() or not executable.is_file():
        raise ValueError("Require original pinned Python server")
    out.mkdir(parents=True)
    messages=[]
    with tempfile.TemporaryDirectory(prefix="risu-b14-followup-synthetic-") as folder:
        tmp=Path(folder).resolve()
        db=tmp/"analysis.sqlite"
        with sqlite3.connect(db) as con:
            con.executescript("""
            CREATE TABLE numeric_records (id INTEGER PRIMARY KEY, label TEXT);
            INSERT INTO numeric_records VALUES (1,'ALPHA'), (2,'BETA');
            CREATE TABLE text_only (name TEXT NOT NULL, label TEXT NOT NULL);
            INSERT INTO text_only VALUES ('FIRST','ALPHA'), ('SECOND','BETA');
            CREATE TABLE real_only (score REAL NOT NULL);
            INSERT INTO real_only VALUES (1.25), (2.5);
            """)
        env={"PATH":os.environ.get("PATH",""),"HOME":str(tmp),
            "LANG":"C.UTF-8","LC_ALL":"C.UTF-8","DB_PATH":str(db),
            "PYTHONDONTWRITEBYTECODE":"1","NO_COLOR":"1","CI":"true"}
        proc=await asyncio.create_subprocess_exec(str(executable),str(src.resolve()),
            cwd=str(tmp),env=env,stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,
            limit=524290)
        async def transact(doc):
            assert proc.stdin and proc.stdout
            raw=(json.dumps(doc,separators=(",",":"),ensure_ascii=False)+"\n").encode()
            proc.stdin.write(raw)
            await asyncio.wait_for(proc.stdin.drain(),15)
            messages.append(raw)
            if "id" not in doc:return None
            for _ in range(20):
                raw=await asyncio.wait_for(proc.stdout.readline(),35)
                if not raw or not raw.endswith(b"\n") or len(raw)>524288:
                    raise RuntimeError("Native stdio unavailable for expected response")
                messages.append(raw)
                data=json.loads(raw)
                if data.get("id")==doc["id"]:return data
                if "id" not in data:continue
                raise RuntimeError("Unexpected server-originated request")
            raise RuntimeError("Too many notifications")
        records=[]
        try:
            reply=await transact({"jsonrpc":"2.0","id":1,"method":"initialize",
                  "params":{"protocolVersion":"2025-11-25","capabilities":{},
                            "clientInfo":{"name":"risu-b14-postfreeze-independent","version":"1"}}})
            if type(reply.get("result")) is not dict:raise RuntimeError("Invalid init")
            proto=reply["result"].get("protocolVersion")
            await transact({"jsonrpc":"2.0","method":"notifications/initialized"})
            catalog=await transact({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})
            if "analyze_table" not in [x.get("name") for x in catalog.get("result",{}).get("tools",[])]:
                raise RuntimeError("Expected original upstream tool missing")
            planned=[
                ("control_text_only","text_only","basic"),
                ("candidate_integer","numeric_records","basic"),
                ("control_real_only","real_only","basic"),
                ("candidate_integer_repeat","numeric_records","basic"),
                ("control_text_only_repeat","text_only","basic"),
            ]
            for n,(label,table,mode) in enumerate(planned,20):
                response=await transact({"jsonrpc":"2.0","id":n,"method":"tools/call",
                    "params":{"name":"analyze_table","arguments":{"table":table,"analysis_type":mode}}})
                text=output_text(response)
                result=response.get("result",{})
                try:
                    parsed=json.loads(text)
                    valid_stats=(type(parsed) is dict and
                                 parsed.get("row_count")==2 and
                                 parsed.get("column_count") in (1,2))
                except (ValueError,TypeError):
                    valid_stats=False
                records.append({"case":label,"fixture_kind":table,"request_id":n,
                    "mcp_is_error":result.get("isError") if type(result) is dict else None,
                    "text":text,"statistics_json_valid":valid_stats,
                    "json_rpc_error":response.get("error")})
            with sqlite3.connect(db) as con:
                assert con.execute("SELECT COUNT(*) FROM numeric_records").fetchone()[0]==2
                assert con.execute("SELECT COUNT(*) FROM text_only").fetchone()[0]==2
                assert con.execute("SELECT COUNT(*) FROM real_only").fetchone()[0]==2
            done={
                "schema":"risu-b14-postfreeze-native-analysis-controls-v1",
                "classification":"POSTFREEZE_REPRODUCTION_NOT_FIRSTPASS",
                "source_repo":REPO,"source_commit":PIN,
                "source_entrypoint_sha256":hashlib.sha256(src.read_bytes()).hexdigest(),
                "negotiated_protocol":proto,
                "native_original_stdio":True,
                "independent_fixture_db":True,
                "cases":records}
            checks={
                "numeric_integer_failure_repeated": all(
                    "not JSON serializable" in r["text"] for r in records if r["case"].startswith("candidate_")),
                "numeric_integer_failure_reported_as_success": all(
                    r["mcp_is_error"] is False for r in records if r["case"].startswith("candidate_")),
                "text_only_normal_controls": all(
                    r["statistics_json_valid"] for r in records if r["case"].startswith("control_text")),
                "real_only_normal_control": all(
                    r["statistics_json_valid"] for r in records if r["case"]=="control_real_only"),
            }
            done["checks"]=checks
            done["runtime_confirmed"]=all(checks.values())
            done["novel_upstream_issue_claimed"]=False
            original=b"".join(messages)
            done["original_stdio_sha256"]=hashlib.sha256(original).hexdigest()
            (out/"original_stdio.jsonl").write_bytes(original)
            (out/"analysis_controls.json").write_text(json.dumps(done,indent=2,ensure_ascii=False,sort_keys=True)+"\n")
            print("B14_POSTFREEZE_NATIVE_ANALYSIS",json.dumps({
                "confirmed_controls":checks,"all_met":done["runtime_confirmed"],
                "sha":done["original_stdio_sha256"]},sort_keys=True))
        finally:
            if proc.returncode is None:
                proc.terminate()
                try:await asyncio.wait_for(proc.wait(),7)
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--executable",required=True,type=Path)
    p.add_argument("--source",required=True,type=Path)
    p.add_argument("--out",required=True,type=Path)
    a=p.parse_args()
    asyncio.run(qualify(a.executable.resolve(),a.source.resolve(),a.out))
if __name__=="__main__":
    main()
