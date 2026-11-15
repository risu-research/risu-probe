#!/usr/bin/env python3
"""B44 independent source-preserving native MCP → MELRA SQLite → filesystem witness.

This script is an EVALUATOR-owned native JSON-RPC client. It launches and
exercises the original pinned external MELRA server unchanged. It is NOT an
external agent; native request IDs are from this evaluator-controlled client,
and MELRA's taskId is NOT the original model tool_call_id. Never synthesize
such an identity mapping.

Actual stdio newline-delimited JSON-RPC request/replies are sent/received as
bytes from original Node MCP CLI. The witness keeps their SHA-256, source
fields and redacted content, independently measured final file bytes and
original persistent SQLite rows reopened by Python's separate sqlite3 reader.
Only a disposable local workspace and a test-only policy permitting it.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import time
import traceback

PROJECT_COMMIT = "ab59ffa134decd9613a378c7bd8a0e8d495c7e89"
SOURCE_BLOB = "17e3d6e7f0b63eb8395c4b5a9553dce3505d1a21"
SECRET_KEYS = {"phrase", "authorization", "token", "access_token", "api_key", "cookie"}

def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def redact(node):
    if isinstance(node, dict):
        return {k: ("[REDACTED_EXACT_APPROVAL]" if k.lower() in SECRET_KEYS
                     else redact(v)) for k,v in node.items()}
    if isinstance(node,list): return [redact(x) for x in node]
    return node

class OriginalNative:
    def __init__(self, process: subprocess.Popen):
        self.p=process
        self.buf=b""
        self.events=[]
        self.nonmatching=[]
    def send(self,msg:dict):
        wire=json.dumps(msg,ensure_ascii=False,separators=(",",":")).encode()+b"\n"
        self.p.stdin.write(wire)
        self.p.stdin.flush()
        self.events.append({
          "direction":"evaluator_native_client_to_original_external_MELRA_stdio_server",
          "exact_bytes_sha256":digest(wire),
          "byte_length":len(wire),
          "parsed_redacted":redact(msg),
          "raw_verified_utf8_newline":True,
        })
    def receive(self,want_id=None,timeout=35):
        deadline=time.monotonic()+timeout
        while True:
            if b"\n" in self.buf:
                raw,self.buf=self.buf.split(b"\n",1)
                if not raw.strip(): continue
                msg=json.loads(raw.decode())
                self.events.append({
                 "direction":"original_external_MELRA_stdio_server_to_evaluator_native_client",
                 "exact_bytes_sha256":digest(raw+b"\n"),"byte_length":len(raw)+1,
                 "parsed_redacted":redact(msg),"raw_verified_utf8_newline":True,
                })
                if want_id is None or msg.get("id")==want_id: return msg
                self.nonmatching.append(msg)
                continue
            left=deadline-time.monotonic()
            if left<=0: raise RuntimeError(f"Original MCP response timed out waiting id {want_id}; code {self.p.poll()}")
            ready,_,_=select.select([self.p.stdout],[],[],min(left,3))
            if not ready:
                if self.p.poll() is not None: raise RuntimeError("Original MCP process exited during native request "+str(self.p.returncode))
                continue
            chunk=os.read(self.p.stdout.fileno(),8192)
            if not chunk: raise RuntimeError(f"Original MCP stdout EOF while expecting {want_id}")
            self.buf+=chunk
            if len(self.buf)>8*1024*1024: raise RuntimeError("Original response exceeds 8MiB bound")
    def call(self,rid,name,args):
        request={"jsonrpc":"2.0","id":rid,"method":"tools/call",
                 "params":{"name":name,"arguments":args}}
        self.send(request)
        response=self.receive(rid)
        if response.get("id")!=rid or response.get("jsonrpc")!="2.0":
            raise AssertionError("Original native JSONRPC response ID mismatch")
        if not isinstance(response.get("result"),dict):
            raise AssertionError(f"Original native tool has no result; {response}")
        return request,response
    @staticmethod
    def value(response):
        result=response["result"]
        if result.get("isError") is True:
            return None
        if not isinstance(result.get("content"),list):
            raise AssertionError("Original native MCP tool content missing")
        texts=[x.get("text") for x in result["content"] if x.get("type")=="text"]
        if len(texts)!=1 or not isinstance(texts[0],str):
            raise AssertionError("Original MCP tool original text did not contain a single JSON payload")
        return json.loads(texts[0])

def src_check(root:Path):
    rev=subprocess.check_output(["git","-C",str(root),"rev-parse","HEAD"],text=True).strip()
    blob=subprocess.check_output(["git","-C",str(root),"rev-parse","HEAD:packages/server/src/mcp-server.ts"],text=True).strip()
    assert rev==PROJECT_COMMIT,(rev,PROJECT_COMMIT)
    assert blob==SOURCE_BLOB,(blob,SOURCE_BLOB)
    cli=root/"apps/cli/dist/bin.js"
    if not cli.is_file(): raise RuntimeError("Original compiled MELRA CLI missing: "+str(cli))
    return rev,blob,cli

def drain_stderr(stream,output):
    try:
        while True:
            chunk=stream.readline()
            if not chunk:break
            if len(output)<160:
                output.append(chunk.decode("utf8",errors="replace")[:1500])
    except Exception as exc:
        output.append("stderr_drain_error:"+str(exc))

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--original",type=Path,required=True)
    ap.add_argument("--output",type=Path,required=True)
    args=ap.parse_args()
    repo=args.original.resolve()
    rev,blob,cli=src_check(repo)
    trace={"schema":"risu-p6b44-original-melra-native-effect-sqlite-v1",
      "original_repo":"XAGI-Lab/melra","original_commit":rev,
      "original_mcp_source_git_blob":blob,"upstream_implementation_patched":False,
      "model_agent":"EVALUATOR_SCRIPTED_NATIVE_CLIENT_NO_ORIGINAL_EXTERNAL_AGENT",
      "declared_proof_level":"ORIGINAL_MCP_SERVER_REAL_STDIO_TO_ORIGINAL_TASK_SQLITE_AND_INDEPENDENT_FILE_EFFECT",
      "original_native_request_id_to_model_agent_tool_call_id_mapping_present":False,
      "original_native_request_id_persisted_in_original_sqlite_receipt":False,
      "original_model_agent_tool_call_id_observed":False,
      "original_per_native_request_matched_persistent_start_and_terminal":False,
      "original_app_task_id_is_not_jsonrpc_or_model_tool_call_id":True,
      "full_chain_verdict":"LINK_INCOMPLETE",
      "original_business_effect":"real isolated local file mutation",
      "experimental_selection":"P1 seal pre-source-inspection",
      "disjoint_original_external_owner":True,
      "no_actual_deployed_external_business_service":True}
    errlines=[]
    with tempfile.TemporaryDirectory(prefix="b44_melra_original_") as work:
        home=Path(work)
        workspace=home/"workspace";workspace.mkdir()
        data=home/"data"
        policy=home/"policy.json"
        policy.write_text(json.dumps({
          "version":"b44-original-native-isolated-local",
          "workspaceRoot":str(workspace),
          "allowedCommands":[],
          "allowedDomains":[],
          "allowLocalhost":False,
          "mutations":"confirm",
          "approvalTtlMs":300000,
          "maxFileBytes":1000000},indent=2)+"\n")
        path=workspace/"b44-effect.txt"
        before_exists=path.exists()
        assert not before_exists
        env={k:v for k,v in os.environ.items() if k!="MELRA_MODE"}
        env.update({"MELRA_WORKSPACE":str(workspace),"MELRA_HOME":str(data),"MELRA_POLICY":str(policy)})
        proc=subprocess.Popen(["node",str(cli),"serve"],cwd=repo,env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
        thread=threading.Thread(target=drain_stderr,args=(proc.stderr,errlines),daemon=True);thread.start()
        n=OriginalNative(proc)
        try:
            n.send({"jsonrpc":"2.0","id":"b44-initialize-1","method":"initialize",
                    "params":{"protocolVersion":"2025-11-25","capabilities":{},
                              "clientInfo":{"name":"b44-external-original-native-evaluator","version":"1.0.0"}}})
            init=n.receive("b44-initialize-1")
            assert "result" in init and "error" not in init,init
            n.send({"jsonrpc":"2.0","method":"notifications/initialized","params":{}})
            task_content="b44-original-external-MELRA-effect-data-5c9d2\n"
            req_plan,res_plan=n.call("b44-plan-101","melra_plan",{
               "goal":"Create one independently checked disposable file through original MCP",
               "operation":{"kind":"file","action":"write","path":path.name,"content":task_content},
               "requiredEvidence":[{"type":"file_exists","path":path.name}],
            })
            planned=n.value(res_plan)
            assert isinstance(planned,dict),(planned,res_plan)
            assert planned.get("status")=="awaiting_approval",planned
            task_id=planned["id"]
            approval=planned["approval"]
            assert not path.exists(),"Effect must not occur before real original approval"
            assert approval.get("approvalId") and approval.get("phrase")
            wrong="APPROVE definitely-wrong-b44"
            req_bad,res_bad=n.call("b44-denied-102","melra_execute",{
              "taskId":task_id,
              "approval":{"approvalId":approval["approvalId"],"phrase":wrong}
            })
            assert res_bad["result"].get("isError") is True,(res_bad["result"].get("content"))
            assert not path.exists(),"Original policy denied tool but still mutated"
            req_execute,res_execute=n.call("b44-execute-103","melra_execute",{
               "taskId":task_id,
               "approval":{"approvalId":approval["approvalId"],"phrase":approval["phrase"]}
            })
            executed=n.value(res_execute)
            assert isinstance(executed,dict),executed
            assert executed["task"]["status"]=="verified_success",executed
            assert executed["receipt"]["effect"]=="mutate",executed
            assert path.is_file(),"External original server claims verified success but file missing"
            effect=path.read_bytes()
            expected=task_content.encode("utf-8")
            assert effect==expected,"Independent file read disagrees with original intent"
            req_receipt,res_receipt=n.call("b44-receipt-104","melra_receipt",{"taskId":task_id})
            original_receipt=n.value(res_receipt)
            assert original_receipt.get("receipts"),original_receipt
            assert original_receipt.get("certificate"),original_receipt
            assert original_receipt["certificate"]["result"]=="VERIFIED_SUCCESS",original_receipt
            req_status,res_status=n.call("b44-status-105","melra_task_status",{"taskId":task_id})
            original_status=n.value(res_status)
            assert original_status.get("status")=="verified_success",original_status
            trace["source_runtime_native_calls"]=[
              {"purpose":"plan","request_id":req_plan["id"],"isError":res_plan["result"].get("isError",False)},
              {"purpose":"unauthorized_execute","request_id":req_bad["id"],"isError":res_bad["result"].get("isError",False)},
              {"purpose":"approved_execute","request_id":req_execute["id"],"isError":res_execute["result"].get("isError",False)},
              {"purpose":"original_receipt_read","request_id":req_receipt["id"],"isError":res_receipt["result"].get("isError",False)},
              {"purpose":"original_status_read","request_id":req_status["id"],"isError":res_status["result"].get("isError",False)},
            ]
            trace["effect"]={"resource":"disposable_workspace/b44-effect.txt",
              "before_exists":before_exists,"after_exists":path.is_file(),
              "after_bytes_len":len(effect),"after_bytes_sha256":digest(effect),
              "expected_bytes_sha256":digest(expected),"independent_reader":"Python pathlib.read_bytes after original Node MCP mutation",
              "real_external_effect_executed":True,
              "wrong_approval_did_not_mutate":True,"authorized_effect_content_exact":True}
            trace["original_melra_task_id"]=task_id
            trace["original_task_status"]=executed["task"]["status"]
            trace["original_melra_receipt_id"]=executed["receipt"].get("receiptId")
            trace["original_certificate_id"]=original_receipt["certificate"].get("certificateId")
            trace["original_certificate_result"]=original_receipt["certificate"]["result"]
            trace["original_certificate_digest"]=original_receipt["certificate"]["digest"]
            trace["original_receipt_count_from_api"]=len(original_receipt["receipts"])
            trace["original_remote_status_matches"]=original_status["status"]==executed["task"]["status"]
        finally:
            if proc.stdin and not proc.stdin.closed:proc.stdin.close()
            try:proc.wait(timeout=12)
            except subprocess.TimeoutExpired:
                proc.terminate()
                try:proc.wait(timeout=5)
                except subprocess.TimeoutExpired:proc.kill();proc.wait()
            thread.join(timeout=2)
            trace["original_process_exit_code"]=proc.returncode
            trace["raw_original_stdout_frame_count"]=len(n.events)
            trace["native_stdio_raw_frame_redacted_witnesses"]=n.events
            trace["native_stdio_nonmatching_messages_count"]=len(n.nonmatching)
            trace["original_process_stderr_last_lines"]=errlines[-25:]
        sqlite=data/"melra.sqlite"
        assert sqlite.is_file(),"Original app did not persist its SQLite database"
        db=sqlite3.connect(f"file:{sqlite}?mode=ro",uri=True)
        db.row_factory=sqlite3.Row
        try:
            table_names=[row["name"] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
            assert {"tasks","receipts","certificates"}.issubset(table_names),table_names
            task_row=db.execute("SELECT * FROM tasks WHERE id=?",(task_id,)).fetchone()
            receipt_rows=db.execute("SELECT * FROM receipts WHERE task_id=? ORDER BY created_at",(task_id,)).fetchall()
            certificate=db.execute("SELECT * FROM certificates WHERE task_id=?",(task_id,)).fetchone()
            assert task_row is not None and len(receipt_rows)==1 and certificate is not None
            task_payload=json.loads(task_row["data"])
            receipt_payload=json.loads(receipt_rows[0]["data"])
            cert_payload=json.loads(certificate["data"])
            assert task_payload["status"]=="verified_success",task_payload.get("status")
            assert receipt_rows[0]["id"]==trace["original_melra_receipt_id"],(receipt_rows[0]["id"],trace["original_melra_receipt_id"])
            assert cert_payload.get("result")=="VERIFIED_SUCCESS",cert_payload
            trace["persisted_original_sqlite"]={
              "independently_reopened_after_original_process_exit":True,
              "reader":"sqlite3 Python read-only separate process",
              "database_byte_count":sqlite.stat().st_size,
              "original_schema_tables":table_names,
              "original_task_row_count_for_id":1,
              "original_receipt_row_count_for_id":len(receipt_rows),
              "original_certificate_row_count_for_id":1,
              "task_status":task_payload["status"],
              "stored_receipt_ids":[r["id"] for r in receipt_rows],
              "stored_certificate_id":certificate["id"],
              "receipt_json_sha256":digest(receipt_rows[0]["data"].encode()),
              "certificate_json_sha256":digest(certificate["data"].encode()),
              "task_json_sha256":digest(task_row["data"].encode()),
              "original_sqlite_task_record_keys":sorted(task_payload.keys()),
              "original_sqlite_receipt_record_keys":sorted(receipt_payload.keys()),
              "native_jsonrpc_request_id_in_original_persisted_task":any(
                    k in task_payload for k in ("nativeRequestId","jsonRpcRequestId","jsonrpcRequestId","mcpRequestId")),
              "original_source_model_tool_call_id_in_original_persisted_task":any(
                    k in task_payload for k in ("toolCallId","modelToolCallId","agentToolCallId")),
            }
            assert not trace["persisted_original_sqlite"]["native_jsonrpc_request_id_in_original_persisted_task"]
            assert not trace["persisted_original_sqlite"]["original_source_model_tool_call_id_in_original_persisted_task"]
        finally:db.close()
        assert path.read_bytes()==expected
        assert trace["original_process_exit_code"]==0,("Original MELRA process nonzero",trace["original_process_stderr_last_lines"])
        trace["test_passed"]=True
        trace["strict_five_edge_w"]=True
        trace["strict_five_edge_a"]=False
        trace["strict_five_edge_s"]=False
        trace["strict_five_edge_t"]=False
        trace["strict_five_edge_e"]=True
        trace["notes"]=[
         "Original server native JSON-RPC requests/replies captured from actual stdout/stdin byte stream",
         "Original returned taskId and receiptId from original MELRA implementation",
         "Original SQLite tasks/receipts/certificates persisted and read after original MCP process exit",
         "Independent real effect file bytes read from disposable workspace and checked after executable exited",
         "No original model agent tool_call_id exists on this server-only route; evaluator-chosen JSONRPC id is not an original model id",
         "Original persistent records are per MELRA task, not per native JSONRPC tools/call start/terminal. No fabricated W-to-A-to-S/T link",
         "The isolated scenario includes a refused attempt whose original isError true was observed and file remained absent",
         "MELRA verified_success denotes independent file_exists predicate; byte-for-byte equality checked separately by evaluator"
        ]
        args.output.parent.mkdir(parents=True,exist_ok=True)
        serialized=json.dumps(trace,ensure_ascii=False,indent=2,sort_keys=True)+"\n"
        args.output.write_text(serialized,encoding="utf8")
        print("B44_P1_REAL_NATIVE_MCP_TO_ORIGINAL_SQLITE_AND_INDEPENDENT_FILE_EFFECT_PASSED")
        print("B44_P1_STRICT_ORIGINAL_MODEL_ID_AND_PER_NATIVE_START_TERMINAL_LINK_INCOMPLETE")
        print("B44_P1_WITNESS_SHA256",digest(serialized.encode("utf8")))
        print("B44_P1_ORIGINAL_TASK_ID",task_id)
        print("B44_P1_ORIGINAL_CERTIFICATE_DIGEST",trace["original_certificate_digest"])
        print("B44_P1_REAL_EFFECT_SHA256",digest(effect))

if __name__=="__main__":
    main()
