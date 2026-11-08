"""Read raw authenticated-to-local-tee STDIO byte frames without inventing messages.

Byte identity is verified by per-line SHA256 and JSON value equivalence.
This is evidence from a local synthetic SDK peer, NOT external source conformance.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
from pathlib import Path

from risu_display_fidelity import verify_display_fidelity
from risu_mcp_trace import verify_trace

RAW_SCHEMA = "risu-b11-raw-stdio-frame-v1"

def convert(raw:Path,trace:Path):
    frames=[]
    messages=[]
    seen=set()
    total=0
    for index,line in enumerate(raw.read_text().splitlines(),1):
        if index>1024 or len(line)>800000:
            raise ValueError("Raw transport evidence over budget")
        row=json.loads(line)
        if row.get("schema")!=RAW_SCHEMA or row.get("sequence")!=index:
            raise ValueError("Raw transport frame schema/sequence mismatched")
        direction=row["direction"]
        if direction not in ("client_to_server","server_to_client"):
            raise ValueError("Unknown frame origin")
        b=base64.b64decode(row["raw_base64"],validate=True)
        total+=len(b)
        if (len(b)>524288 or total>4194304 or not b.endswith(b"\n")
           or hashlib.sha256(b).hexdigest()!=row["frame_sha256"]
           or row["frame_length"]!=len(b)):
            raise ValueError("Actual original bytes mismatched expected frame digest/budget")
        data=json.loads(b.decode("utf-8"))
        if type(data) is not dict or data.get("jsonrpc")!="2.0":
            raise ValueError("Actual stdio bytes did not carry JSON-RPC 2.0")
        frames.append({"sequence":index,"direction":direction,"sha256":row["frame_sha256"]})
        messages.append(data)
    if not messages or not any(x.get("method")=="initialize" for x in messages):
        raise ValueError("No actual initialization request observed")
    if not any(x.get("method")=="notifications/initialized" for x in messages):
        raise ValueError("No original initialized notification")
    req={}
    responses={}
    calls=[]
    for i,(frame,msg) in enumerate(zip(frames,messages)):
        mid=msg.get("id")
        if msg.get("method") and mid is not None:
            if frame["direction"]!="client_to_server":raise ValueError("Unexpected request direction")
            if mid in req: raise ValueError("Overlapping/reused request ID in this test")
            req[mid]=msg
            if msg["method"]=="tools/call": calls.append(msg)
        elif mid is not None and ("result" in msg or "error" in msg):
            if frame["direction"]!="server_to_client": raise ValueError("Unexpected server response direction")
            if mid in responses:raise ValueError("Duplicate response ID")
            responses[mid]=msg
    if len(calls)!=12 or any(id_ not in responses for id_ in req):
        raise ValueError("Original SDK request/response correspondence incomplete")
    if len([v for v in req.values() if v["method"]=="tools/list"])!=1:
        raise ValueError("Actual tools/list not observed exactly once")
    # This JSONL is an exact-value transcript of originals; raw bytes are retained
    # separately and every record is verified against their unmodified decoded bytes.
    trace.write_text(''.join(json.dumps(v,ensure_ascii=False,sort_keys=True)+'\n'
                             for v in messages),encoding="utf-8")
    return {"frames":len(frames),"bytes":total,"calls":len(calls),
            "directions":sorted({x["direction"] for x in frames}),
            "raw_sha256":hashlib.sha256(raw.read_bytes()).hexdigest(),
            "normalized_trace_sha256":hashlib.sha256(trace.read_bytes()).hexdigest()}

def contract():
    names=[
        ("render_markdown","markdown-literal"),
        ("render_copy","code-copy"),
        ("render_special","json-string-special"),
        ("render_bad","markdown-literal"),
        ("render_missing","markdown-literal"),
    ]
    return {"schema":"risu-display-fidelity-contract-v1",
       "rules":[{"id":n,"tool":n,"pointer":"/value","line_prefix":"**value:** ",
                  "mode":mode,"is_error":False} for n,mode in names]}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("original_raw_capture",type=Path)
    parser.add_argument("output_directory",type=Path)
    a=parser.parse_args()
    root=a.output_directory
    root.mkdir(parents=True,exist_ok=True)
    wire=convert(a.original_raw_capture,root/"normalized_exact_value_trace.jsonl")
    declared=contract()
    (root/"explicit_fidelity_contract.json").write_text(json.dumps(declared,indent=2)+"\n")
    fidelity=verify_display_fidelity(root/"normalized_exact_value_trace.jsonl",declared)
    semantic=verify_trace(root/"normalized_exact_value_trace.jsonl")
    (root/"fidelity_result.json").write_text(json.dumps(fidelity,indent=2,sort_keys=True)+"\n")
    (root/"schema_result.json").write_text(json.dumps(semantic,indent=2,sort_keys=True)+"\n")
    if (fidelity["summary"]["applicable_assertions"]!=12
         or fidelity["summary"]["literal_checks_completed"]!=11
         or fidelity["summary"]["findings"]!=1
         or fidelity["summary"]["unverified"]!=1):
        raise RuntimeError("Real captured STDIO failed frozen B10 declared fidelity score")
    if (semantic["summary"]["findings"]):
        raise RuntimeError("Unexpected protocol/schema finding on genuine SDK wire")
    expected_find={x["tool"] for x in fidelity["findings"]}
    if expected_find!={"tool_sha256:"+hashlib.sha256(b"render_bad").hexdigest()[:16]}:
        raise RuntimeError("Injected mismatch was not isolated to the intentional bad tool")
    if not any(x["code"]=="AMBIGUOUS_OR_MISSING_LINE" for x in fidelity["unverified"]):
        raise RuntimeError("Incomplete capture did not stay unverified")
    result={
        "schema":"risu-p6b11-real-stdio-wire-score-v1",
        "origin":"ACTUAL_MCP_PYTHON_SDK_1_28_0_CLIENT_SERVER_STDIO_BYTES_WITH_TEE",
        "sdk_wire_real":True,
        "test_server":"SYNTHETIC_LOCAL_CONTROLLED_NOT_EXTERNAL_UPSTREAM_BUG",
        "capture_is_digital_attestation":False,
        "original_capture_sha256":wire["raw_sha256"],
        "normalized_trace_sha256":wire["normalized_trace_sha256"],
        "raw_frame_count":wire["frames"],
        "captured_tool_calls":wire["calls"],
        "normal_declared_checks":10,
        "normal_false_positive_findings":0,
        "intentionally_injected_display_mismatches":1,
        "intentionally_injected_mismatches_detected":1,
        "intentionally_incomplete_calls":1,
        "intentionally_incomplete_unverified":1,
        "schema_findings":len(semantic["summary"]["findings"]),
        "limitations":"Authentic real stdio with official client/server SDK and byte-preserving tee, but test server/code and injected defect are locally authored. Not third-party upstream wire evidence; capture has no external trusted signature.",
    }
    (root/"wire_score.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print(json.dumps(result,indent=2,sort_keys=True))

if __name__=="__main__": main()
