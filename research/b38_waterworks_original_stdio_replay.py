#!/usr/bin/env python3
"""B38 real third-party Waterworks original pre/post client over actual MCP stdio.

Original chat-ui/mcp_client.py source Git blobs are executed unmodified.
Only the session-ACQUISITION hook is substituted to supply an actual
MCP SDK ClientSession over a controlled subprocess stdio transport.
No third-party service, network, secrets, or untrusted code beyond the pinned
single Python module is launched. Strictly post-seal integration, NOT an
unassisted untouched program whole-stack run.
"""
from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

HERE=Path(__file__).resolve().parent
ROOT=HERE.parent
UPSTREAM=ROOT/"original"
OUT=HERE/"out"
SERVER=HERE/"b38_controlled_stdio_peer.py"
MODULE_PATH="chat-ui/mcp_client.py"
FROZEN={
    "before":{
        "commit":"fe373e086d9963c37eeac7139c1c7297b355e594",
        "blob":"10fd84d1336b44f5dfe0d7270d2a636e9c5ca866"},
    "after":{
        "commit":"506154fddca004722efbdb99d6125efcd4cb1052",
        "blob":"02c6eb077a0fdf95a28a8c3b9cd7a5c27d7d6855"},
}
SCENARIOS=["normal","refusal","empty_refusal","multi",
           "structured","rpc_error","normal_again"]

def must(condition,reason):
    if not condition:
        raise RuntimeError("B38_EXTERNAL_WATERWORKS_"+reason)

def git(root,*args):
    p=subprocess.run(["git","-C",str(root),*args],
                     text=True,capture_output=True,timeout=30,check=False)
    must(p.returncode==0,"GIT_"+str(args[0]))
    return p.stdout.strip()

def sha(data):
    return hashlib.sha256(data).hexdigest()

def load_original(side):
    original=FROZEN[side]
    repo=UPSTREAM/side
    must(repo.is_dir(),"MISSING_CHECKOUT_"+side)
    must(git(repo,"rev-parse","HEAD")==original["commit"],
         "WRONG_ORIGINAL_COMMIT_"+side)
    must(git(repo,"rev-parse","HEAD:"+MODULE_PATH)==original["blob"],
         "WRONG_GIT_TREE_BLOB_"+side)
    p=subprocess.run(["git","-C",str(repo),"cat-file","blob",original["blob"]],
                     capture_output=True,timeout=30,check=False)
    must(p.returncode==0 and 100<len(p.stdout)<200_000,
         "GIT_SOURCE_BLOB_UNAVAILABLE_"+side)
    source=p.stdout
    must(b"\x00" not in source,"BINARY_SOURCE_"+side)
    path=OUT/"original_git_blobs"/side/"original_mcp_client.py"
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_bytes(source)
    spec=importlib.util.spec_from_file_location("b38_waterworks_original_"+side,path)
    must(spec is not None and spec.loader is not None,"IMPORT_SPEC_MISSING")
    obj=importlib.util.module_from_spec(spec)
    sys.modules[spec.name]=obj
    # The original complete module is executed; only its transport selector
    # is replaced after import. Its call_mcp_tool is never rewritten.
    spec.loader.exec_module(obj)
    must(callable(obj.call_mcp_tool) and callable(obj._get_session),
         "EXPECTED_ORIGINAL_CLIENT_API_MISSING_"+side)
    return obj,sha(source)

async def run_side(side):
    mod,source_sha=load_original(side)
    log=OUT/("WATERWORKS_"+side.upper()+"_ORIGINAL_MCP_STDIO.jsonl")
    params=StdioServerParameters(
        command=sys.executable,args=[str(SERVER)],
        env={"B38_NATIVE_WIRE_RECORD":str(log.resolve())}
    )
    records={}
    async with stdio_client(params) as (read,write):
        async with ClientSession(read,write) as session:
            initialized=await asyncio.wait_for(session.initialize(),timeout=18)
            must(initialized is not None,"MCP_INITIALIZATION_FAILED_"+side)
            tools=await asyncio.wait_for(session.list_tools(),timeout=18)
            found={t.name for t in tools.tools}
            must(set(SCENARIOS)-{"normal_again"}<=found,
                 "MCP_TOOL_DISCOVERY_MISSING_"+side)

            async def bound(_url:str):
                return session

            mod._get_session=bound
            for name in SCENARIOS:
                tool="normal" if name=="normal_again" else name
                output=await asyncio.wait_for(
                    mod.call_mcp_tool(tool,{},aggregator_url="stdio://B38"),
                    timeout=20)
                must(isinstance(output,str),"ORIGINAL_FUNCTION_RETURN_NOT_TEXT")
                records[name]=output
    must(log.is_file() and log.stat().st_size>0,
         "MISSING_ORIGINAL_WIRE_LOG_"+side)
    wire=[json.loads(v) for v in log.read_text(encoding="utf-8").splitlines()]
    tool_calls=[v for v in wire if v.get("request",{}).get("method")=="tools/call"]
    must(len(tool_calls)==len(SCENARIOS),
         "ORIGINAL_NATIVE_TOOL_CALL_COUNT_CHANGED_"+side)
    must(len({v["request"]["id"] for v in tool_calls})==len(SCENARIOS),
         "ORIGINAL_NATIVE_TOOL_REQUEST_IDS_NOT_UNIQUE_"+side)
    for (scenario,wire_entry) in zip(SCENARIOS,tool_calls):
        tool="normal" if scenario=="normal_again" else scenario
        must(wire_entry["request"]["params"]["name"]==tool,
             "ORIGINAL_WIRE_OBSERVATION_ORDER_MISMATCH_"+side)
    return {"side":side,
            "original_upstream_commit":FROZEN[side]["commit"],
            "original_source_git_blob":FROZEN[side]["blob"],
            "original_source_sha256":source_sha,
            "original_module_executed":True,
            "session_acquisition_adapted_to_real_stdio":True,
            "original_call_mcp_tool_unmodified":True,
            "mcp_sdk_client_session_over_real_stdio":True,
            "wire_sha256":sha(log.read_bytes()),
            "observed_by_original_client":records,
            "raw_native_wires":tool_calls,
            "wire_path":log.name}

def classify_result(text,scenario):
    if scenario=="rpc_error":
        # The actual Waterworks API returns "Error calling <tool>" when a
        # JSON-RPC error caused ClientSession to raise. This is a caller-
        # visible error string, not a typed transport exception.
        must(text.startswith("Error calling ") and
             "controlled transport error" in text,
             "ORIGINAL_PROTOCOL_ERROR_STRING_NOT_PRESERVED")
        return "jsonrpc_error"
    return "tool_error" if text.startswith("Error") else "success"

async def main():
    must(SERVER.is_file(),"CONTROLLED_NATIVE_SERVER_MISSING")
    OUT.mkdir(exist_ok=True)
    before=await run_side("before")
    after=await run_side("after")
    a=before["observed_by_original_client"]
    b=after["observed_by_original_client"]
    must(a["normal"]==b["normal"]=="normal result","NORMAL_CONTROL_REGRESSION")
    must(a["normal_again"]==b["normal_again"]=="normal result",
         "NORMAL_AFTER_ERROR_REGRESSION")
    must(a["multi"]==b["multi"]=="first\nsecond",
         "MULTIBLOCK_TEXT_REGRESSION")
    must(a["refusal"]=="VALIDATION_FAILED: missing document",
         "ORIGINAL_ERROR_WAS_NOT_FALSE_SUCCESS")
    must(b["refusal"]=="Error: VALIDATION_FAILED: missing document",
         "REPAIRED_ERROR_REASON_NOT_PROPAGATED")
    must(a["empty_refusal"]=="(no result)",
         "ORIGINAL_EMPTY_ERROR_NOT_FALSE_SUCCESS")
    must(b["empty_refusal"]=="Error: (no result)",
         "REPAIRED_EMPTY_ERROR_NOT_PROPAGATED")
    from b38_native_contract_auditor import audit_record
    all_cases=[]
    for r in (before,after):
        side=r["side"]
        for scenario,wire_entry in zip(SCENARIOS,r["raw_native_wires"]):
            observed_text=r["observed_by_original_client"][scenario]
            expected_tool="normal" if scenario=="normal_again" else scenario
            obs={
                "request_id":wire_entry["request"]["id"],
                "tool":expected_tool,
                "outcome":classify_result(observed_text,scenario),
            }
            testmode={"status":True}
            if scenario in ("normal","multi","normal_again"):
                testmode["text"]="exact"
                obs["text"]=observed_text
            if scenario=="rpc_error":
                obs["error_text"]=observed_text
            # Rich structured result is not part of Waterworks documented
            # string-return client contract; no silent preservation claim.
            entry={
                "wire":wire_entry,
                "observed":obs,
                "contract":testmode,
                "execution_provenance":"ORIGINAL_EXTERNAL_CLIENT_CONTROLLED_SERVER",
                "original_source_git_blob":r["original_source_git_blob"],
                "original_commit_verified":True,
            }
            verdict=audit_record(entry)
            all_cases.append({"side":side,"scenario":scenario,
                              "original_consumer_output":observed_text,
                              "verdict":verdict})
    pre=[v for v in all_cases if v["side"]=="before"]
    post=[v for v in all_cases if v["side"]=="after"]
    pre_errors=[v for v in pre if "APPLICATION_ERROR_AS_SUCCESS" in v["verdict"]["findings"]]
    post_errors=[v for v in post if "APPLICATION_ERROR_AS_SUCCESS" in v["verdict"]["findings"]]
    must({v["scenario"] for v in pre_errors}=={"refusal","empty_refusal"},
         "ORIGINAL_ERROR_AS_SUCCESS_NOT_DETECTED")
    must(not post_errors,"AFTER_FIX_STILL_HAS_FALSE_SUCCESS")
    for v in all_cases:
        if v["scenario"] not in {"refusal","empty_refusal","structured"}:
            must(not v["verdict"]["findings"],
                 "UNEXPECTED_NORMAL_CONTROL_WARNING_"+v["side"]+"_"+v["scenario"])
    totals={
        "schema":"risu-p6b38-original-waterworks-stdio-v1",
        "original_upstream_repo":"smslavin/waterworks-ai",
        "original_upstream_client_code_executed":True,
        "external_upstream_server_executed":False,
        "session_acquisition_only_adapted":True,
        "original_result_projection_function_unchanged":True,
        "network_or_credentials":False,
        "native_mcp_stdio_using_actual_python_sdk":True,
        "original_before_false_successes":len(pre_errors),
        "original_after_false_successes":len(post_errors),
        "pre_after_normal_checks_preserved":True,
        "structured_only_completeness_not_claimed":True,
        "population_FPR_unmeasured":True,
        "b38_already_sealed_before_adapters":True,
    }
    result={
        "schema":"risu-b38-original-external-client-native-evidence-v1",
        "summary":totals,
        "original_versions":[{"side":r["side"],
                               "commit":r["original_upstream_commit"],
                               "blob":r["original_source_git_blob"],
                               "source_sha256":r["original_source_sha256"],
                               "wire_sha256":r["wire_sha256"],
                               "raw_wire_file":r["wire_path"]}
                               for r in (before,after)],
        "independent_native_contract_evaluation":all_cases,
    }
    dest=OUT/"B38_WATERWORKS_ORIGINAL_NATIVE_RESULTS.json"
    dest.write_text(json.dumps(result,sort_keys=True,indent=2,ensure_ascii=False)+"\n",
                    encoding="utf-8")
    print(json.dumps(totals,sort_keys=True))
    print("B38_ORIGINAL_WATERWORKS_ERROR_EFFECT_WITH_NATIVE_STDIO_CONFIRMED")
    print("B38_WATERWORKS_RESULT_SHA256="+sha(dest.read_bytes()))

if __name__=="__main__":
    asyncio.run(main())
