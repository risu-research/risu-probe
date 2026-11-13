#!/usr/bin/env python3
"""B37 KitAgent original source pre/post native stdio effect replay.

This is a POST-FIRST-LOOK original-upstream code execution. It proves the
already-known kitagent issue on an isolated, controlled, credential-free MCP
JSON-RPC stdio server; it does NOT alter or improve B37 first-look 0/7.
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

HERE=Path(__file__).resolve().parent
WORK=HERE.parent
SERVER=HERE/"b37_original_kitagent_stdio_server.py"
UPSTREAM=WORK/"original"
OUTPUT=HERE/"out"
PATH="src/agent_runtime/core/mcp/client.py"
CASES={
 "before":{
   "sha":"33afd476312db30561f998c1d1dbb46fed9b835c",
   "blob":"a9e849ee577c1c415fca93b75104e32e72ce9adb",
 },
 "after":{
   "sha":"ddbcca26231bbaef937b8a8823fc982a52f5c1c8",
   "blob":"e06486e1769a21278e7506933fd3f57ce8088302",
 }
}

def check(flag,what):
    if not flag:
        raise RuntimeError("B37_UPSTREAM_ORIGINAL_"+what)

def git(cwd,*args):
    r=subprocess.run(["git","-C",str(cwd),*args],
                     capture_output=True,text=True,timeout=30,check=False)
    check(r.returncode==0,"GIT_"+str(args[0]))
    return r.stdout.strip()

def load_version(side):
    target=CASES[side]
    root=UPSTREAM/side
    check(root.is_dir(),"CHECKOUT_MISSING_"+side)
    check(git(root,"rev-parse","HEAD")==target["sha"],"WRONG_COMMIT_"+side)
    check(git(root,"rev-parse","HEAD:"+PATH)==target["blob"],
          "ORIGINAL_GIT_TREE_BLOB_MISMATCH_"+side)
    r=subprocess.run(["git","-C",str(root),"cat-file","blob",target["blob"]],
                     capture_output=True,timeout=30,check=False)
    check(r.returncode==0,"ORIGINAL_BLOB_MISSING_"+side)
    source=r.stdout
    check(0<len(source)<100_000 and b"\x00" not in source,
          "UNSAFE_ORIGINAL_SIZE_"+side)
    clean=OUTPUT/"source"/side/"kitagent_original_client.py"
    clean.parent.mkdir(parents=True,exist_ok=True)
    clean.write_bytes(source)
    spec=importlib.util.spec_from_file_location("b37_kitagent_original_"+side,clean)
    check(spec is not None and spec.loader is not None,"IMPORT_SPEC_"+side)
    obj=importlib.util.module_from_spec(spec)
    sys.modules[spec.name]=obj
    # Only the audited stdlib-only original client module is executed, in a
    # credentialless CI runner; never import the rest of the upstream repo.
    spec.loader.exec_module(obj)
    check(hasattr(obj,"McpClient") and hasattr(obj,"McpToolError"),
          "CLIENT_API_MISSING_"+side)
    return obj, hashlib.sha256(source).hexdigest()

async def invoke(client,module,name):
    try:
        text=await asyncio.wait_for(client.call_tool(name,{}),timeout=18)
        return {"outcome":"success","value":text}
    except module.McpToolError as exc:
        return {"outcome":"mcp_tool_error","message":str(exc)}

async def run_side(side):
    mod,source_hash=load_version(side)
    wire=OUTPUT/("KITAGENT_"+side.upper()+"_ORIGINAL_STDIO.jsonl")
    cli=mod.McpClient()
    try:
        await asyncio.wait_for(cli.connect_stdio(
            sys.executable,[str(SERVER)],
            env={"B37_NATIVE_WIRE_LOG":str(wire.resolve())}
        ),timeout=20)
        tools=await asyncio.wait_for(cli.list_tools(),timeout=20)
        names={x.name for x in tools}
        check({"normal","refusal","empty_refusal","multi","rpc_error"}<=names,
              "ORIGINAL_TOOL_LIST_MISSING_"+side)
        observed={}
        for name in ("normal","refusal","empty_refusal","multi","rpc_error"):
            observed[name]=await invoke(cli,mod,name)
        observed["normal_again"]=await invoke(cli,mod,"normal")
    finally:
        await asyncio.wait_for(cli.close(),timeout=15)
    check(wire.is_file() and wire.stat().st_size>0,
          "ORIGINAL_STDIO_TRACE_MISSING_"+side)
    records=[json.loads(v) for v in wire.read_text(encoding="utf-8").splitlines()]
    calls=[x for x in records if x.get("request",{}).get("method")=="tools/call"]
    check(len(calls)==6,"EXPECTED_SIX_NATIVE_TOOL_CALLS_"+side)
    check(any(x.get("request",{}).get("params",{}).get("name")=="refusal"
              and x.get("response",{}).get("result",{}).get("isError") is True
              for x in calls),"TRUE_ERROR_ON_NATIVE_WIRE_MISSING_"+side)
    check(observed["normal"]=={"outcome":"success","value":"normal result"},
          "NORMAL_RESULT_NOT_PRESERVED_"+side)
    check(observed["normal_again"]==observed["normal"],
          "CLIENT_NOT_REUSABLE_AFTER_ERROR_"+side)
    check(observed["multi"]=={"outcome":"success","value":"first\nsecond"},
          "MULTI_TEXT_BLOCK_RESULT_CHANGED_"+side)
    check(observed["rpc_error"]["outcome"]=="mcp_tool_error" and
          "controlled JSON-RPC failure" in observed["rpc_error"]["message"],
          "JSONRPC_ERROR_NOT_PROPAGATED_"+side)
    return {
      "upstream_repo":"zed123214/kitagent",
      "upstream_original_commit":CASES[side]["sha"],
      "upstream_original_source_git_blob":CASES[side]["blob"],
      "upstream_original_source_sha256":source_hash,
      "native_protocol":"JSONRPC 2.0 over real subprocess stdio",
      "native_protocol_handshake":"2024-11-05",
      "native_request_response_count":len(records),
      "native_tool_call_count":len(calls),
      "original_client_imported_and_executed":True,
      "producer":"FIRST_PARTY_CONTROLLED_STDIO_SERVER",
      "preexisting_upstream_fix":"https://github.com/zed123214/kitagent/pull/14",
      "scenario_observations":observed,
      "original_raw_native_wire_sha256":hashlib.sha256(wire.read_bytes()).hexdigest(),
      "original_raw_native_wire_record_file":wire.name,
    }

async def main():
    check(SERVER.is_file(),"CONTROLLED_SERVER_MISSING")
    OUTPUT.mkdir(exist_ok=True)
    before=await run_side("before")
    after=await run_side("after")
    assert before["scenario_observations"]["refusal"]=={
       "outcome":"success","value":"VALIDATION_FAILED: missing document"
    }, before["scenario_observations"]["refusal"]
    assert before["scenario_observations"]["empty_refusal"]=={
       "outcome":"success","value":""
    }, before["scenario_observations"]["empty_refusal"]
    assert after["scenario_observations"]["refusal"]["outcome"]=="mcp_tool_error"
    assert "VALIDATION_FAILED: missing document" in after[
       "scenario_observations"]["refusal"]["message"]
    assert after["scenario_observations"]["empty_refusal"]["outcome"]=="mcp_tool_error"
    assert "isError" in after["scenario_observations"]["empty_refusal"]["message"]
    summary={
      "case":"B37B",
      "stage":"POST_FIRST_LOOK_ORIGINAL_UPSTREAM_RUNTIME_REPRODUCTION",
      "original_external_client_code_executed":True,
      "external_original_server_executed":False,
      "server_controlled_first_party":True,
      "external_original_upstream_bug_fixed_by_maintainer_before_this_research":True,
      "first_look_original_static_result":"MISSED",
      "native_wire_error_result_isError_true":True,
      "before_bad_result_falsely_reported_as_success":True,
      "after_bad_result_reported_as_tool_error":True,
      "before_empty_error_falsely_reported_as_success":True,
      "after_empty_error_reported_as_tool_error":True,
      "normal_success_preserved_in_both":True,
      "normal_multiblock_text_preserved_in_both":True,
      "real_jsonrpc_errors_preserved_in_both":True,
      "client_reuse_after_errors_passed_both":True,
      "passwords_or_external_network_used":False,
      "population_false_positive_rate":"UNMEASURED",
    }
    output={
       "schema":"risu-b37-original-upstream-native-stdio-before-after-v1",
       "summary":summary,
       "before":before,"after":after,
    }
    dest=OUTPUT/"B37_ORIGINAL_KITAGENT_NATIVE_BEFORE_AFTER.json"
    dest.write_text(json.dumps(output,sort_keys=True,indent=2,ensure_ascii=False)+"\n",
                    encoding="utf-8")
    print(json.dumps(summary,sort_keys=True))
    print("B37_REAL_ORIGINAL_UPSTREAM_CLIENT_STDIO_BEFORE_AFTER_CONFIRMED")
    print("B37_ORIGINAL_REPLAY_SHA256="+hashlib.sha256(dest.read_bytes()).hexdigest())

if __name__=="__main__":
    asyncio.run(main())
