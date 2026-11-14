#!/usr/bin/env python3
"""B38 Langboard original bridge serializer from exact pinned Git AST + MCP stdio.

Code body of original serialize_mcp_result is compiled unmodified; full
Langboard service and HTTP router are deliberately NOT executed. Real MCP SDK
ClientSession calls a bounded first-party stdio server. The pre-frozen,
source-independent B38 verifier checks image + structured channel preservation
on the real wire and exactly observed serializer return value.
"""
from __future__ import annotations
import ast
import asyncio
import hashlib
import json
from json import JSONDecodeError
from pathlib import Path
import subprocess
import sys
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from pydantic import BaseModel
from b38_native_contract_auditor import audit_record, digest

HERE=Path(__file__).resolve().parent
ROOT=HERE.parent
UPSTREAM=ROOT/"original"
PEER=HERE/"b38_langboard_native_peer.py"
OUT=HERE/"out"
TARGET="src/api/langboard/routes/mcp/McpApi.py"
FIX={
 "before":{"sha":"751ed96cbe4817d10edf5467212d3ca0833381e5",
           "blob":"c2e4a7c339304d2d78398447df847fa51affa90a"},
 "after":{"sha":"63753a9618aef540b08e72f7e1ca5313ef1e86bf",
          "blob":"cedab42d86517e7186144101ba8992959e00ca8b"},
}
CALLS=("plain_text","structured_only","image_with_structured","multi_text")

def check(value,reason):
    if not value:raise RuntimeError("B38_LANGBOARD_"+reason)
def git(root,*args):
    r=subprocess.run(["git","-C",str(root),*args],text=True,capture_output=True,
                     timeout=40,check=False)
    check(r.returncode==0,"GIT_"+str(args[0]))
    return r.stdout.strip()
def sha(b):
    return hashlib.sha256(b).hexdigest()

def compile_original_serializer(side):
    meta=FIX[side]
    root=UPSTREAM/side
    check(git(root,"rev-parse","HEAD")==meta["sha"],
          "UPSTREAM_COMMIT_MISMATCH_"+side)
    check(git(root,"rev-parse","HEAD:"+TARGET)==meta["blob"],
          "UPSTREAM_SOURCE_GIT_BLOB_MISMATCH_"+side)
    r=subprocess.run(["git","-C",str(root),"cat-file","blob",meta["blob"]],
                     capture_output=True,timeout=40,check=False)
    check(r.returncode==0 and 100<len(r.stdout)<100_000,
          "ORIGINAL_BLOB_READ_FAILED")
    original=r.stdout.decode("utf-8")
    module=ast.parse(original,filename=TARGET)
    funcs=[n for n in module.body if isinstance(n,ast.FunctionDef)
           and n.name=="serialize_mcp_result"]
    check(len(funcs)==1,"NO_SINGLE_ORIGINAL_FORMATTER")
    fn=funcs[0]
    globs={"__name__":"b38_original_langboard_"+side,
           "Any":Any,"JSONDecodeError":JSONDecodeError,
           "json_loads":json.loads,"BaseModel":BaseModel}
    # The exact function AST and body are compiled without rewriting any node.
    copied=ast.fix_missing_locations(ast.Module(body=[fn],type_ignores=[]))
    exec(compile(copied,TARGET,"exec"),globs)
    return globs["serialize_mcp_result"],sha(r.stdout),[fn.lineno,fn.end_lineno]

def media_observation(value):
    if not isinstance(value,dict) or not isinstance(value.get("content"),list):
        return []
    content=value["content"]
    out=[]
    for block in content:
        if not isinstance(block,dict):continue
        if block.get("type") in ("image","audio"):
            encoded=block.get("data")
            check(isinstance(encoded,str),"RESULT_MEDIA_NOT_BASE64_STRING")
            out.append({"type":block["type"],"base64_sha256":
                        digest(encoded.encode("ascii"))})
    return out

def structured_observation(value):
    if isinstance(value,dict) and "structuredContent" in value:
        return value["structuredContent"]
    # The original pre-fix serializer deliberately preferred structured-only
    # payload and returns it directly, even when image content was present.
    return value

async def run_side(side):
    ser,source_sha,lines=compile_original_serializer(side)
    wirefile=OUT/("B38_LANGBOARD_"+side.upper()+"_ORIGINAL_NATIVE.jsonl")
    params=StdioServerParameters(
        command=sys.executable,args=[str(PEER)],
        env={"B38_LANGBOARD_NATIVE_WIRE":str(wirefile.resolve())})
    observed={}
    async with stdio_client(params) as (read,write):
        async with ClientSession(read,write) as session:
            await asyncio.wait_for(session.initialize(),timeout=20)
            tools=await asyncio.wait_for(session.list_tools(),timeout=20)
            check(set(CALLS)<={t.name for t in tools.tools},
                  "CONTROLLED_TOOL_DISCOVERY_MISSING")
            for name in CALLS:
                native=await asyncio.wait_for(session.call_tool(name,{}),timeout=20)
                value=ser(native)
                check(isinstance(value,(str,dict,list)),"SERIALIZER_UNEXPECTED_TYPE")
                observed[name]=value
    check(wirefile.is_file() and wirefile.stat().st_size>0,
          "ORIGINAL_WIRE_LOG_MISSING")
    lines_raw=[json.loads(x) for x in wirefile.read_text(encoding="utf-8").splitlines()]
    calls=[x for x in lines_raw if x.get("request",{}).get("method")=="tools/call"]
    check(len(calls)==len(CALLS),"MISSING_NATIVE_TOOL_CALLS")
    audits=[]
    for name,wire in zip(CALLS,calls):
        check(wire["request"]["params"]["name"]==name,
              "WIRE_OUTCOME_TOOL_ID_MISMATCH")
        obs={
            "request_id":wire["request"]["id"],
            "tool":name,
            "outcome":"success",
        }
        contract={"status":True}
        if name=="plain_text":
            contract["text"]="exact"
            obs["text"]=observed[name]
        elif name in ("structured_only","image_with_structured"):
            contract["structured"]="exact"
            obs["structured"]=structured_observation(observed[name])
            if name=="image_with_structured":
                contract["media"]="exact"
                obs["media"]=media_observation(observed[name])
        # Multi-text deliberately returns an envelope, not the text-concatenated
        # consumer string; compare before/after as a sibling control instead.
        audit=audit_record({
          "wire":wire,"observed":obs,"contract":contract,
          "execution_provenance":"ORIGINAL_EXTERNAL_SERVER_CONTROLLED_CLIENT",
          "original_source_git_blob":FIX[side]["blob"],
          "original_commit_verified":True,
        })
        audits.append({"scenario":name,"verdict":audit})
    return {
      "side":side,"original_upstream_commit":FIX[side]["sha"],
      "original_source_git_blob":FIX[side]["blob"],
      "source_sha256":source_sha,"original_function_line_span":lines,
      "complete_original_service_executed":False,
      "exact_original_serializer_function_ast_executed":True,
      "original_mcp_client_session_real_stdio":True,
      "native_stdio_wire_sha256":sha(wirefile.read_bytes()),
      "native_stdio_trace_file":wirefile.name,
      "observed_serialized_values":observed,
      "frozen_contract_checker_results":audits,
    }

async def main():
    check(PEER.is_file(),"NATIVE_PEER_MISSING")
    OUT.mkdir(exist_ok=True)
    before=await run_side("before")
    after=await run_side("after")
    a=before["observed_serialized_values"]
    b=after["observed_serialized_values"]
    check(a["plain_text"]==b["plain_text"]=="plain text",
          "NORMAL_PLAIN_TEXT_REGRESSION")
    check(a["structured_only"]==b["structured_only"]==
          {"id":"N","value":7},"NORMAL_STRUCTURED_ONLY_REGRESSION")
    check(a["multi_text"]==b["multi_text"],
          "NORMAL_MULTIBLOCK_ENVELOPE_REGRESSION")
    check(a["image_with_structured"]=={"id":"IMG","value":17},
          "ORIGINAL_PRE_FIX_DID_NOT_DROP_IMAGE")
    check(isinstance(b["image_with_structured"],dict)
          and b["image_with_structured"].get("structuredContent")==
          {"id":"IMG","value":17}
          and len(media_observation(b["image_with_structured"]))==1,
          "ORIGINAL_POST_FIX_IMAGE_NOT_PRESERVED")
    bef={r["scenario"]:r["verdict"] for r in before["frozen_contract_checker_results"]}
    aft={r["scenario"]:r["verdict"] for r in after["frozen_contract_checker_results"]}
    check(bef["image_with_structured"]["findings"]==
          ["MCP_MEDIA_LOST_OR_CHANGED"],"FROZEN_CHECKER_DID_NOT_FIND_IMAGE_LOSS")
    check(aft["image_with_structured"]["findings"]==[],
          "FROZEN_CHECKER_FALSE_IMAGE_LOSS_AFTER_FIX")
    check(all(not r["verdict"]["findings"] for r in before["frozen_contract_checker_results"]
              if r["scenario"]!="image_with_structured"),
          "NORMAL_CONTROL_FALSE_POSITIVE_BEFORE")
    check(all(not r["verdict"]["findings"] for r in after["frozen_contract_checker_results"]),
          "NORMAL_CONTROL_FALSE_POSITIVE_AFTER")
    result={
      "schema":"risu-b38-langboard-original-bridge-function-native-stdio-v1",
      "summary":{
        "upstream_repo":"Langboard/langboard",
        "source_git_fix_url":"https://github.com/Langboard/langboard/pull/259",
        "original_full_server_executed":False,
        "original_serialize_mcp_result_body_ast_executed":True,
        "actual_official_MCP_SDK_native_stdio_wire_collected":True,
        "frozen_generic_media_contract_checker_successful":True,
        "media_lost_before":1,"media_lost_after":0,
        "original_structured_content_present_and_preserved_both":True,
        "normal_text_structured_and_multiblock_controls_pass":True,
        "third_party_source_modified":False,
        "source_to_execution_adapter_used":True,
        "false_positive_population_rate":"UNMEASURED",
        "no_novel_discovery_claim":True,
      },
      "before":before,"after":after,
    }
    p=OUT/"B38_LANGBOARD_ORIGINAL_IMAGE_STRUCTURED_RESULTS.json"
    p.write_text(json.dumps(result,indent=2,sort_keys=True,ensure_ascii=False)+"\n")
    print(json.dumps(result["summary"],sort_keys=True))
    print("B38_LANGBOARD_FROZEN_GENERIC_MEDIA_VERIFIER_ORIGINAL_AST_NATIVE_PASS")
    print("B38_LANGBOARD_EVIDENCE_SHA256="+sha(p.read_bytes()))

if __name__=="__main__":
    asyncio.run(main())
