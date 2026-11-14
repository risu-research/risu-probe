#!/usr/bin/env python3
"""B39 Otari original external MCP result formatter function pre/post on real stdio.

An isolated, exact original source AST execution, NOT the original gateway
application or a full original MCP client session pool. First-party official
SDK receives actual native MCP result, original formatter renders it.
"""
from __future__ import annotations
import ast,asyncio,hashlib,json,os,subprocess,sys
from pathlib import Path
from typing import Any
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import CallToolResult
from b38_native_contract_auditor import audit_record

ROOT=Path(__file__).resolve().parent.parent
HERE=Path(__file__).resolve().parent
FILE="src/gateway/services/mcp_client.py"
META={
 "before":{"commit":"54c67f5986b090db1198ebf43f9c879b3f5779a2",
  "blob":"5e61fa7fb8f7df50e71d4b03211a21ec6960e17b"},
 "after":{"commit":"86267dbf0f22bdeaebad9efdcb6111445c7656a5",
  "blob":"5dab897cef5ce34e0d847efe49e59f0abd21e640"},
}
CALLS=("normal","embedded_text","embedded_blob","mixed")
OUT=HERE/"out"

def check(ok,c):
 if not ok:raise RuntimeError("B39_OTARI_"+c)
def git(root,*args):
 x=subprocess.run(["git","-C",str(root),*args],text=True,capture_output=True,timeout=30)
 check(x.returncode==0,"GIT_"+str(args[0]))
 return x.stdout.strip()
def sha(b):return hashlib.sha256(b).hexdigest()

def original(side):
 repo=ROOT/"original"/side
 m=META[side]
 check(git(repo,"rev-parse","HEAD")==m["commit"],"ORIGINAL_COMMIT_CHANGED")
 check(git(repo,"rev-parse","HEAD:"+FILE)==m["blob"],"ORIGINAL_BLOB_CHANGED")
 x=subprocess.run(["git","-C",str(repo),"cat-file","blob",m["blob"]],
                  capture_output=True,timeout=30)
 check(x.returncode==0 and 100<len(x.stdout)<100_000,"ORIGINAL_SOURCE_MISSING")
 orig=x.stdout.decode("utf-8")
 body=ast.parse(orig,filename=FILE)
 funcs=[n for n in body.body if isinstance(n,ast.FunctionDef)
        and n.name in ("_render_content_block","_result_text")]
 check(len(funcs)==2,"EXPECTED_TWO_UNMODIFIED_ORIGINAL_FUNCTIONS")
 mod=ast.fix_missing_locations(ast.Module(body=funcs,type_ignores=[]))
 scope={"__name__":"b39_otari_original_"+side,
        "Any":Any,"CallToolResult":CallToolResult}
 exec(compile(mod,FILE,"exec"),scope)
 return scope["_result_text"],sha(x.stdout),[
  {"name":n.name,"line_start":n.lineno,"line_end":n.end_lineno}
  for n in funcs]

async def run_side(side):
 fn,src_sha,lines=original(side)
 wire=OUT/("B39_OTARI_"+side.upper()+"_NATIVE_STDIO.jsonl")
 peer=HERE/"b39_otari_controlled_stdio_peer.py"
 params=StdioServerParameters(command=sys.executable,args=[str(peer)],
                             env={"B39_OTARI_ORIGINAL_WIRE":str(wire.resolve())})
 outputs={}
 async with stdio_client(params) as (read,write):
  async with ClientSession(read,write) as cli:
   await asyncio.wait_for(cli.initialize(),timeout=20)
   for name in CALLS:
    result=await asyncio.wait_for(cli.call_tool(name,{}),timeout=20)
    check(isinstance(result,CallToolResult) and result.is_error is not True,
          "ORIGINAL_SDK_TOOL_RESULT_NOT_SUCCESS")
    outputs[name]=fn(result)
 check(wire.is_file(),"WIRE_MISSING")
 records=[json.loads(x) for x in wire.read_text(encoding="utf-8").splitlines()]
 calls=[x for x in records if x.get("request",{}).get("method")=="tools/call"]
 check(len(calls)==4,"WIRE_TOOL_CALL_COUNT_WRONG")
 for name,x in zip(CALLS,calls):
  check(x["request"]["params"]["name"]==name,"MCP_TOOL_NAME_MISMATCH")
 return {"side":side,"original_git_commit":META[side]["commit"],
   "original_git_blob":META[side]["blob"],"original_source_sha256":src_sha,
   "exact_original_AST_functions":lines,
   "original_gateway_application_executed":False,
   "original_external_formatter_source_executed":True,
   "actual_official_MCP_SDK_stdio_received":True,
   "native_request_response_sha256":sha(wire.read_bytes()),
   "raw_wire_file":wire.name,"rendered_model_messages":outputs,"native_calls":calls}

async def main():
 OUT.mkdir(exist_ok=True)
 before=await run_side("before");after=await run_side("after")
 a=before["rendered_model_messages"];b=after["rendered_model_messages"]
 check(a["normal"]==b["normal"]=="normal","NORMAL_TEXT_MISMATCH")
 check(a["embedded_text"]=="[resource uri=file:///controlled/hello.txt]",
       "PRE_FIX_RESOURCE_NOT_JUST_URI")
 check(b["embedded_text"]==a["embedded_text"]+"\nPRINT_THIS_ORIGINAL_BODY",
       "POST_FIX_EMBEDDED_RESOURCE_TEXT_NOT_VISIBLE")
 check(a["embedded_blob"]=="[resource uri=file:///controlled/hello.bin]",
       "PRE_FIX_BLOB_NOT_URI_ONLY")
 check(b["embedded_blob"]=="[resource uri=file:///controlled/hello.bin type=application/octet-stream bytes_b64=8]",
       "POST_FIX_BINARY_NOT_SUMMARIZED")
 check("PRINT_THIS_ORIGINAL_BODY" not in a["mixed"]
       and "PRINT_THIS_ORIGINAL_BODY" in b["mixed"],
       "MIXED_RESOURCE_BODY_NOT_RECOVERED")
 # B38 frozen detector does NOT support an embedded-resource source-to-model
 # full-body projection contract: do not count these as its detections.
 controls=[]
 for rec in (before,after):
  for name,wire in zip(CALLS,rec["native_calls"]):
   obs={"request_id":wire["request"]["id"],
        "tool":name,"outcome":"success"}
   result=audit_record({"wire":wire,"observed":obs,
      "contract":{"status":True},
      "execution_provenance":"CONTROLLED_FIRST_PARTY"})
   check(not result["findings"] and result["channels_tested"]==["status"],
         "STATUS_ONLY_FALSE_ALARM")
   controls.append({"version":rec["side"],"tool":name,
      "checker_result":"STATUS_ONLY_PRESERVED",
      "resource_body_preservation_not_measured_by_frozen_checker":True,
      "model_text_sha256":sha(rec["rendered_model_messages"][name].encode())})
 summary={
  "case":"P2","original_upstream_repo":"mozilla-ai/otari",
  "exact_original_external_formatter_function_executed":True,
  "whole_external_gateway_client_executed":False,
  "genuine_own_full_server_executed":False,
  "real_first_party_MCP_SDK_stdio_receiver":True,
  "embedded_text_resource_body_missing_before":True,
  "embedded_text_resource_body_present_after":True,
  "binary_resource_intentionally_summarized_after":True,
  "normal_text_preserved_both":True,
  "frozen_B38_generic_embedded_resource_detection":"NOT_SUPPORTED_NOT_SCORED",
  "population_FPR":"UNMEASURED",
 }
 report={"schema":"risu-b39-otari-original-resource-fix-v1",
         "summary":summary,"before":{k:v for k,v in before.items() if k!="native_calls"},
         "after":{k:v for k,v in after.items() if k!="native_calls"},
         "frozen_status_only_controls":controls}
 p=OUT/"B39_OTARI_ORIGINAL_EMBEDDED_RESOURCE_EFFECT.json"
 p.write_text(json.dumps(report,sort_keys=True,indent=2,ensure_ascii=False)+"\n")
 print(json.dumps(summary,sort_keys=True))
 print("B39_OTARI_ORIGINAL_EMBEDDED_RESOURCE_BODY_BEFORE_AFTER_CONFIRMED")
 print("B39_OTARI_RESULT_SHA256="+sha(p.read_bytes()))

if __name__=="__main__":
 asyncio.run(main())
