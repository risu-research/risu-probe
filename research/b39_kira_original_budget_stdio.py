#!/usr/bin/env python3
"""B39 normal policy challenge: execute exact KiraAI truncation function on real MCP stdio results.

This is original upstream *function-only* execution, not a KiraAI agent run,
and observations come from a first-party harness. Detecting intentional
truncation under a mis-specified exact contract is not detector FPR.
"""
from __future__ import annotations
import ast
import asyncio
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from b38_native_contract_auditor import audit_record

HERE=Path(__file__).resolve().parent
ROOT=HERE.parent
TARGET="core/agent/tool.py"
COMMIT="c69b8eab5e89cb09201723e48dcefb83164b7bd6"
BLOB="cdb1833c8593d45b724fe5c6daddacfde04bacff"
LIMIT=32
PEER=HERE/"b39_budget_stdio_peer.py"
OUT=HERE/"out"
CALLS=("short","long_ascii","long_unicode","base64","empty")

def require(ok,msg):
    if not ok:raise RuntimeError("B39_KIRA_"+msg)

def git(root,*args):
    p=subprocess.run(["git","-C",str(root),*args],text=True,
                     capture_output=True,timeout=30,check=False)
    require(p.returncode==0,"GIT_"+str(args[0]))
    return p.stdout.strip()

def sha(x):return hashlib.sha256(x).hexdigest()

def original():
    repo=ROOT/"original"
    require(repo.is_dir(),"ORIGINAL_REPO_MISSING")
    require(git(repo,"rev-parse","HEAD")==COMMIT,"ORIGINAL_COMMIT_MISMATCH")
    require(git(repo,"rev-parse","HEAD:"+TARGET)==BLOB,"ORIGINAL_BLOB_MISMATCH")
    x=subprocess.run(["git","-C",str(repo),"cat-file","blob",BLOB],
                     capture_output=True,timeout=30,check=False)
    require(x.returncode==0 and 100<len(x.stdout)<100_000,
            "ORIGINAL_SOURCE_UNAVAILABLE")
    s=x.stdout.decode("utf-8")
    tree=ast.parse(s,filename=TARGET)
    nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef)
           and n.name=="truncate_tool_output"]
    require(len(nodes)==1,"ORIGINAL_TRUNCATION_FUNCTION_MISSING")
    selected=ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[]))
    globals={"__name__":"b39_exact_kira_original_code"}
    exec(compile(selected,TARGET,"exec"),globals)
    return globals["truncate_tool_output"],sha(x.stdout),[
        nodes[0].lineno,nodes[0].end_lineno]

async def main():
    fn,source_sha,lines=original()
    OUT.mkdir(exist_ok=True)
    trace=OUT/"B39_KIRA_ORIGINAL_NATIVE_WIRE.jsonl"
    params=StdioServerParameters(command=sys.executable,args=[str(PEER)],
        env={"B39_KIRA_WIRE":str(trace.resolve())})
    results={}
    async with stdio_client(params) as (read,write):
        async with ClientSession(read,write) as cli:
            await asyncio.wait_for(cli.initialize(),timeout=20)
            listed=await asyncio.wait_for(cli.list_tools(),timeout=20)
            require(set(CALLS)<={x.name for x in listed.tools},"TOOLS_MISSING")
            for name in CALLS:
                r=await asyncio.wait_for(cli.call_tool(name,{}),timeout=20)
                require(not r.is_error and len(r.content)==1 and
                        r.content[0].type=="text","NORMAL_TEXT_RESULT_MISSING")
                text=r.content[0].text
                transformed=fn(text,LIMIT)
                zero_mode=fn(text,0)
                require(zero_mode==text,"ZERO_BUDGET_MUST_MEAN_NO_CAP")
                require(len(transformed.encode("utf-8"))<=LIMIT*4,
                        "ORIGINAL_TRUNCATOR_EXCEEDED_PREREG_BUDGET")
                if name in ("long_ascii","long_unicode","base64"):
                    require(transformed!=text,"EXPECTED_ORIGINAL_TRUNCATION_NOT_TRIGGERED")
                    require("truncated" in transformed.lower(),
                            "ORIGINAL_TRUNCATION_NOT_EXPLAINED")
                else:
                    require(transformed==text,"NORMAL_SHORT_TEXT_CHANGED")
                results[name]={"original_utf8_bytes":len(text.encode("utf-8")),
                               "original_output_sha256":sha(text.encode("utf-8")),
                               "original_transformed_sha256":sha(transformed.encode("utf-8")),
                               "observed_text":transformed,
                               "budget_max_tokens":LIMIT,
                               "predeclared_intent":"BUDGETED_SUMMARY_NOT_BYTE_EXACT"}
    require(trace.is_file(),"MISSING_NATIVE_STDIO_RECORD")
    wires=[json.loads(x) for x in trace.read_text(encoding="utf-8").splitlines()]
    calls=[x for x in wires if x.get("request",{}).get("method")=="tools/call"]
    require(len(calls)==len(CALLS),"WRONG_ORIGINAL_WIRE_CALL_COUNT")
    audits=[]
    for name,wire in zip(CALLS,calls):
        require(wire["request"]["params"]["name"]==name,"WIRE_IDENTITY_MISMATCH")
        observed={"request_id":wire["request"]["id"],"tool":name,"outcome":"success"}
        record={"wire":wire,"observed":observed,
            "contract":{"status":True},
            "execution_provenance":"CONTROLLED_FIRST_PARTY",
            "original_source_git_blob":BLOB,"original_commit_verified":True}
        correct=audit_record(record)
        require(not correct["findings"] and correct["channels_tested"]==["status"],
                "UNEXPECTED_STATUS_ERROR")
        # Deliberately WRONG exactness contract: this warning is expected and
        # does not represent an original-project defect or an independent FPR.
        exact=audit_record({**record,
            "contract":{"status":True,"text":"exact"},
            "observed":{**observed,"text":results[name]["observed_text"]}})
        if name in ("long_ascii","long_unicode","base64"):
            require(exact["findings"]==["MCP_TEXT_CHANGED"],
                    "POLICY_MISMATCH_CHALLENGE_WAS_NOT_DETECTED")
        else:
            require(not exact["findings"],"EXACT_CONTROL_FALSE_ALARM")
        audits.append({"name":name,"proper_policy_status_findings":correct["findings"],
            "misconfigured_exact_contract_findings":exact["findings"],
            "original_output_sha256":results[name]["original_output_sha256"],
            "intentional_transformed_sha256":results[name]["original_transformed_sha256"],
            "original_utf8_bytes":results[name]["original_utf8_bytes"],
            "observed_transformed_bytes":len(results[name]["observed_text"].encode("utf-8"))})
    summary={
      "case":"N3","external_original_repo":"xxynet/KiraAI",
      "execution_class":"ISOLATED_ORIGINAL_FUNCTION_ON_NATIVE_SDK_STDIO_TOOL_RESULT",
      "original_source_ast_unmodified":True,
      "original_agent_whole_app_executed":False,
      "original_external_client_program_executed":False,
      "native_protocol_tool_results_count":len(CALLS),
      "independent_real_user_client_FPR_eligible":False,
      "normal_exact_short_or_empty":2,
      "intentional_truncations":3,
      "misconfigured_exact_preservation_warnings_expected":3,
      "proper_scoped_status_contract_warnings":0,
      "population_fpr":"UNMEASURED",
      "explicit_policy_protection":"Do not flag intentional declared text budgets as defects",
      "normal_content_loss_not_equivalent_to_mcp_protocol_loss":True,
    }
    output={"summary":summary,"upstream_commit":COMMIT,"upstream_git_blob":BLOB,
       "original_sha256":source_sha,"original_function_lines":lines,
       "actual_stdio_wire_sha256":sha(trace.read_bytes()),
       "actual_wire_file":trace.name,"observations":audits}
    dest=OUT/"B39_KIRA_ORIGINAL_BUDGET_POLICY_RESULT.json"
    dest.write_text(json.dumps(output,sort_keys=True,indent=2,ensure_ascii=False)+"\n")
    print(json.dumps(summary,sort_keys=True))
    print("B39_KIRA_EXTERNAL_ORIGINAL_INTENTIONAL_TRUNCATION_POLICY_VERIFIED")
    print("B39_KIRA_RESULT_SHA256="+sha(dest.read_bytes()))

if __name__=="__main__":
    asyncio.run(main())
