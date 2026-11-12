"""B14: independent post-call logical state oracle; scanner findings remain separate.

Never infer effect from text only. Failure of the native server or semantic parser
is UNVERIFIED, not a detection. A mismatch is a candidate, not a novel issue.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

def text_content(call):
    response=call.get("response",{})
    result=response.get("result",{})
    if type(result) is not dict:return ""
    blocks=result.get("content",[])
    if type(blocks) is not list:return ""
    return "\n".join(x.get("text","") for x in blocks
                     if type(x) is dict and x.get("type")=="text" and type(x.get("text")) is str)

def find_rows(call):
    result=call.get("response",{}).get("result",{})
    if type(result) is not dict:return None
    for v in [result.get("structuredContent")]:
        if type(v) is dict:
            if type(v.get("result")) is dict and type(v["result"].get("rows")) is list:
                return v["result"]["rows"]
            if type(v.get("rows")) is list:return v["rows"]
    for b in result.get("content",[]):
        if type(b) is not dict or b.get("type")!="text":continue
        t=b.get("text")
        if type(t) is not str or len(t)>65000:continue
        try: v=json.loads(t)
        except ValueError:continue
        if type(v) is dict:
            if type(v.get("result")) is dict and type(v["result"].get("rows")) is list:
                return v["result"]["rows"]
            if type(v.get("rows")) is list:return v["rows"]
        if type(v) is list:return v
    return None

def score(case:str,root:Path,manifest:Path,risu:Path|None)->dict:
    m=json.loads(manifest.read_text("utf-8"))
    entry=next(v for v in m["cohort"] if v["id"]==case)
    origin=json.loads((root/"origin.json").read_text("utf-8"))
    raw=(root/"original_stdio.jsonl").read_bytes()
    calls=json.loads((root/"unmodified_calls.json").read_text("utf-8"))
    if origin.get("case")!=case or origin.get("source_commit")!=entry["sha"]:
        raise ValueError("Upstream source/cohort identity changed")
    if origin.get("stdout_sha256")!=hashlib.sha256(raw).hexdigest():
        raise ValueError("Captured original stdio hash mismatch")
    if len(calls)>len(entry["probe"]): raise ValueError("Unregistered call injected")
    for item,p in zip(calls,entry["probe"]):
        if item["case"]!=p["id"] or item["tool"]!=p["name"]:
            raise ValueError("Native selected call order changed")
    checks=[]
    def check(name, state, reason):
        assert state in ("PASS","MISMATCH","UNVERIFIED")
        checks.append({"id":name,"result":state,"note":reason})
    if origin["status"]!="CAPTURED_NATIVE_STDIO" or len(calls)!=len(entry["probe"]):
        check("native_capture_complete","UNVERIFIED","Original upstream server handshake/tool calls incomplete")
    else:
        by={c["case"]:c for c in calls}
        if case=="SP":
            for key in ("sp_page0","sp_page2","sp_bound","sp_guard","sp_after"):
                if "response" not in by[key]:
                    check(key,"UNVERIFIED","Upstream original tool absent; no effect inference")
            guarded=by["sp_guard"]
            if "response" in guarded:
                check("sp_readonly_effect","PASS" if guarded["before"]==guarded["after"] else "MISMATCH",
                      "Independent SQLite logical table snapshot before/after execute_read_query DELETE")
            post=by["sp_after"]
            if "response" in post:
                check("sp_no_loss_of_seed_row","PASS" if [1,"RISU_B14_ONE"] in post["after"] else "MISMATCH",
                      "Independent committed table must retain row 1 following read-only attempt")
            page0=find_rows(by["sp_page0"])
            page2=find_rows(by["sp_page2"])
            if page0 is None or page2 is None:
                check("sp_offset_two_pages","UNVERIFIED","Could not unambiguously decode two declared JSON result row arrays")
            else:
                lhs=[v.get("id") for v in page0 if type(v) is dict]
                rhs=[v.get("id") for v in page2 if type(v) is dict]
                check("sp_offset_two_pages","PASS" if lhs==[1,2] and rhs==[3,4] else "MISMATCH",
                      "Native SQLite fixture has IDs 1-5; limit 2, offsets 0/2, expected [1,2] and [3,4]")
            bound=find_rows(by["sp_bound"])
            if bound is None:
                check("sp_unicode_bound_parameter","UNVERIFIED","Declared structured rows unavailable")
            else:
                check("sp_unicode_bound_parameter",
                      "PASS" if len(bound)==1 and any(type(v) is dict and v.get("label")=="RISU_B14_Ω" for v in bound)
                      else "MISMATCH","Named parameter must preserve exact Unicode fixture value")
        elif case=="ME":
            guarded=by["me_guard"]
            if "response" not in guarded:
                check("me_documented_readonly_effect","UNVERIFIED","Query tool unadvertised")
            else:
                check("me_documented_readonly_effect",
                    "PASS" if guarded["before"]==guarded["after"] else "MISMATCH",
                    "README documents read-only query; independent SQLite committed rows before and after SQL UPDATE")
            positive=by["me_positive"]
            if "response" not in positive:
                check("me_positive_write_control","UNVERIFIED","Update tool unadvertised")
            else:
                check("me_positive_write_control",
                    "PASS" if [2,"RISU_B14_POSITIVE"] in positive["after"] and [2,"RISU_B14_TWO"] in positive["before"]
                    else "MISMATCH","Positive write control must commit an allowed update to a different fixture row")
            after=by["me_after"]
            if "response" not in after:
                check("me_after_query","UNVERIFIED","Read tool unadvertised")
            else:
                check("me_after_query",
                    "PASS" if [1,"RISU_B14_ONE"] in after["after"] or [1,"RISU_B14_WRONG_PATH"] in after["after"]
                    else "MISMATCH","Synthetic row 1 must exist after query to qualify state comparison")
            if "response" in by["me_before"] and "response" in by["me_confirmation"]:
                check("me_stdio_results_readable",
                      "PASS" if "RISU_B14_ONE" in text_content(by["me_before"]) and
                                "RISU_B14_POSITIVE" in text_content(by["me_confirmation"])
                      else "MISMATCH","Normal read/control must report fixture values in native MCP result")
            else:
                check("me_stdio_results_readable","UNVERIFIED","Original tool result unavailable")
    detector={"status":"UNVERIFIED","finding_codes":[]}
    if risu and risu.is_file():
        try:
            value=json.loads(risu.read_text("utf-8"))
            detector={"status":"RECORDED","finding_codes":[f.get("rule_id") for f in value.get("findings",[])]}
        except (ValueError,TypeError):
            pass
    return {"schema":"risu-p6b14-first-pass-effect-oracle-v1",
        "case":case,"repository":entry["repo"],"source_commit":entry["sha"],
        "source_informed":True,"source_stdout_sha256":origin["stdout_sha256"],
        "origin_status":origin["status"],"original_native":origin["original_source_executed"],
        "selected_tool_calls":len(entry["probe"]),"calls_captured":len(calls),
        "checks":checks,"independent_mismatches":sum(x["result"]=="MISMATCH" for x in checks),
        "unverified":sum(x["result"]=="UNVERIFIED" for x in checks),
        "frozen_risu":detector,"unknown_upstream_bug_confirmed":False,
        "novelty":"NOT_REVIEWED_OR_CONFIRMED","original_source_stdout_only":True,
        "claim_boundary":"Source-informed hypothesis test, no previously-unreported bug claim without independent reproduction and issue-history check."}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--case",choices=["SP","ME"],required=True)
    p.add_argument("--capture",type=Path,required=True)
    p.add_argument("--manifest",type=Path,default=Path("benchmarks/p6b14/prelocked_native_effect_cohort.json"))
    p.add_argument("--scanner",type=Path)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    report=score(a.case,a.capture,a.manifest,a.scanner)
    a.out.write_text(json.dumps(report,indent=2,ensure_ascii=False,sort_keys=True)+"\n")
    print("B14_INDEPENDENT_EFFECT_FIRSTPASS",json.dumps({k:report[k] for k in
          ("case","origin_status","independent_mismatches","unverified","novelty")},sort_keys=True))
if __name__=="__main__":
    main()
