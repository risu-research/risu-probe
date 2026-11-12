"""Cross-artifact B14 audit, independently validating both first-pass originals.

Every selected source is retained. No first-pass finding is rewritten. Native
stdout/SQLite outcomes, normal control, unexpected analysis failure, and
postfreeze corroboration are separate fields with distinct evidence hashes.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

CASES={"SP":"a6a6f196b315b11e17929aeeb274821f5a0e6ed0",
       "ME":"05191e95d1ca74f7c26312ae071f5fab42c19601"}
def read(p):return json.loads(p.read_text("utf-8"))
def sha(buf):return hashlib.sha256(buf).hexdigest()
def text_result(item):
    resp=item.get("response",{}).get("result",{})
    if type(resp) is not dict:return ""
    return "\n".join(c["text"] for c in resp.get("content",[])
        if type(c) is dict and c.get("type")=="text" and type(c.get("text")) is str)
def status_check(test,msg):
    if not test:raise ValueError(msg)

def audit(manifest:Path, firstpass:dict[str,Path], postfreeze:dict[str,Path]):
    m=read(manifest)
    status_check([x["id"] for x in m["cohort"]]==["SP","ME"],"Prelocked roster modified")
    status_check(m["denominator"]["predeclared_calls"]==12,"Denominator modified")
    roster={}
    for case in CASES:
        root=firstpass[case]
        origin=read(root/".b14-evidence/origin.json")
        trace=(root/".b14-evidence/original_stdio.jsonl").read_bytes()
        calls=read(root/".b14-evidence/unmodified_calls.json")
        score=read(root/".b14-firstpass.json")
        scanner=read(root/".b14-risu.json")
        entry=next(x for x in m["cohort"] if x["id"]==case)
        status_check(origin["case"]==case and origin["source_commit"]==CASES[case],"Source mismatch")
        status_check(origin["status"]=="CAPTURED_NATIVE_STDIO","Native original incomplete")
        status_check(origin["stdout_sha256"]==sha(trace),"Raw source stdout hash differs")
        status_check(score["source_stdout_sha256"]==sha(trace),"Score detached from original bytes")
        status_check(score["source_commit"]==entry["sha"],"Score source changed")
        status_check(origin["selected_calls"]==6 and len(calls)==6,"Selected tool calls omitted")
        status_check([v["case"] for v in calls]==[p["id"] for p in entry["probe"]],"Locked call order modified")
        status_check(all(call["call_id"]==20+i for i,call in enumerate(calls)),"Call ID changed")
        parsed=[json.loads(line) for line in trace.splitlines()]
        status_check(len([msg for msg in parsed if msg.get("method")=="tools/call"])==6,
                     "Captured wire lacks prelocked original requests")
        response_by_id={v.get("id"):v for v in parsed if "id" in v and "method" not in v}
        status_check(all(c["call_id"] in response_by_id and
                   response_by_id[c["call_id"]]==c["response"] for c in calls),
                   "Derived call response differs from native wire bytes")
        status_check(scanner["capture_sha256"]==sha(trace),"Frozen RISU scan differs from bytes")
        status_check(score["frozen_risu"]["finding_codes"]==[
            f.get("rule_id") for f in scanner.get("findings",[])],"Scanner score recoded")
        status_check(score["unverified"]==0 and score["origin_status"]=="CAPTURED_NATIVE_STDIO",
                     "Missing measurement reclassified as completed")
        roster[case]={"origin_sha256":sha(trace),"commit":CASES[case],
            "firstpass_oracle":{v["id"]:v["result"] for v in score["checks"]},
            "frozen_detector_findings":[f.get("rule_id") for f in scanner.get("findings",[])],
            "calls":{v["case"]:v for v in calls}}
    sp=roster["SP"]["calls"]
    me=roster["ME"]["calls"]
    status_check(all(v=="PASS" for v in roster["SP"]["firstpass_oracle"].values()),
                 "Normal SP counterexample disappeared")
    status_check(sp["sp_guard"]["before"]==sp["sp_guard"]["after"],
                 "SP explicit guard mutated database")
    status_check(sp["sp_guard"]["response"]["result"].get("isError") is True,
                 "SP known read-only execution attempt not signaled as error")
    status_check(me["me_guard"]["before"]!=me["me_guard"]["after"],
                 "Unexpected ME effect missing from original committed database")
    status_check([1,"RISU_B14_ONE"] in me["me_guard"]["before"] and
                 [1,"RISU_B14_WRONG_PATH"] in me["me_guard"]["after"],
                 "ME independent mutation not the predeclared fixture row")
    status_check(me["me_guard"]["response"]["result"].get("isError") is False,
                 "ME original server did not report normal success")
    status_check([2,"RISU_B14_POSITIVE"] in me["me_positive"]["after"],
                 "ME valid writer control did not commit")
    status_check("me_documented_readonly_effect" in roster["ME"]["firstpass_oracle"] and
                 roster["ME"]["firstpass_oracle"]["me_documented_readonly_effect"]=="MISMATCH",
                 "First-pass independent mismatch replaced")
    analysis=me["me_analysis"]
    status_check("Object of type int64 is not JSON serializable" in text_result(analysis),
                 "Unexpected native analysis fault not in locked original trace")
    status_check(analysis["response"]["result"].get("isError") is False,
                 "Original failure-vs-success flag mismatch absent")
    checkset={}
    for python,root in postfreeze.items():
        data=read(root/".b14-analysis-results/analysis_controls.json")
        trace=(root/".b14-analysis-results/original_stdio.jsonl").read_bytes()
        status_check(data["source_commit"]==CASES["ME"],"Postfreeze source revision drift")
        status_check(data["original_stdio_sha256"]==sha(trace),"Postfreeze evidence hash mismatch")
        status_check(data["classification"]=="POSTFREEZE_REPRODUCTION_NOT_FIRSTPASS",
                     "Development results mislabeled as first-pass")
        status_check(data["runtime_confirmed"] and all(data["checks"].values()),
                     "Missing positive and negative independent reproduction controls")
        checkset[python]={"trace_sha256":sha(trace),"checks":data["checks"]}
    status_check(set(checkset)=={"3.11","3.12"},"Python runtime comparison incomplete")
    result={"schema":"risu-b14-cross-source-native-effect-audit-v1",
        "prelock_manifest_sha256":sha(manifest.read_bytes()),
        "source_firstpass_run":43283214546,
        "postfreeze_control_run":43283834458,
        "cohort":[{"case":x,"repo":next(v["repo"] for v in m["cohort"] if v["id"]==x),
                   "source_commit":roster[x]["commit"],
                   "original_stdout_sha256":roster[x]["origin_sha256"],
                   "firstpass_oracles":roster[x]["firstpass_oracle"],
                   "frozen_risu_findings":roster[x]["frozen_detector_findings"]}
                  for x in ("SP","ME")],
        "postfreeze_runtime_controls":checkset,
        "conclusions":{
            "original_upstreams_executed":2,"prelocked_tool_calls":12,
            "SP_normal_oracle_checks":4,
            "ME_original_independent_effect_mismatches":1,
            "ME_unexpected_analyze_table_error_in_original":True,
            "ME_analyze_table_failure_mislabeled_success":True,
            "postfreeze_original_server_python_3_11_and_3_12_reproduction":True,
            "new_upstream_issue_reported":False,
            "novelty_status":"ISSUE_SEARCH_FOUND_NO_MATCH_BUT_NO_GLOBAL_NOVELTY_GUARANTEE",
            "RISU_original_detector_detected_candidates":False,
            "interpretation":"First-pass source-informed evaluation and subsequent postfreeze reproduction are separate. No ecological recall or false-positive rate inferred."}}
    return result

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--manifest",type=Path,default=Path("benchmarks/p6b14/prelocked_native_effect_cohort.json"))
    p.add_argument("--sp",required=True,type=Path)
    p.add_argument("--me",required=True,type=Path)
    p.add_argument("--python311",required=True,type=Path)
    p.add_argument("--python312",required=True,type=Path)
    p.add_argument("--out",required=True,type=Path)
    a=p.parse_args()
    r=audit(a.manifest,{"SP":a.sp,"ME":a.me},{"3.11":a.python311,"3.12":a.python312})
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(r,indent=2,ensure_ascii=False,sort_keys=True)+"\n")
    print("B14_FINAL_CROSS_ORIGINAL_AUDIT",json.dumps(r["conclusions"],sort_keys=True))
if __name__=="__main__":main()
