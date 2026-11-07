"""P6-B7 independent upstream semantic oracle and frozen RISU score.

The upstream BUG/FIX criterion is independent of RISU findings. The two
selected defects count once each, irrespective of tool calls or error count.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

EXPECTED={
 "A11Y205":{"before":"284865a7e07b847972b63447a6b17020f08bb618",
    "fixed":"decf6bac7f086c19afb242797b4974671ceff597",
    "source_repo":"Community-Access/accessibility-agents"},
 "FS5184":{"before":"3bd1337713c796ada8a3dbb088dd911aa83dc932",
    "fixed":"0dce8bd9b65d91a6f7afe1d8f99ffea5d5cf8fe4",
    "source_repo":"modelcontextprotocol/servers"}
}
RELEVANT_RULES={"A11Y205":{"RMC501","RMC502","RMC503","RMC504"},
                "FS5184":{"RMC501","RMC502","RMC503","RMC504"}}

def get(root:Path, family:str, version:str)->dict:
    directory=root/family/version
    original=directory/"original_stdio.jsonl"
    o=json.loads((directory/"origin.json").read_bytes())
    r=json.loads((directory/"risu.json").read_bytes())
    assert o["schema"]=="p6b7-upstream-actual-stdio-v1"
    assert o["family"]==family and o["version"]==version
    assert o["repo"]==EXPECTED[family]["source_repo"]
    assert o["commit"]==EXPECTED[family]["before" if version=="old" else "fixed"]
    assert o["trace_sha256"]==hashlib.sha256(original.read_bytes()).hexdigest()
    assert o["production_data_used"] is False and o["external_mcp_endpoint_called"] is False
    assert o["source"]=="PINNED_PUBLIC_UPSTREAM_SOURCE_EXECUTED_WITH_SYNTHETIC_INPUT"
    assert r["schema"]=="risu-mcp-jsonrpc-trace-audit-v1"
    assert r["capture_sha256"]==o["trace_sha256"]
    assert r["origin_integrity"]=="UNATTESTED_LOCAL_CAPTURE"
    assert r["summary"]["tool_call_requests"]==len(o["outcomes"])
    assert r["summary"]["messages_parsed"]==o["message_count"]
    for f in r["findings"]:
        assert f["rule_id"] in {"RMC501","RMC502","RMC503","RMC504"}
    return {"origin":o,"risu":r}

def primary(x:dict)->dict:
    return x["origin"]["outcomes"]["primary"]

def extract_text(outcome:dict)->str:
    return "".join(v.get("text","") for v in outcome["text"] if
                   isinstance(v,dict) and isinstance(v.get("text"),str))

def verify_runtime(records:dict)->dict:
    a=primary(records["A11Y205"]["old"])
    b=primary(records["A11Y205"]["fixed"])
    # Actual SDK server reports a tool failure, and the fixed version produces
    # structured output. This does not by itself prove runtime data loss.
    aa=(a["is_error"] is True and ("output validation" in extract_text(a).lower()
             or "structured content" in extract_text(a).lower()))
    bb=(b["is_error"] is False and b["jsonrpc_error"] is False and b["structured_present"] is True)
    f1=primary(records["FS5184"]["old"])
    f2=primary(records["FS5184"]["fixed"])
    def file_content(v:dict):
        data=v["structured"]
        return data.get("content") if isinstance(data,dict) else None
    fs=(f1["is_error"] is False and f2["is_error"] is False
        and file_content(f1)=="one\ntwo\nthree\nfour\n"
        and file_content(f2)=="")
    c1=records["FS5184"]["old"]["origin"]["outcomes"]["normal_two"]
    c2=records["FS5184"]["fixed"]["origin"]["outcomes"]["normal_two"]
    normal=(c1["is_error"] is False and c2["is_error"] is False
       and file_content(c1)==file_content(c2) and
       isinstance(file_content(c1),str) and file_content(c1).startswith("one\ntwo"))
    return {"A11Y205":aa and bb,"FS5184":fs and normal,
       "a11y_old_is_error":a["is_error"],"a11y_fixed_structured":bb,
       "filesystem_old_text_nonempty":bool(file_content(f1)),
       "filesystem_fixed_zero_text":file_content(f2)=="",
       "filesystem_unchanged_head_two":normal}

def evaluate(root:Path)->dict:
    reports={fam:{ver:get(root,fam,ver) for ver in ("old","fixed")} for fam in EXPECTED}
    runtime=verify_runtime(reports)
    rows=[]
    for fam in EXPECTED:
        old=reports[fam]["old"]
        fixed=reports[fam]["fixed"]
        old_rules={r["rule_id"] for r in old["risu"]["findings"]}
        fixed_rules={r["rule_id"] for r in fixed["risu"]["findings"]}
        relevant=RELEVANT_RULES[fam]
        caught=bool(runtime[fam] and old_rules & relevant and not fixed_rules & relevant)
        gaps=sum(v["risu"]["summary"]["unverified_count"] for v in (old,fixed))
        rows.append({
          "family":fam,"upstream_bug_reproduced":runtime[fam],
          "before_rules":sorted(old_rules),"fixed_rules":sorted(fixed_rules),
          "issue_relevant_detected":caught,
          "false_alarm_on_official_fix":bool(fixed_rules & relevant),
          "unverified_evidence_items":gaps,
          "source_blind_version":"0.9.25.dev0",
          "before_origin_sha256":old["origin"]["trace_sha256"],
          "after_origin_sha256":fixed["origin"]["trace_sha256"],
          "capability_reason":("SDK returns isError=true; current RISU intentionally exempts tool errors"
                    if fam=="A11Y205" else
                    "Return text is schema-conformant; without a behavioral oracle, head=0 semantics are not inferable"),
          "assessment":"DETECTED" if caught else "MISSED" if runtime[fam] else "REPRODUCTION_NOT_CONFIRMED"})
    eligible=[r for r in rows if r["upstream_bug_reproduced"]]
    fixed_alarm=sum(r["false_alarm_on_official_fix"] for r in eligible)
    tp=sum(r["issue_relevant_detected"] for r in eligible)
    # No score is assigned to cases where upstream execution didn't demonstrate
    # its predefined defect. The baseline audit FAILS closed on such a case.
    assert len(eligible)==2,("not fully reproduced upstream",rows,runtime)
    return {
      "schema":"risu-p6b7-independent-upstream-evaluation-v1",
      "source_product_sha":"601f086903b20b61df2f44e8a569d82df67f03a7",
      "upstream_replay_oracle":"ACTUAL_PINNED_NODE_STDIO",
      "engine_modified_for_evaluation":False,
      "result_rows":rows,
      "metrics":{
         "reproduced_independent_defect_families":len(eligible),
         "issue_relevant_true_positive":tp,
         "issue_relevant_false_negative":len(eligible)-tp,
         "holdout_recall":tp/len(eligible),
         "official_fixed_negative_pairs":len(eligible),
         "false_alarm_on_fixed":fixed_alarm,
         "normal_head_two_call_controls":2,
         "unverified_capture_items":sum(r["unverified_evidence_items"] for r in rows),
         "precision":None if tp+fixed_alarm==0 else tp/(tp+fixed_alarm),
         "not_representative_of_ecosystem":True,
         "schema_contract_failures_vs_behavior_semantics":"Separate causal mechanisms; both counted as actual upstream bugs, not equated to automatically analyzable MCP schema violations"}
    }

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--root",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    outcome=evaluate(a.root)
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(outcome,sort_keys=True,indent=2)+"\n")
    print("P6B7_INDEPENDENT_HOLDOUT_SCORE",outcome["metrics"],flush=True)
