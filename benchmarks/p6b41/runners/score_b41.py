#!/usr/bin/env python3
"""Score B41 executed originals with the exact unchanged B38, no inferred outcomes.

CLI mode N1 (original explicit status), N2 (original API not status-bearing),
P1 (original audit terminal event). No redefinition of B38's semantics.
"""
import argparse,hashlib,importlib.util,json,math
from pathlib import Path

def run_checker(path):
    spec=importlib.util.spec_from_file_location("b38_frozen_b41",path)
    assert spec and spec.loader
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def read(p):
    return json.loads(p.read_text(encoding="utf8"))

def wilson(k,n,z=1.96):
    if n==0: return None
    p=k/n; den=1+z*z/n
    mid=(p+z*z/(2*n))/den
    delta=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/den
    return [round(max(0,mid-delta),6),round(min(1,mid+delta),6)]

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--mode",required=True,choices=("n1","n2","p1"))
    p.add_argument("--checker",required=True,type=Path)
    p.add_argument("--input",nargs="+",required=True,type=Path)
    p.add_argument("--output",required=True,type=Path)
    args=p.parse_args()
    checker=run_checker(args.checker)
    meta={"schema":"risu-b41-frozen-b38-per-org-v1","mode":args.mode,
      "frozen_checker_commit":"425d3d8272c4e725064010ed8fbf5b8217080cab",
      "frozen_checker_blob":"67bbb607d277dda3a1ead60a2ccd9ba807afd7ae",
      "frozen_checker_changed":False,
      "no_population_fpr_claim":True}
    if args.mode=="n1":
        assert len(args.input)==1
        orig=read(args.input[0]); assert orig["original_client_source_unchanged"]
        results=[]
        for r in orig["native_witnesses"]:
            try:sc=checker.audit_record(r)
            except checker.IncompleteEvidence as e:
                sc={"classification":"INCOMPLETE","reason":str(e)}
            results.append({"tool":r["tool"],"score":sc})
        eligible=all(r["score"]["classification"]!="INCOMPLETE" for r in results)
        false=any(r["score"]["classification"]=="DISCREPANCY" for r in results) if eligible else None
        meta.update({"original_external_client_organization":"mark3labs/mcp-go",
          "original_native_client_executed":True,"original_native_source_unchanged":True,
          "original_native_wire_with_distinct_status_observed":eligible,
          "normal_org_denominator":1 if eligible else 0,
          "normal_org_false_alarm_numerator":int(false) if eligible else None,
          "wilson_95_desc_only":wilson(int(false),1) if eligible else None,
          "b38_contracts_scored":"status_only","records":results})
    elif args.mode=="n2":
        assert len(args.input)==1
        orig=read(args.input[0])
        assert orig["original_client_executed"] and not orig["original_client_was_modified"]
        witnesses=orig["witnesses"]
        assert len(witnesses)==2
        flags=[w["original_observed"]["api_exposes_IsError"] for w in witnesses]
        if any(flags): raise AssertionError("N2 unexpectedly has a returned explicit status: audit mode must be revised under sealed protocol")
        meta.update({"original_external_client_organization":"metoro-io/mcp-golang",
          "original_native_client_executed":True,
          "native_tool_calls_with_wire_trace":len(witnesses),
          "native_inband_error_demonstrated":True,
          "original_API_exposes_IsError":False,
          "normal_org_denominator":0,
          "normal_org_false_alarm_numerator":None,
          "classification":"INELIGIBLE_NO_EXPLICIT_ORIGINAL_CLIENT_INBAND_STATUS",
          "b38_score":"NOT_SCORED",
          "reason":"Original ToolResponse exposes only Content, not isError. Error-nil alone is not independently observed presentation success under sealed policy.",
          "source_limited_insight":"Original client API returned original text but has no isError flag for an in-band tool denial; this is a concrete interface omission rather than a measured B38 false positive.",
          "witnesses":witnesses})
    else:
        assert len(args.input)==2
        before,after=map(read,args.input)
        assert before["variant"]=="before" and after["variant"]=="after"
        results=[]
        for variant,doc in (("before",before),("after",after)):
            for r in doc["records"]:
                try:sc=checker.audit_record(r)
                except checker.IncompleteEvidence as e:
                    sc={"classification":"INCOMPLETE","reason":str(e)}
                results.append({"variant":variant,"test":r["variant_case"],
                   "actual_original_terminal_audit_event":r["observed"]["original_terminal_event"],
                   "score":sc})
        x=[r for r in results if r["test"]=="native_true_error"]
        assert len(x)==2
        assert x[0]["variant"]=="before" and x[0]["score"]["classification"]=="INCOMPLETE"
        assert x[1]["variant"]=="after" and x[1]["score"]["classification"]=="OBSERVED_CONTRACT_PRESERVED"
        meta.update({"original_external_client_organization":"blitzcrieg1/agentmetry",
          "original_upstream_before_after_relay_executed":True,
          "actual_original_error_event_before":None,
          "actual_original_error_event_after":"tool_failed",
          "owner_repair_reproduced":True,
          "b38_generic_positive_detected":False,
          "reason":"Before there was NO explicit successful terminal observation; omission is INCOMPLETE under the frozen positive-evidence checker, not a proven successful consumer result.",
          "normal_org_denominator":0,"records":results})
    raw=json.dumps(meta,indent=2,sort_keys=True,ensure_ascii=False)+"\n"
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(raw,encoding="utf8")
    print("B41_SCORE",args.mode,json.dumps({k:meta[k] for k in ("normal_org_denominator","b38_score","owner_repair_reproduced","b38_generic_positive_detected") if k in meta}),"sha256",hashlib.sha256(raw.encode()).hexdigest())

if __name__=="__main__": main()
