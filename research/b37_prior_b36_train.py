#!/usr/bin/env python3
"""B37 development scoring ONLY on previously opened B36 repaired originals.

This may be used to refine the research detector. It must never be described
as a new independent holdout. No third-party modules are imported/executed.
"""
from __future__ import annotations
import difflib
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
DEV=ROOT/"dev"
B36=ROOT/"previous"
ORIG=ROOT/"original"
sys.path.insert(0,str(DEV/"research"))
from b37_semantic_preservation import analyze_source


def require(cond,why):
    if not cond:
        raise RuntimeError("B37_DEV_"+why)


def git(root,*args):
    r=subprocess.run(["git","-C",str(root),*args],
                     capture_output=True,text=True,timeout=60,check=False)
    require(r.returncode==0,"GIT_"+str(args[0]))
    return r.stdout.strip()


def original(repo_root,sha,path,blob):
    require(git(repo_root,"rev-parse","HEAD")==sha,"COMMIT_CHANGED")
    require(git(repo_root,"rev-parse","HEAD:"+path)==blob,"TREE_BLOB_CHANGED")
    r=subprocess.run(["git","-C",str(repo_root),"cat-file","blob",blob],
                     capture_output=True,timeout=60,check=False)
    require(r.returncode==0,"SOURCE_UNAVAILABLE")
    return r.stdout.decode("utf-8")


def changes(old,new):
    left=old.splitlines()
    right=new.splitlines()
    out=set()
    for tag,a,b,c,d in difflib.SequenceMatcher(None,left,right,autojunk=False).get_opcodes():
        if tag=="equal":
            continue
        out.update(range(max(1,a-2),min(len(left),b+3)+1))
    return out


def one(case):
    records=[]
    for path,pre_blob,post_blob in case["files"]:
        if case["id"]=="B36D":
            pre_blob=ERRATUM["correct_before_blob"]
        old=original(ORIG/case["id"]/"before",case["pre"],path,pre_blob)
        new=original(ORIG/case["id"]/"after",case["post"],path,post_blob)
        a=analyze_source(old,path)
        b=analyze_source(new,path)
        changed=changes(old,new)
        after_ids={x["rule_id"] for x in b["findings"]}
        localized=[x for x in a["findings"] if x["line"] in changed]
        strict=[x for x in localized if x["rule_id"] not in after_ids]
        partial=(a["coverage"]!="COMPLETE_AST" or b["coverage"]!="COMPLETE_AST")
        records.append({
            "path":path,
            "before_coverage":a["coverage"],
            "after_coverage":b["coverage"],
            "before_parse_error":a["parse_error"],
            "after_parse_error":b["parse_error"],
            "before_rules":[x["rule_id"] for x in a["findings"]],
            "after_rules":[x["rule_id"] for x in b["findings"]],
            "source_only_candidate":True,
            "partial":partial,
            "localized_differential":[{"rule_id":x["rule_id"],"line":x["line"],"function":x["function"]}
                                    for x in strict],
            "old_original_sha256":hashlib.sha256(old.encode()).hexdigest(),
            "fixed_original_sha256":hashlib.sha256(new.encode()).hexdigest(),
        })
    if any(r["partial"] for r in records):
        status="PARTIAL_ANALYSIS"
    elif any(r["localized_differential"] for r in records):
        status="LOCALIZED_STATIC_HYPOTHESIS"
    else:
        status="MISSED"
    return {"id":case["id"],"repo":case["repo"],"status":status,"files":records}


def main():
    require(git(DEV,"hash-object","research/b34_channel_projection.py")
            =="79c8b45901766179c7e39b17969c726a276e543d",
            "INHERITED_B34_ALGORITHM_CHANGED")
    manifest=json.loads((B36/"benchmarks/p6b36/SEALED_HOLDOUT.json").read_text())
    cases=[x for x in manifest["cases"] if x["language"]=="python"]
    require([x["id"] for x in cases]==["B36A","B36B","B36C","B36D","B36E"],
            "OLD_TRAINING_CASES_CHANGED")
    rows=[one(x) for x in cases]
    summary={
      "previous_development_case_count":len(rows),
      "primary_complete_cases":sum(r["status"]!="PARTIAL_ANALYSIS" for r in rows),
      "localized_complete_development_hypotheses":sum(r["status"]=="LOCALIZED_STATIC_HYPOTHESIS" for r in rows),
      "partial_analysis_cases":sum(r["status"]=="PARTIAL_ANALYSIS" for r in rows),
      "missed_complete_cases":sum(r["status"]=="MISSED" for r in rows),
      "external_upstream_executed":False,
      "untouched_new_B37_upstream_used":False,
      "false_positive_population_rate":"UNMEASURED",
    }
    dest=DEV/"out"
    dest.mkdir(exist_ok=True)
    out=dest/"B37_B36_TRAINING_RESULTS.json"
    out.write_text(json.dumps({"schema":"risu-b37-prior-B36-development-v1",
                               "summary":summary,"cases":rows},indent=2,sort_keys=True)+"\n")
    print(json.dumps({"summary":summary,"cases":[{"id":r["id"],"status":r["status"],
                      "files":[{"path":f["path"],"before":f["before_rules"],
                                "after":f["after_rules"],
                                "localized":f["localized_differential"],
                                "coverage":f["before_coverage"]} for f in r["files"]]}
                     for r in rows]},sort_keys=True))
    print("B37_PRIOR_B36_DEVELOPMENT_ONLY_DO_NOT_CALL_INDEPENDENT")
    return 0


if __name__=="__main__":
    ERRATUM=json.loads((B36/"benchmarks/p6b36/PROVENANCE_ERRATUM.json").read_text())
    raise SystemExit(main())
