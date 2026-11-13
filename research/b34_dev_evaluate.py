#!/usr/bin/env python3
"""Evaluate the new source-channel algorithm ONLY on pre-existing B34 development data."""
from __future__ import annotations
import difflib
import hashlib
import json
from pathlib import Path
import subprocess
import sys

DEV=Path(__file__).resolve().parents[1]
ROOT=DEV.parent
B34=ROOT/"b34"/"benchmarks"/"p6b34"/"LOCKED_HOLDOUT.json"
UPSTREAM=ROOT/"dev"/"upstream"

sys.path.insert(0,str(DEV/"research"))
from b34_channel_projection import analyze_source

def must(ok,message):
    if not ok:
        raise RuntimeError("B34_DEV_REFUSED "+message)

def get_blob(tree,path):
    run=subprocess.run(["git","-C",str(tree),"hash-object",path],
                       text=True,capture_output=True,check=False)
    must(run.returncode==0, "hash-object failed")
    return run.stdout.strip()

def changed_old_lines(old,new):
    before=old.splitlines()
    after=new.splitlines()
    out=set()
    for tag,a,b,c,d in difflib.SequenceMatcher(
            None,before,after,autojunk=False).get_opcodes():
        if tag=="equal":
            continue
        out.update(range(max(1,a-2),min(len(before),b+3)+1))
    return out

def record(case):
    old_dir=UPSTREAM/case["id"]/"before"
    new_dir=UPSTREAM/case["id"]/"after"
    file_path=case["source_path"]
    old_file=old_dir/file_path
    new_file=new_dir/file_path
    must(old_file.is_file() and new_file.is_file(), case["id"]+" files absent")
    must(get_blob(old_dir,file_path)==case["pre_git_blob"],case["id"]+" original blob changed")
    must(get_blob(new_dir,file_path)==case["post_git_blob"],case["id"]+" repaired blob changed")
    for side,tree,commit in [("before",old_dir,case["pre"]),("after",new_dir,case["post"])]:
        head=subprocess.run(["git","-C",str(tree),"rev-parse","HEAD"],
                            text=True,capture_output=True,check=False)
        must(head.returncode==0 and head.stdout.strip()==commit,case["id"]+" "+side+" ref mismatch")
    old=old_file.read_text(encoding="utf-8")
    new=new_file.read_text(encoding="utf-8")
    a=analyze_source(old,file_path)
    b=analyze_source(new,file_path)
    difflines=changed_old_lines(old,new)
    localized=[f for f in a["findings"] if f["line"] in difflines]
    before_ids={f["rule_id"] for f in a["findings"]}
    after_ids={f["rule_id"] for f in b["findings"]}
    differential=[f for f in localized if f["rule_id"] not in after_ids]
    decision=("LOCALIZED_DEV_HYPOTHESIS" if differential else "MISSED_OR_OUT_OF_ALGORITHM_SCOPE")
    return {
      "id":case["id"], "upstream":case["repo"],"source_path":file_path,
      "decision":decision,"before_rules":sorted(before_ids),
      "after_rules":sorted(after_ids),"before_findings":a["findings"],
      "after_findings":b["findings"],
      "localized_differential":differential,
      "source_original_sha256":hashlib.sha256(old.encode()).hexdigest(),
      "source_fixed_sha256":hashlib.sha256(new.encode()).hexdigest(),
      "changed_old_lines":len(difflines),
      "original_live_mcp_execution":False,
      "source_only_classification":"HYPOTHESIS_NOT_RUNTIME_CONFIRMATION"
    }

def main():
    cases=json.loads(B34.read_text())["cases"]
    must(len(cases)==5 and [c["id"] for c in cases]==["H1","H2","H3","H4","H5"],
         "training cases changed")
    records=[record(c) for c in cases]
    hits=sum(c["decision"]=="LOCALIZED_DEV_HYPOTHESIS" for c in records)
    out={"schema":"risu-b34-new-channel-algorithm-training-v1",
         "source_only":True,
         "training_cases_5":True,
         "baseline_frozen_product_hits":0,
         "new_algorithm_localized_development_hits":hits,
         "new_algorithm_misses":5-hits,
         "postfix_findings":sum(len(c["after_findings"]) for c in records),
         "population_false_positive_rate":"UNMEASURED",
         "cases":records}
    dest=DEV/"out"
    dest.mkdir(exist_ok=True)
    (dest/"B34_CHANNEL_DEVELOPMENT_RESULTS.json").write_text(
        json.dumps(out,sort_keys=True,indent=2,ensure_ascii=False)+"\n")
    print(json.dumps({
         "training_cases":5,"localized_source_hypotheses":hits,
         "missed":5-hits,"after_fix_source_candidates":out["postfix_findings"],
         "cases":[{"id":c["id"],"decision":c["decision"],
                   "before":c["before_rules"],"after":c["after_rules"]}
                   for c in records]},sort_keys=True))
    print("B34_DEV_SOURCE_ONLY_NO_B35_SOURCE_USED")
    return 0

if __name__=="__main__":
    raise SystemExit(main())
