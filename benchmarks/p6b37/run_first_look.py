#!/usr/bin/env python3
"""B37 sealed first-look. No foreign code executes; no result-driven tuning.

Original source is pinned by the Git tree and Git blob. Published public
scanner, frozen B34 old detector, and B37 improved scanner evaluated against
the same UTF-8 bytes. Source findings are hypotheses, not runtime proof.
"""
from __future__ import annotations
import difflib
import hashlib
import json
from pathlib import Path
import subprocess
import sys

WORK=Path(__file__).resolve().parents[3]
ROOT=WORK/"holdout"
UPSTREAM=ROOT/"upstream"
DEV=WORK/"development"
BASE=WORK/"frozen"
MANIFEST=ROOT/"benchmarks"/"p6b37"/"SEALED_HOLDOUT.json"
EXPECTED_CASE_BLOB="7e71d523996a0cb1a2387d161c93eb0c34ef33d1"
EXPECTED_DEV_COMMIT="fd025a31a18d5d1c57f089af19ab8342b25f6cd4"
EXPECTED_DEV_ALG_BLOB="412165214a181cf43ef62c69c9711b737f73c268"
EXPECTED_B34_BLOB="79c8b45901766179c7e39b17969c726a276e543d"
EXPECTED_PUBLIC_COMMIT="8d622b792b4ae58b7157fd81ee5f95d6febcfd53"
LIMIT=2*1024*1024

# Compatibility table fixed BEFORE any B37 source was opened, based solely on
# the published original PR defect descriptions that selected the holdout.
CASE_KIND={
  "B37A":"structured_only",
  "B37B":"error_status",
  "B37C":"json_double_envelope",
  "B37D":"structured_only",
  "B37E":"non_object_structured_schema",
  "B37F":"non_object_structured_schema",
  "B37G":"structured_only",
  "B37H":"error_status",
}
RULE_KIND={
 "RSEM101":{"structured_only"},
 "RSEM102":{"multiblock_loss"},
 "RSEM103":{"multimedia_loss"},
 "RSEM104":{"error_status"},
 "RSEM105":{"error_status"},
 "RSEM106":{"json_double_envelope"},
}

def must(ok,code):
    if not ok:
        raise RuntimeError("B37_UNVERIFIED_"+code)

def git(root,*args):
    p=subprocess.run(["git","-C",str(root),*args],
                     capture_output=True,text=True,timeout=60,check=False)
    must(p.returncode==0,"GIT_"+str(args[0]))
    return p.stdout.strip()

def shad(data):
    return hashlib.sha256(data).hexdigest()

def extract_original(case,side,path,blob):
    root=UPSTREAM/case["id"]/side
    commit=case["pre"] if side=="before" else case["post"]
    must(root.is_dir(),case["id"]+"_CHECKOUT_MISSING_"+side)
    must(git(root,"rev-parse","HEAD")==commit,
         case["id"]+"_WRONG_UPSTREAM_COMMIT_"+side)
    actual=git(root,"rev-parse","HEAD:"+path)
    must(actual==blob,
         case["id"]+"_GIT_TREE_BLOB_MISMATCH_"+side+
         "_expected_"+blob+"_actual_"+actual)
    p=subprocess.run(["git","-C",str(root),"cat-file","blob",blob],
                     capture_output=True,timeout=60,check=False)
    must(p.returncode==0,case["id"]+"_MISSING_ORIGINAL_BLOB_"+side)
    data=p.stdout
    must(0<len(data)<=LIMIT and b"\x00" not in data,
         case["id"]+"_NON_TEXT_OR_OVERSIZE_"+side)
    try:
        text=data.decode("utf-8")
    except UnicodeDecodeError:
        raise RuntimeError("B37_UNVERIFIED_NON_UTF8_"+case["id"]) from None
    # Feed exact Git blob bytes into original published binary, avoiding
    # checkout filter or encoding transformations. Never ship foreign source
    # files to the action artifact.
    out=ROOT/"out"/"original_blobs"/case["id"]/side/path
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_bytes(data)
    return text,out,shad(data)

def changed_old_lines(old,new):
    x=old.splitlines()
    y=new.splitlines()
    spans=set()
    for tag,i,j,p,q in difflib.SequenceMatcher(
            None,x,y,autojunk=False).get_opcodes():
        if tag!="equal":
            spans.update(range(max(1,i-2),min(len(x),j+3)+1))
    return spans

def public_check(cli,path):
    p=subprocess.run([str(cli),"check",str(path),"--format","json",
                      "--strict-incomplete"],
                     text=True,capture_output=True,timeout=120,check=False)
    must(p.returncode in (0,2),"PUBLISHED_CLI_FAILED_"+str(p.returncode))
    try:
        data=json.loads(p.stdout)
    except json.JSONDecodeError:
        raise RuntimeError("B37_UNVERIFIED_PUBLISHED_JSON_INVALID") from None
    must(data.get("scope")=="LOCAL_READ_ONLY_NO_EXEC_NO_NETWORK",
         "PUBLIC_CHECK_OUTSIDE_READONLY_SCOPE")
    return {
      "status":data.get("status"),
      "parsed":data.get("summary",{}).get("python_parsed",0),
      "candidate_rule_ids":[f.get("rule_id") for f in data.get("suspected",[])],
      "unverified":data.get("unverified",[]),
      "output_sha256":shad(p.stdout.encode()),
    }

def assess(case,baseline_cli):
    paths=[]
    for path,pre_blob,post_blob in case["files"]:
        old,old_file,old_hash=extract_original(case,"before",path,pre_blob)
        new,new_file,new_hash=extract_original(case,"after",path,post_blob)
        entry={
           "path":path,"before_git_blob":pre_blob,"after_git_blob":post_blob,
           "before_sha256":old_hash,"after_sha256":new_hash,
           "original_upstream_ran":False,
        }
        if case["language"]!="python":
            entry["outcome"]="UNSUPPORTED_LANGUAGE"
            paths.append(entry)
            continue
        published_pre=public_check(baseline_cli,old_file)
        published_post=public_check(baseline_cli,new_file)
        before=ALG_B37(old,path)
        after=ALG_B37(new,path)
        try:
            old_b34=ALG_B34(old,path)
            new_b34=ALG_B34(new,path)
            old_b34_rules=[f.get("rule_id") for f in old_b34["findings"]]
            new_b34_rules=[f.get("rule_id") for f in new_b34["findings"]]
        except (SyntaxError,ValueError,RecursionError):
            old_b34_rules=["UNVERIFIED_PARSE_ERROR"]
            new_b34_rules=["UNVERIFIED_PARSE_ERROR"]
        changed=changed_old_lines(old,new)
        fixed_ids={f["rule_id"] for f in after["findings"]}
        localized=[f for f in before["findings"] if f["line"] in changed]
        differential=[f for f in localized if f["rule_id"] not in fixed_ids]
        relevant=[f for f in differential if CASE_KIND[case["id"]] in
                  RULE_KIND.get(f["rule_id"],set())]
        partial=(before["coverage"]!="COMPLETE_AST" or
                 after["coverage"]!="COMPLETE_AST")
        incomplete_public=(published_pre["parsed"]!=1 or published_post["parsed"]!=1
                           or published_pre["unverified"] or published_post["unverified"])
        if partial:
            outcome="PARTIAL_ONLY"
        elif incomplete_public:
            outcome="UNVERIFIED_PUBLIC_BASELINE_INCOMPLETE"
        elif relevant:
            outcome="LOCALIZED_SOURCE_HYPOTHESIS"
        else:
            outcome="MISSED"
        entry.update({
           "outcome":outcome,"before_coverage":before["coverage"],
           "after_coverage":after["coverage"],
           "before_parse_error":before["parse_error"],
           "after_parse_error":after["parse_error"],
           "before_candidate_rules":[f["rule_id"] for f in before["findings"]],
           "after_candidate_rules":[f["rule_id"] for f in after["findings"]],
           "before_legacy_b34_rules":old_b34_rules,
           "after_legacy_b34_rules":new_b34_rules,
           "published_before":published_pre,
           "published_after":published_post,
           "localized_differential_candidates":[
              {"rule_id":f["rule_id"],"line":f["line"],
               "function":f.get("function"),"rule_mechanism":f.get("mechanism")}
              for f in differential],
           "mechanism_compatible_localized_candidates":[
              {"rule_id":f["rule_id"],"line":f["line"],
               "function":f.get("function"),"rule_mechanism":f.get("mechanism")}
              for f in relevant],
           "old_lines_changed":len(changed),
           "postfix_source_candidate_count":len(after["findings"]),
           "static_only_not_runtime_confirmed":True,
        })
        paths.append(entry)
    if case["language"]!="python":
        status="UNSUPPORTED_LANGUAGE"
    elif any(p["outcome"].startswith("UNVERIFIED") for p in paths):
        status="UNVERIFIED"
    elif any(p["outcome"]=="PARTIAL_ONLY" for p in paths):
        status="PARTIAL_ONLY"
    elif any(p["outcome"]=="LOCALIZED_SOURCE_HYPOTHESIS" for p in paths):
        status="LOCALIZED_SOURCE_HYPOTHESIS"
    else:
        status="MISSED"
    return {
      "id":case["id"],"repo":case["repo"],"language":case["language"],
      "original_fix_pr":case["issue"],"mechanism_kind":CASE_KIND[case["id"]],
      "status":status,"files":paths,
      "genuine_upstream_original_runtime_reproduced":False,
    }

def main():
    must(git(ROOT,"hash-object","benchmarks/p6b37/SEALED_HOLDOUT.json")
         ==EXPECTED_CASE_BLOB,"ORIGINAL_HOLDOUT_SEAL_CHANGED")
    must(git(DEV,"rev-parse","HEAD")==EXPECTED_DEV_COMMIT,
         "FROZEN_DEVELOPMENT_CODE_MOVED")
    must(git(BASE,"rev-parse","HEAD")==EXPECTED_PUBLIC_COMMIT,
         "ORIGINAL_PRODUCT_CHANGED")
    must(git(DEV,"hash-object","research/b37_semantic_preservation.py")
         ==EXPECTED_DEV_ALG_BLOB,"NEW_ALGORITHM_CHANGED_AFTER_TRAINING")
    must(git(DEV,"hash-object","research/b34_channel_projection.py")
         ==EXPECTED_B34_BLOB,"OLD_ALGORITHM_CHANGED")
    m=json.loads(MANIFEST.read_text(encoding="utf-8"))
    cases=m["cases"]
    must(m["sealed_before_b37_code_development"] is True,
         "NOT_SEALED_BEFORE_DEVELOPMENT")
    must([c["id"] for c in cases]==[
        "B37A","B37B","B37C","B37D","B37E","B37F","B37G","B37H"],
         "CASE_MEMBERSHIP_OR_ORDER_CHANGED")
    must(len({c["repo"].split("/")[0].lower() for c in cases})==8,
         "ORGANIZATIONS_NOT_INDEPENDENT")
    must(CASE_KIND.keys()=={c["id"] for c in cases},
         "UNREGISTERED_MECHANISM_CATEGORY")
    results=[]
    for case in cases:
        try:
            results.append(assess(case,CLI))
        except (RuntimeError,OSError,UnicodeError) as exc:
            # An original evidence failure stays visible for the preselected
            # case; never filter, substitute, or assign clean findings.
            results.append({
                "id":case["id"],"repo":case["repo"],
                "language":case["language"],"status":"UNVERIFIED",
                "reason":str(exc),"files":[],
                "genuine_upstream_original_runtime_reproduced":False,
            })
    primary=[x for x in results if x["language"]=="python"]
    eligible=[x for x in primary if x["status"] in (
        "MISSED","LOCALIZED_SOURCE_HYPOTHESIS"
    )]
    positive=[x for x in eligible if x["status"]=="LOCALIZED_SOURCE_HYPOTHESIS"]
    summary={
      "preselected_external_cases":len(cases),
      "independent_upstream_organizations":len(set(x["repo"].lower().split("/")[0] for x in results)),
      "python_primary_preselected":len(primary),
      "python_complete_eligible":len(eligible),
      "python_mechanism_compatible_localized_source_hypotheses":len(positive),
      "python_missed_complete":len([x for x in eligible if x["status"]=="MISSED"]),
      "python_partial_only":len([x for x in primary if x["status"]=="PARTIAL_ONLY"]),
      "python_unverified":len([x for x in primary if x["status"]=="UNVERIFIED"]),
      "other_language_explicit_unsupported":len([x for x in results if x["status"]=="UNSUPPORTED_LANGUAGE"]),
      "native_original_upstream_exec_count":0,
      "population_false_positive_rate":"UNMEASURED",
      "postfix_controls_not_false_positive_population":True,
      "training_on_b37_before_first_look":False,
    }
    report={
       "schema":"risu-p6b37-first-look-immutable-8-original-fixes-v1",
       "original_case_manifest_git_blob":EXPECTED_CASE_BLOB,
       "frozen_product_commit":EXPECTED_PUBLIC_COMMIT,
       "frozen_new_algorithm_commit":EXPECTED_DEV_COMMIT,
       "frozen_new_algorithm_source_blob":EXPECTED_DEV_ALG_BLOB,
       "source_only_hypotheses_not_executed_upstream":True,
       "summary":summary,"cases":results,
    }
    dest=ROOT/"out"
    dest.mkdir(exist_ok=True)
    (dest/"B37_FIRST_LOOK_RESULTS.json").write_text(
        json.dumps(report,sort_keys=True,indent=2,ensure_ascii=False)+"\n")
    lines=["# P6-B37 original first-look report","",
           "Source-only original Git-blob-pinned tests; no upstream code executed.",
           "Frozen B37 detector "+EXPECTED_DEV_COMMIT,"",
           "| Case | Upstream | Language | Result |",
           "|---|---|---|---|"]
    for x in results:
        lines.append("| "+x["id"]+" | "+x["repo"]+" | "+x["language"]+" | "+x["status"]+" |")
    lines+=["","Python fully eligible: "+str(len(eligible))+
            "; mechanism-matched localized source hypotheses: "+str(len(positive))+
            "; complete misses: "+str(summary["python_missed_complete"])+
            "; partial: "+str(summary["python_partial_only"])+
            "; unverified: "+str(summary["python_unverified"])+".",
            "No claim of population FPR, real external runtime proof, or undisclosed bug discovery."]
    (dest/"B37_FIRST_LOOK_REPORT.md").write_text("\n".join(lines)+"\n")
    print(json.dumps({"summary":summary,"verdicts":[{"id":x["id"],
          "status":x["status"],"rules":[r["before_candidate_rules"]
          for r in x.get("files",[]) if "before_candidate_rules" in r]}
          for x in results]},sort_keys=True))
    print("B37_EXTERNAL_HOLDOUT_FIRST_LOOK_RECORDED_NO_RULE_TUNING")
    return 0

if __name__=="__main__":
    CLI=Path(sys.argv[1]).resolve()
    sys.path.insert(0,str(DEV/"research"))
    from b37_semantic_preservation import analyze_source as ALG_B37
    from b34_channel_projection import analyze_source as ALG_B34
    raise SystemExit(main())
