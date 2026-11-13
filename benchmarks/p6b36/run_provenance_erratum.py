#!/usr/bin/env python3
"""Sealed, one-time B36 original-source holdout: code was frozen before execution.

Does NOT import or execute upstream applications. Reports only source-based
candidate detections; native MCP server/runtime transport behavior is untested.
"""
from __future__ import annotations

import difflib
import hashlib
import json
from pathlib import Path
import subprocess
import sys

HERE=Path(__file__).resolve()
ROOT=HERE.parents[3]
HOLDOUT=ROOT/"holdout"
UPSTREAM=HOLDOUT/"upstream"
DEV=ROOT/"development"
FROZEN=ROOT/"frozen"
MANIFEST=HOLDOUT/"benchmarks"/"p6b36"/"SEALED_HOLDOUT.json"
ERRATUM=HOLDOUT/"benchmarks"/"p6b36"/"PROVENANCE_ERRATUM.json"
EXPECTED_ERRATUM_GIT_BLOB="506040893169eb27a95ab752f2b86ed793117203"
EXPECTED_MANIFEST_GIT_BLOB="d73d8a029c78c216f6a0167d891f63299c89798a"
EXPECTED_DEV_COMMIT="c34def4a25b66cbc89df039ca235d6c1df2094f0"
EXPECTED_DEV_ALGORITHM_BLOB="79c8b45901766179c7e39b17969c726a276e543d"
EXPECTED_FROZEN_PRODUCT="8d622b792b4ae58b7157fd81ee5f95d6febcfd53"
MAX_BYTES=2*1024*1024


def check(cond,reason):
    if not cond:
        raise RuntimeError("B36_UNVERIFIED_"+reason)


def git(root,*args):
    p=subprocess.run(["git","-C",str(root),*args],capture_output=True,text=True,
                     timeout=60,check=False)
    check(p.returncode==0,"GIT_"+str(args[0]).upper())
    return p.stdout.strip()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def old_changed_lines(a,b):
    left=a.splitlines()
    right=b.splitlines()
    changed=set()
    for tag,old_start,old_end,new_start,new_end in difflib.SequenceMatcher(
            None,left,right,autojunk=False).get_opcodes():
        if tag=="equal":
            continue
        changed.update(range(max(1,old_start-2),min(len(left),old_end+3)+1))
    return changed


def verify_original(case,side):
    root=UPSTREAM/case["id"]/side
    commit=case["pre"] if side=="before" else case["post"]
    check(root.is_dir(),case["id"]+"_SOURCE_MISSING_"+side)
    check(git(root,"rev-parse","HEAD")==commit,case["id"]+"_COMMIT_CHANGED_"+side)
    records=[]
    for entry in case["files"]:
        path,before_blob,after_blob=entry
        expected=before_blob if side=="before" else after_blob
        file=root/path
        check(file.is_file() and not file.is_symlink(),case["id"]+"_FILE_MISSING_"+side)
        # Compare the actual pinned Git tree object, not the *materialized*
        # checkout bytes. Worktree filters/attributes may transform bytes.
        actual_tree_blob=git(root,"rev-parse","HEAD:"+path)
        check(actual_tree_blob==expected,
              case["id"]+"_PINNED_GIT_TREE_BLOB_CHANGED_"+side+
              "_expected_"+expected+"_actual_"+actual_tree_blob)
        raw=subprocess.run(["git","-C",str(root),"cat-file","blob",expected],
                           capture_output=True,timeout=60,check=False)
        check(raw.returncode==0,case["id"]+"_ORIGINAL_GIT_BLOB_UNAVAILABLE_"+side)
        data=raw.stdout
        check(0<len(data)<=MAX_BYTES and b"\x00" not in data,
              case["id"]+"_UNSUPPORTED_SOURCE_"+side)
        try:
            decoded=data.decode("utf-8")
        except UnicodeDecodeError:
            raise RuntimeError("B36_UNVERIFIED_NON_UTF8_"+case["id"]) from None
        # Feed the scanner materialized *original Git blob bytes*, not a
        # possibly clean/smudge filtered checkout. No upstream code execution.
        rel=Path(path)
        check(not rel.is_absolute() and ".." not in rel.parts,
              case["id"]+"_UNSAFE_SELECTED_PATH")
        exact=HOLDOUT/"out"/"original_source"/case["id"]/side/rel
        exact.parent.mkdir(parents=True,exist_ok=True)
        exact.write_bytes(data)
        records.append({"path":path,"original_git_blob":expected,
                        "sha256":sha(data),"text":decoded,"local_file":exact,
                        "checkout_bytes_equal_original_git_blob":file.read_bytes()==data})
    return records


def run_frozen(cli,path):
    p=subprocess.run([str(cli),"check",str(path),"--format","json",
                      "--strict-incomplete"],capture_output=True,text=True,
                     timeout=120,check=False)
    check(p.returncode in (0,2),"FROZEN_CLI_EXIT_"+str(p.returncode))
    try:
        record=json.loads(p.stdout)
    except json.JSONDecodeError:
        raise RuntimeError("B36_UNVERIFIED_FROZEN_PRODUCT_OUTPUT") from None
    check(record.get("scope")=="LOCAL_READ_ONLY_NO_EXEC_NO_NETWORK",
          "FROZEN_PRODUCT_SCOPE")
    return {"exit":p.returncode,"status":record.get("status"),
            "parsed":record.get("summary",{}).get("python_parsed",0),
            "findings":record.get("suspected",[]),
            "unverified":record.get("unverified",[]),
            "sha256":sha(p.stdout.encode("utf-8"))}


def analyze(case,alg,cli):
    originals=verify_original(case,"before")
    repairs=verify_original(case,"after")
    records=[]
    qualifying=[]
    status="UNSUPPORTED_LANGUAGE"
    for raw,fix in zip(originals,repairs):
        p=raw["path"]
        record={"path":p,"original_blob":raw["original_git_blob"],
                "after_blob":fix["original_git_blob"],
                "before_sha256":raw["sha256"],"after_sha256":fix["sha256"],
                "source_changed":raw["sha256"]!=fix["sha256"],
                "original_mcp_execution_verified":False}
        if case["language"]!="python":
            record["decision"]="UNSUPPORTED_LANGUAGE"
            record["unsupported_reason"]="Algorithm implements Python AST only; no TypeScript/Rust parse"
            records.append(record)
            continue
        try:
            pre=alg.analyze_source(raw["text"],p)
            post=alg.analyze_source(fix["text"],p)
        except (SyntaxError,ValueError,RecursionError) as ex:
            record["decision"]="UNVERIFIED_PARSE_ERROR"
            record["parse_error_type"]=type(ex).__name__
            record["parse_error_line"]=getattr(ex,"lineno",None)
            record["parse_error_message"]=str(ex)[:180]
            records.append(record)
            status="UNVERIFIED"
            continue
        baseline_old=run_frozen(cli,raw["local_file"])
        baseline_after=run_frozen(cli,fix["local_file"])
        if baseline_old["parsed"]!=1 or baseline_after["parsed"]!=1 or (
                baseline_old["unverified"] or baseline_after["unverified"]):
            record["decision"]="UNVERIFIED_FROZEN_PRODUCT_INCOMPLETE"
            record["baseline_before"]=baseline_old
            record["baseline_after"]=baseline_after
            records.append(record)
            status="UNVERIFIED"
            continue
        changed=old_changed_lines(raw["text"],fix["text"])
        after_ids={r["rule_id"] for r in post["findings"]}
        localized=[f for f in pre["findings"] if f["line"] in changed]
        delta=[f for f in localized if f["rule_id"] not in after_ids]
        # Pair-specific verdict is source-based; never make a runtime claim.
        record.update({
          "decision":"LOCALIZED_SOURCE_HYPOTHESIS" if delta else "MISSED",
          "before_candidate_ids":[f["rule_id"] for f in pre["findings"]],
          "after_candidate_ids":[f["rule_id"] for f in post["findings"]],
          "qualifying_candidates":[{"rule_id":f["rule_id"],"line":f["line"],
                                    "source_mechanism":f["mechanism"]}
                                    for f in delta],
          "localized_count":len(localized),
          "changed_old_lines":len(changed),
          "baseline_before_status":baseline_old["status"],
          "baseline_after_status":baseline_after["status"],
          "baseline_before_candidates":len(baseline_old["findings"]),
          "baseline_after_candidates":len(baseline_after["findings"]),
          "baseline_before_output_sha256":baseline_old["sha256"],
          "baseline_after_output_sha256":baseline_after["sha256"],
          "classification":"HYPOTHESIS_NOT_PROVEN_RUNTIME_FAILURE",
        })
        if delta:
            qualifying.append(record)
        records.append(record)
        if status!="UNVERIFIED":
            status="LOCALIZED_SOURCE_HYPOTHESIS" if qualifying else "MISSED"
    # An incomplete focused file prevents a whole-case detection claim.
    if any(x["decision"].startswith("UNVERIFIED") for x in records):
        status="UNVERIFIED"
    if case["language"]=="python" and status=="UNSUPPORTED_LANGUAGE":
        status="UNVERIFIED_NO_PARSEABLE_PYTHON_FILES"
    return {"id":case["id"],"repo":case["repo"],"language":case["language"],
            "fix_pr":case["fix_pr"],"status":status,"files":records,
            "confidence":"SOURCE_HYPOTHESIS_ONLY","original_execution_verified":False}


def main():
    check(git(DEV,"rev-parse","HEAD")==EXPECTED_DEV_COMMIT,
          "DEVELOPMENT_CODE_COMMIT_MOVED")
    check(git(FROZEN,"rev-parse","HEAD")==EXPECTED_FROZEN_PRODUCT,
          "FROZEN_PUBLIC_MAIN_MOVED")
    check(git(DEV,"hash-object","research/b34_channel_projection.py")
          ==EXPECTED_DEV_ALGORITHM_BLOB,"ALGORITHM_CODE_MOVED")
    check(git(HOLDOUT,"hash-object","benchmarks/p6b36/SEALED_HOLDOUT.json")
          ==EXPECTED_MANIFEST_GIT_BLOB,"SEALED_CASES_CHANGED")
    manifest=json.loads(MANIFEST.read_text(encoding="utf-8"))
    cases=manifest["cases"]
    check(manifest["selection_phase"]=="BEFORE_SOURCE_OPENING_AND_ANY_B35_DRIVEN_RULE_CHANGES","MANIFEST_STAGE")
    check([c["id"] for c in cases]==["B36A","B36B","B36C","B36D","B36E","B36F","B36G","B36H"],
          "CASE_MEMBERSHIP_CHANGED")
    check(len({c["repo"].split("/")[0].lower() for c in cases})==8,
          "REPOSITORY_ORGANIZATIONS_NOT_DISTINCT")
    sys.path.insert(0,str(DEV/"research"))
    from b34_channel_projection import analyze_source
    from types import SimpleNamespace
    frozen_algorithm=SimpleNamespace(analyze_source=analyze_source)
    # Post-first-look mechanical data correction; the original SHA seal
    # remains unchanged in Git and was checked above before loading overlay.
    check(git(HOLDOUT,"hash-object","benchmarks/p6b36/PROVENANCE_ERRATUM.json")
          ==EXPECTED_ERRATUM_GIT_BLOB,"ERRATUM_ORIGINAL_GIT_BLOB_CHANGED")
    correction=json.loads(ERRATUM.read_text(encoding="utf-8"))
    check(correction["case_id"]=="B36D" and
          correction["before_commit"]=="7325b78af73e633978566a9d4298f5fbacb149da",
          "ERRATUM_SCOPE_CHANGED")
    correction_case=next(c for c in cases if c["id"]=="B36D")
    original_row=correction_case["files"][0]
    check(original_row[0]==correction["path"] and
          original_row[1]==correction["invalid_presealed_before_blob"] and
          len(original_row[1])!=40,
          "ERRATUM_OLD_INVALID_SHA_NOT_PROVEN")
    check(len(correction["correct_before_blob"])==40,
          "ERRATUM_CORRECT_SHA_NOT_40_CHARACTERS")
    correction_case["files"][0]=[
        original_row[0],correction["correct_before_blob"],original_row[2]
    ]
    results=[]
    for case in cases:
        try:
            results.append(analyze(case,frozen_algorithm,CLI))
        except RuntimeError as exc:
            # A single integrity failure is an UNVERIFIED preselected case,
            # never a removal or replacement; continue through every case.
            results.append({
                "id":case["id"],"repo":case["repo"],
                "language":case["language"],"fix_pr":case["fix_pr"],
                "status":"UNVERIFIED","error":str(exc),
                "files":[],"confidence":"NO_RESULT",
                "original_execution_verified":False,
            })
    python=[r for r in results if r["language"]=="python"]
    eligible=[r for r in python if r["status"] in ("LOCALIZED_SOURCE_HYPOTHESIS","MISSED")]
    hits=[r for r in eligible if r["status"]=="LOCALIZED_SOURCE_HYPOTHESIS"]
    misses=[r for r in eligible if r["status"]=="MISSED"]
    incomplete=[r for r in python if r not in eligible]
    unsupported=[r for r in results if r["status"]=="UNSUPPORTED_LANGUAGE"]
    summary={
      "preselected_external_cases":len(cases),
      "upstream_orgs":len({c["repo"].split("/")[0].lower() for c in cases}),
      "python_primary_preselected":len(python),
      "python_eligible":len(eligible),
      "python_localized_hypotheses":len(hits),
      "python_missed":len(misses),
      "python_incomplete_or_unverified":len(incomplete),
      "typescript_rust_explicit_unsupported":len(unsupported),
      "original_external_mcp_runtime_reproductions":0,
      "independently_validated_normal_control_fpr":"UNMEASURED",
      "postfix_files_examined":sum(len(c["files"]) for c in results),
      "all_B34_B35_development_repos_excluded":True,
      "algorithm_unchanged_since_B34_training":True,
    }
    out={
      "schema":"risu-p6b36-provenance-corrected-supplement-v1",
      "original_seal_git_blob":EXPECTED_MANIFEST_GIT_BLOB,
      "frozen_public_main":EXPECTED_FROZEN_PRODUCT,
      "frozen_dev_commit":EXPECTED_DEV_COMMIT,
      "frozen_dev_algorithm_git_blob":EXPECTED_DEV_ALGORITHM_BLOB,
      "source_only_no_upstream_execution":True,
      "original_first_look_result_sha256":correction["primary_first_look_result_sha256"],
      "post_first_look_erratum_applied":True,
      "erratum_git_blob":EXPECTED_ERRATUM_GIT_BLOB,
      "original_sealed_manifest_left_unchanged":True,
      "no_claim_of_runtime_defect_confirmation":True,
      "summary":summary,
      "cases":results,
    }
    dest=HOLDOUT/"out"
    dest.mkdir(exist_ok=True)
    fname=dest/"B36_SUPPLEMENTAL_RESULTS.json"
    fname.write_text(json.dumps(out,sort_keys=True,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    lines=["# B36 post-first-look provenance-corrected supplement, original seal unchanged","",
           "Only source-level hypotheses, not independently reproduced MCP wire failures.",
           "Frozen algorithm "+EXPECTED_DEV_COMMIT+"; public baseline "+EXPECTED_FROZEN_PRODUCT,
           "", "| Case | Org | Language | Result |", "|---|---|---|---|"]
    for x in results:
        lines.append("| "+x["id"]+" | "+x["repo"]+" | "+x["language"]+" | "+x["status"]+" |")
    lines.extend(["", "Primary Python eligible: "+str(len(eligible))+
                  "; localized source hypotheses: "+str(len(hits))+
                  "; missed: "+str(len(misses))+
                  "; incomplete: "+str(len(incomplete))+".",
                  "Cross-language unsupported: "+str(len(unsupported))+".",
                  "No original MCP runtimes executed and no population FPR inferred."])
    (dest/"B36_SUPPLEMENTAL_REPORT.md").write_text("\n".join(lines)+"\n",encoding="utf-8")
    print(json.dumps(summary,sort_keys=True))
    print("B36_SUPPLEMENTAL_ERRATUM_UNCHANGED_ALGORITHM")
    return 0

if __name__=="__main__":
    CLI=Path(sys.argv[1]).resolve()
    raise SystemExit(main())
