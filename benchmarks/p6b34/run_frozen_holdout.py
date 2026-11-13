#!/usr/bin/env python3
"""B34 blinded, frozen-product, external original-source audit.

This script is an EVALUATOR. It never imports third-party source, changes the
published RISU detector, runs a third-party service, or manufactures a witness.
"""
from __future__ import annotations

import difflib
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
MANIFEST=ROOT/"benchmarks/p6b34/LOCKED_HOLDOUT.json"
SAFE_ID={"H1","H2","H3","H4","H5"}
FROZEN="8d622b792b4ae58b7157fd81ee5f95d6febcfd53"

def run(argv, cwd=None):
    result=subprocess.run(argv,cwd=cwd,capture_output=True,text=True,
                          timeout=240,check=False)
    return result

def require(test,reason):
    if not test:
        raise RuntimeError(reason)

def changed_old_lines(before,after):
    """Only original source lines in edited hunks (+2 lines around insertions)."""
    lhs=before.splitlines()
    rhs=after.splitlines()
    matcher=difflib.SequenceMatcher(a=lhs,b=rhs,autojunk=False)
    ranges=set()
    for tag,i1,i2,j1,j2 in matcher.get_opcodes():
        if tag=="equal":
            continue
        ranges.update(range(max(1,i1-1), min(len(lhs),i2+2)+1))
    return ranges

def payload_hash(data):
    return hashlib.sha256(data).hexdigest()

def source_manifest(case,side):
    path=ROOT/"upstream"/case["id"]/side
    expected=case["pre"] if side=="before" else case["post"]
    return path,expected

def verify_source(case,side):
    tree,sha=source_manifest(case,side)
    p=tree/case["source_path"]
    require(p.is_file() and not p.is_symlink(),
            f"{case['id']} {side}: pinned real source file missing")
    commit=run(["git","-C",str(tree),"rev-parse","HEAD"])
    require(commit.returncode==0 and commit.stdout.strip()==sha,
            f"{case['id']} {side}: immutable original commit mismatch")
    blob=run(["git","-C",str(tree),"hash-object",case["source_path"]])
    expected=case["pre_git_blob"] if side=="before" else case["post_git_blob"]
    require(blob.returncode==0 and blob.stdout.strip()==expected,
            f"{case['id']} {side}: Git original source blob mismatch")
    data=p.read_bytes()
    require(len(data)>0 and b"\x00" not in data,
            f"{case['id']} {side}: unexpected binary source")
    return {"root":tree,"path":p,"commit":sha,"git_blob":expected,
            "byte_sha256":payload_hash(data),"source_bytes":data}

def get_scan(cli,case,side,source):
    result=run([str(cli),"check",str(source["root"]),
                "--format","json","--strict-incomplete"])
    require(result.returncode in (0,2),
            f"{case['id']} {side}: unexpected CLI exit {result.returncode}: {result.stderr[-300:]}")
    try:
        obj=json.loads(result.stdout)
    except (ValueError,TypeError) as exc:
        raise RuntimeError(f"{case['id']} {side}: no valid JSON from frozen CLI: {result.stderr[-200:]}") from exc
    require(type(obj) is dict and obj.get("command")=="check",
            f"{case['id']} {side}: invalid detector record")
    require(obj.get("scope")=="LOCAL_READ_ONLY_NO_EXEC_NO_NETWORK",
            f"{case['id']} {side}: target execution / side effects not allowed")
    return {"exit":result.returncode,"status":obj.get("status"),
            "parsed":obj.get("summary",{}).get("python_parsed",0),
            "total_static_candidates":len(obj.get("suspected",[])),
            "suspected":obj.get("suspected",[]),
            "incomplete":obj.get("unverified",[]),
            "confirmed_saved_replay":len(obj.get("confirmed",[])),
            "stdout_sha256":payload_hash(result.stdout.encode()),
            "full_report":obj}

def summarize(cases):
    out=[]
    for case in cases:
        original=verify_source(case,"before")
        fixed=verify_source(case,"after")
        before=get_scan(CLI,case,"before",original)
        after=get_scan(CLI,case,"after",fixed)
        changed=changed_old_lines(original["source_bytes"].decode("utf-8"),
                                  fixed["source_bytes"].decode("utf-8"))
        usable=(before["parsed"]>=1 and after["parsed"]>=1 and
                not before["incomplete"] and not after["incomplete"])
        orig_findings=before["suspected"]
        fixed_findings=after["suspected"]
        # Original source line numbers, matched solely to upstream fix hunks.
        localized=[f for f in orig_findings if f.get("path")==case["source_path"] and
                   type(f.get("line")) is int and f["line"] in changed]
        fixed_ids={(f.get("rule_id"),f.get("code")) for f in fixed_findings}
        differential=[f for f in localized
                      if (f.get("rule_id"),f.get("code")) not in fixed_ids]
        if not usable: decision="INCOMPLETE_OR_UNSUPPORTED"
        elif differential: decision="LOCALIZED_STATIC_CANDIDATE"
        else: decision="MISSED"
        out.append({
            "id":case["id"],"upstream_repo":case["repo"],
            "upstream_issue":case["issue"],"upstream_fix":case["fix_pr"],
            "source_path":case["source_path"],"org_cluster":case["org_cluster"],
            "expected_defect":case["mechanism"],
            "before_source_commit":case["pre"],"after_source_commit":case["post"],
            "before_source_sha256":original["byte_sha256"],
            "after_source_sha256":fixed["byte_sha256"],
            "source_sha_changes":original["byte_sha256"]!=fixed["byte_sha256"],
            "before_result_sha256":before["stdout_sha256"],
            "after_result_sha256":after["stdout_sha256"],
            "before_status":before["status"],"after_status":after["status"],
            "before_parsed":before["parsed"],"after_parsed":after["parsed"],
            "before_total_static_candidates":before["total_static_candidates"],
            "after_total_static_candidates":after["total_static_candidates"],
            "before_rule_ids":[x.get("rule_id") for x in orig_findings],
            "after_rule_ids":[x.get("rule_id") for x in fixed_findings],
            "changed_line_count":len(changed),
            "localized_pre_fix_findings":[{"rule_id":f["rule_id"],
                                         "path":f["path"],"line":f["line"]}
                                         for f in localized],
            "localized_differential_findings":[{"rule_id":f["rule_id"],
                                                "line":f["line"]}
                                                for f in differential],
            "before_unverified":before["incomplete"],
            "after_unverified":after["incomplete"],
            "frozen_product_decision":decision,
            "original_runtime_reproduced":False,
            "independent_external_native_protocol_witness":False,
            "negative_control":"official upstream post-fix source only",
            "full_before_report":before["full_report"],
            "full_after_report":after["full_report"],
        })
    return out

def main():
    manifest=json.loads(MANIFEST.read_text(encoding="utf-8"))
    require(manifest["frozen_product_sha"]==FROZEN,"frozen product SHA mismatch")
    cases=manifest["cases"]
    require([x["id"] for x in cases]==["H1","H2","H3","H4","H5"],
            "candidate membership or order changed")
    root=ROOT/"out"
    root.mkdir(exist_ok=True)
    records=summarize(cases)
    usable=[r for r in records if r["frozen_product_decision"]!="INCOMPLETE_OR_UNSUPPORTED"]
    positives=[r for r in usable if r["frozen_product_decision"]=="LOCALIZED_STATIC_CANDIDATE"]
    missed=[r for r in usable if r["frozen_product_decision"]=="MISSED"]
    incomplete=[r for r in records if r not in usable]
    report={
        "schema":"risu-p6b34-frozen-external-holdout-results-v1",
        "frozen_product_sha":FROZEN,
        "evaluator_prereg_sha":manifest["prereg_commit"],
        "locked_external_manifest_sha256":payload_hash(MANIFEST.read_bytes()),
        "no_rules_changed":True,
        "third_party_code_executed":False,
        "source_scope":"single upstream changed Python source file per case, checked out at each immutable original commit; NOT full repository scan",
        "result_kind":"OFFLINE_STATIC_ONLY_NOT_RUNTIME_DEFECT_PROOF",
        "five_cases_three_independent_organizations":True,
        "cases":records,
        "summary":{
          "candidate_preselected":len(cases),
          "eligible_with_parsed_source_and_complete_output":len(usable),
          "localized_static_before_fix_only":len(positives),
          "missed":len(missed),
          "incomplete_or_unsupported":len(incomplete),
          "fixed_source_sibling_controls_examined":sum(r["after_parsed"]>=1 for r in records),
          "all_after_fix_static_candidates":sum(r["after_total_static_candidates"] for r in records),
          "genuine_original_runtime_verification_count":0,
          "external_repositories":len(set(r["upstream_repo"] for r in records)),
          "external_maintainer_organizations":len(set(r["org_cluster"] for r in records)),
          "unmeasured":"population false-positive rate and runtime semantic detection; 5 fixed-file controls alone cannot estimate these rates"
        }
    }
    result_path=root/"B34_FROZEN_BASELINE_RESULTS.json"
    result_path.write_text(json.dumps(report,indent=2,sort_keys=True,ensure_ascii=False)+"\n",encoding="utf-8")
    summary=report["summary"]
    lines=["# RISU P6-B34 | Pre-registered external holdout baseline verdict","",
           f"- Frozen public commit: `{FROZEN}`",
           f"- Explicit preselected independent cases: {summary['candidate_preselected']} in {summary['external_maintainer_organizations']} external organizations",
           f"- Successfully parsed focused Python source: {summary['eligible_with_parsed_source_and_complete_output']}",
           f"- Localized pre-fix-only STATIC candidates: {summary['localized_static_before_fix_only']}",
           f"- Missed: {summary['missed']}",
           f"- Incomplete/unsupported: {summary['incomplete_or_unsupported']}",
           f"- Post-fix source controls examined: {summary['fixed_source_sibling_controls_examined']}",
           "- Genuine original MCP execution confirmed in this audit: 0",
           "- Population FPR: UNMEASURED (not zero)", "",
           "| Case | Upstream | Before | Fixed | Decision |",
           "|---|---|---:|---:|---|"]
    for r in records:
        lines.append(f"| {r['id']} | {r['upstream_repo']} | {r['before_total_static_candidates']} | {r['after_total_static_candidates']} | {r['frozen_product_decision']} |")
    lines.extend(["","**Interpretation:** STATIC findings are hypotheses only. No third-party source was executed; the exact upstream source files were parsed read-only. The wider repositories were intentionally not scanned, so no full-repository detection claim follows. Five defect instances include three correlated bugs from the same official SDK. A miss is evidence about the CURRENT frozen CLI, not about all historical RISU prototype algorithms.",""])
    (root/"B34_FROZEN_BASELINE_REPORT.md").write_text("\n".join(lines),encoding="utf-8")
    print(json.dumps(summary,sort_keys=True))
    print("B34_FIXED_PUBLIC_PRODUCT_BLINDED_AUDIT_FINISHED")
    return 0

if __name__=="__main__":
    CLI=Path(sys.argv[1]).resolve()
    raise SystemExit(main())
