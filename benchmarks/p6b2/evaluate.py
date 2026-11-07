"""P6-B2 independent holdout. Static-only scans; no execution of fetched source."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ALLOWED = {"modelcontextprotocol/python-sdk", "PrefectHQ/fastmcp", "modelcontextprotocol/typescript-sdk"}
LABELS = {"known_defect", "official_fixed", "normal_control", "withdrawn_report", "unsupported"}
SHA40 = re.compile(r"^[0-9a-f]{40}$")
# No matching new issue-specific rules exist in the frozen 0.9.21 candidate.
# Rules RPY201..RPY204 target different causal mechanisms. Unrelated warnings are not TPs.
ISSUE_MATCHED_RULES = {
    "BOOL_PROPERTY_SCHEMA": frozenset(),
    "RECURSIVE_SCHEMA_ROOT": frozenset(),
    "MIDDLEWARE_RESULT_DISCARDED": frozenset(),
    "CLIENT_CACHE_TOOL_METADATA": frozenset(),
}

def git_blob(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()

def run_git(cwd: Path, *args: str) -> bytes:
    cmd = ["git", "-c", "core.hooksPath=/dev/null", *args]
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1",
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
    p = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, timeout=180)
    if p.returncode:
        raise RuntimeError("Public source fetch failure: " + p.stderr.decode("utf-8", "replace")[-450:])
    return p.stdout

def freeze_check(manifest: dict) -> None:
    assert manifest["schema"] == "risu-p6b2-independent-holdout-v1"
    assert manifest["source_product_commit"] == "89db4b12a05e51fae475710133e254191c90657f"
    assert manifest["counts"] == {"known_defect":2, "official_fixed":2,
                                    "normal_control":1, "withdrawn_report":1,"unsupported":1}
    cases = manifest["cases"]
    assert len(cases) == 7 and len({c["id"] for c in cases}) == 7
    assert {c["id"] for c in cases} == {"M3353-old","M3353-fixed","M3337-old",
        "M3337-fixed","M3353-modern-control","F3590-withdrawn","TS2614-unsupported"}
    for c in cases:
        assert c["repo"] in ALLOWED and c["label"] in LABELS
        assert SHA40.fullmatch(c["commit"]) and SHA40.fullmatch(c["git_blob"])
        assert c["family"] in ISSUE_MATCHED_RULES
        src = Path(c["path"])
        assert not src.is_absolute() and ".." not in src.parts and len(src.parts) <= 12
        assert src.suffix in {".py",".ts"}
    assert {c["family"] for c in cases if c["label"]=="known_defect"} == {
        "BOOL_PROPERTY_SCHEMA","RECURSIVE_SCHEMA_ROOT"}
    assert {c["issue"] for c in cases if c["label"]=="known_defect"} == {
        "https://github.com/modelcontextprotocol/python-sdk/issues/3353",
        "https://github.com/modelcontextprotocol/python-sdk/issues/3337"}

def materialize(manifest: dict, root: Path) -> list[tuple[dict,Path]]:
    root.mkdir(parents=True, exist_ok=False)
    repos: dict[str, Path] = {}
    result=[]
    for c in manifest["cases"]:
        name = c["repo"]
        if name not in repos:
            dirname = root/("source-"+str(len(repos)))
            dirname.mkdir()
            run_git(dirname, "init","-q")
            run_git(dirname,"remote","add","origin", "https://github.com/"+name+".git")
            repos[name] = dirname
        original = repos[name]
        run_git(original,"fetch","--no-tags","--depth","1","origin",c["commit"])
        raw = run_git(original,"show",c["commit"]+":"+c["path"])
        if len(raw) > 300_000 or git_blob(raw) != c["git_blob"]:
            raise ValueError("Pinned original blob mismatch: "+c["id"])
        out = root/("case-"+c["id"])/("original"+Path(c["path"]).suffix)
        out.parent.mkdir()
        out.write_bytes(raw)
        result.append((c,out))
    return result

def execute(cli: Path, source: Path, unsupported: bool) -> dict:
    if unsupported:
        return {"status":"UNSUPPORTED_LANGUAGE","parsed":0,"unverified":1,
                "finding_count":0,"findings":[],"returncode":None}
    p = subprocess.run([str(cli),"check",str(source),"--format","json"],
        capture_output=True, timeout=90, env={**os.environ,"PYTHONUTF8":"1",
        "PYTHONDONTWRITEBYTECODE":"1"})
    if p.returncode not in (0,1,2):
        raise ValueError("RISU execution failure: "+p.stderr.decode(errors="replace")[-300:])
    v=json.loads(p.stdout)
    summ=v.get("summary",{})
    parsed=summ.get("python_parsed",0)
    unknown=summ.get("unverified",0)
    findings=[{"rule_id":f.get("rule_id"),"line":f.get("line"),
               "code":f.get("code"),"verdict":f.get("verdict")}
              for f in v.get("suspected",[])]
    if parsed != 1 or unknown != 0:
        status="UNVERIFIED_SOURCE"
    else:
        status="STATIC_WARNINGS" if findings else "NO_STATIC_FINDINGS"
    return {"status":status,"parsed":parsed,"unverified":unknown,
            "finding_count":len(findings),"findings":findings,"returncode":p.returncode,
            "raw_report_sha256":hashlib.sha256(p.stdout).hexdigest()}

def calculate(rows: list[dict]) -> dict:
    positives=[r for r in rows if r["label"]=="known_defect"]
    repairs=[r for r in rows if r["label"]=="official_fixed"]
    controls=[r for r in rows if r["label"]=="normal_control"]
    withdrawn=[r for r in rows if r["label"]=="withdrawn_report"]
    unsupported=[r for r in rows if r["label"]=="unsupported"]
    assert (len(positives),len(repairs),len(controls),len(withdrawn),len(unsupported))==(2,2,1,1,1)
    for r in rows:
        if r["label"] != "unsupported" and r["scan"]["parsed"]!=1:
            raise RuntimeError("Partial parse: "+r["id"])
    detections=sum(r["issue_matched_detection"] for r in positives)
    false_match=sum(r["issue_matched_detection"] for r in repairs+controls+withdrawn)
    return {
        "independent_known_defects":len(positives),
        "issue_matched_true_positive":detections,
        "issue_matched_false_negative":len(positives)-detections,
        "holdout_recall":round(detections/len(positives),3),
        "official_fixes":len(repairs),"normal_protocol_controls":len(controls),
        "withdrawn_issue_controls":len(withdrawn),
        "issue_matched_false_alarm":false_match,
        "issue_matched_false_alarm_denominator":len(repairs+controls+withdrawn),
        "unreviewed_ancillary_warning_count":sum(r["scan"]["finding_count"] for r in rows if r["label"] in ("official_fixed","normal_control","withdrawn_report")),
        "in_scope_incomplete_parses":sum(r["scan"]["status"]=="UNVERIFIED_SOURCE" for r in rows),
        "semantic_assurance_absent":sum(not r["issue_specific_capability"] for r in positives),
        "unsupported_excluded":len(unsupported),
        "precision":None if detections+false_match==0 else round(detections/(detections+false_match),3),
        "scope_note":"2 independent official defects, narrow issue-matched metrics; not ecosystem recall or validated false-positive prevalence"
    }

def main() -> None:
    ap=argparse.ArgumentParser()
    ap.add_argument("--manifest",type=Path,required=True)
    ap.add_argument("--cli",type=Path,required=True)
    ap.add_argument("--scratch",type=Path,required=True)
    ap.add_argument("--out",type=Path,required=True)
    args=ap.parse_args()
    raw=args.manifest.read_bytes()
    manifest=json.loads(raw)
    freeze_check(manifest)
    paths=materialize(manifest,args.scratch)
    rows=[]
    for case,path in paths:
        scan=execute(args.cli,path,case["label"]=="unsupported")
        rules=ISSUE_MATCHED_RULES[case["family"]]
        row={key:case[key] for key in ("id","issue","repo","commit","git_blob","path","label","family","split")}
        row["source_sha256"]=hashlib.sha256(path.read_bytes()).hexdigest()
        row["scan"]=scan
        row["issue_specific_capability"]=bool(rules)
        row["issue_matched_detection"]=any(f["rule_id"] in rules for f in scan["findings"])
        row["issue_status"]=("UNSUPPORTED" if case["label"]=="unsupported" else
            "DETECTED" if row["issue_matched_detection"] else "NOT_DETECTED_WITHOUT_ISSUE_RULE")
        rows.append(row)
        print("P6B2_FROZEN",case["id"],scan["status"],row["issue_status"],flush=True)
    scores=calculate(rows)
    result={"schema":"risu-p6b2-frozen-independent-audit-v1",
            "manifest_sha256":hashlib.sha256(raw).hexdigest(),
            "product_source_commit":manifest["source_product_commit"],
            "target_source_executed":False,
            "raw_production_api_called":False,
            "results":rows,"metrics":scores}
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(result,ensure_ascii=False,sort_keys=True,indent=2)+"\n")
    print("P6B2_INDEPENDENT_SCORE",json.dumps(scores,sort_keys=True),flush=True)

if __name__=="__main__":
    main()
