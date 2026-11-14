#!/usr/bin/env python3
"""B38 sealed first original-source integrity pass, NO upstream source execution."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]
MANIFEST=ROOT/"benchmarks"/"p6b38"/"SEALED_HOLDOUT.json"
PIN="b72a240999de701282f9b583f11755e6ae844ae1"
MAX=2*1024*1024

def git(root,*args):
    r=subprocess.run(["git","-C",str(root),*args],capture_output=True,
                     text=True,timeout=50,check=False)
    if r.returncode:
        raise RuntimeError("B38_ORIGINAL_GIT_ERROR_"+str(args[0]))
    return r.stdout.strip()

def evidence(case,side,path,blob):
    root=ROOT/"upstream"/case["id"]/side
    original=case["pre"] if side=="before" else case["post"]
    if not root.is_dir():
        raise RuntimeError("B38_ORIGINAL_MISSING_CHECKOUT_"+case["id"]+side)
    if git(root,"rev-parse","HEAD")!=original:
        raise RuntimeError("B38_ORIGINAL_WRONG_COMMIT_"+case["id"]+side)
    if len(blob)!=40 or git(root,"rev-parse","HEAD:"+path)!=blob:
        raise RuntimeError("B38_ORIGINAL_WRONG_TREE_BLOB_"+case["id"]+side)
    p=subprocess.run(["git","-C",str(root),"cat-file","blob",blob],
                     capture_output=True,timeout=50,check=False)
    if p.returncode or not (0<len(p.stdout)<=MAX) or b"\x00" in p.stdout:
        raise RuntimeError("B38_ORIGINAL_BLOB_BYTES_UNAVAILABLE_"+case["id"]+side)
    return {"side":side,"commit":original,"git_blob":blob,
            "sha256":hashlib.sha256(p.stdout).hexdigest(),
            "bytes":len(p.stdout),"utf8":is_utf8(p.stdout)}

def is_utf8(b):
    try:
        b.decode("utf-8")
        return True
    except UnicodeError:
        return False

def main():
    if git(ROOT,"hash-object","benchmarks/p6b38/SEALED_HOLDOUT.json")!=PIN:
        raise RuntimeError("B38_ORIGINAL_SEALED_MANIFEST_CHANGED")
    m=json.loads(MANIFEST.read_text())
    cases=m["cases"]
    if [c["id"] for c in cases]!=["B38A","B38B","B38C","B38D",
                                   "B38E","B38F","B38G","B38H"]:
        raise RuntimeError("B38_ORIGINAL_CASE_LIST_CHANGED")
    if len({c["repo"].split("/")[0].lower() for c in cases})!=8:
        raise RuntimeError("B38_ORIGINAL_ORGANIZATIONS_OVERLAP")
    output=[]
    errors=[]
    for case in cases:
        files=[]
        for path,pre,post in case["files"]:
            try:
                files.append({
                    "path":path,
                    "before":evidence(case,"before",path,pre),
                    "after":evidence(case,"after",path,post),
                })
            except RuntimeError as ex:
                errors.append({"id":case["id"],"path":path,"reason":str(ex)})
        output.append({
            "id":case["id"],"repo":case["repo"],
            "fix_pr":case["fix_pr"],"type":case["type"],
            "original_upstream_code_executed":False,
            "files":files,
            "status":"ORIGINAL_SOURCES_VERIFIED" if
            len(files)==len(case["files"]) else "UNVERIFIED",
        })
    summary={
        "sealed_external_organizations":8,
        "preselected_cases":8,
        "original_git_file_pairs":sum(len(c["files"]) for c in cases),
        "source_pairs_verified":sum(len(c["files"]) for c in output),
        "source_pair_errors":len(errors),
        "original_external_code_executed":False,
        "original_wire_evidence_collected":False,
        "independent_runtime_recall":"NOT_YET_TESTED",
    }
    report={"schema":"risu-b38-source-seal-audit-v1",
            "manifest_git_blob":PIN,
            "summary":summary,"cases":output,"errors":errors}
    dest=ROOT/"out"
    dest.mkdir(exist_ok=True)
    (dest/"B38_ORIGINAL_SOURCE_INTEGRITY.json").write_text(
        json.dumps(report,sort_keys=True,indent=2,ensure_ascii=False)+"\n")
    print(json.dumps(summary,sort_keys=True))
    if errors:
        print("B38_ORIGINAL_SOURCE_BLOBS_INCOMPLETE")
        raise SystemExit(3)
    print("B38_ALL_EIGHT_ORIGINAL_REPAIR_GIT_BLOBS_VERIFIED_NO_FOREIGN_EXECUTION")
if __name__=="__main__":
    main()
