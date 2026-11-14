#!/usr/bin/env python3
"""Read-only integrity audit of preregistered B39 external original Git objects.

Does not import or execute foreign files, contact remote endpoints, or
run any original tools. Missing original source does not disappear from n.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import subprocess

BASE=Path(__file__).resolve().parents[2]
MANIFEST=BASE/"benchmarks/p6b39/SEALED_COHORT.json"
EXPECTED_SEALED_BLOB="25b59a910fa71015ed2f1eb3e592db42f05f8aaf"
MAX=3*1024*1024
IDS=["P1","P2","P3","P4","N1","N2","N3","N4"]

def git(repo,*args,strict=True):
    x=subprocess.run(["git","-C",str(repo),*args],capture_output=True,
                     timeout=55,check=False)
    if strict and x.returncode:
        raise ValueError("B39_GIT_OP_FAILED_"+str(args[0]))
    return x

def sha(b):
    return hashlib.sha256(b).hexdigest()

def attest(case,side,path,expected):
    orig=BASE/"original"/case["id"]/side
    commit=case["pre"] if side=="before" else case["post"]
    if not orig.is_dir():
        raise ValueError("ORIGINAL_CHECKOUT_MISSING")
    if git(orig,"rev-parse","HEAD").stdout.decode().strip()!=commit:
        raise ValueError("WRONG_ORIGINAL_UPSTREAM_COMMIT")
    pointer=git(orig,"rev-parse","HEAD:"+path,strict=False)
    if expected is None:
        if pointer.returncode==0:
            raise ValueError("EXPECTED_NEW_FILE_ALREADY_PRESENT_IN_PARENT")
        return {"state":"ABSENT_AS_PREREGISTERED","commit":commit,
                "path":path,"original_external_executed":False}
    if pointer.returncode!=0:
        raise ValueError("PINNED_FILE_NOT_IN_TREE")
    blob=pointer.stdout.decode().strip()
    if blob!=expected:
        raise ValueError("PINNED_TREE_BLOB_SHA_MISMATCH")
    raw=git(orig,"cat-file","blob",blob).stdout
    if not(0<len(raw)<MAX) or b"\x00" in raw:
        raise ValueError("BINARY_OR_OVERSIZE_ORIGINAL")
    if git(orig,"hash-object","--stdin",strict=False).returncode!=0:
        # A known no-stdin check is not counted as source evidence.
        pass
    return {"state":"ORIGINAL_GIT_BLOB_VERIFIED","commit":commit,
            "git_blob":blob,"bytes":len(raw),"raw_sha256":sha(raw),
            "utf8_decodable":is_utf8(raw),"original_external_executed":False}

def is_utf8(b):
    try:b.decode("utf-8");return True
    except UnicodeError:return False

def main():
    blob=git(BASE,"hash-object","benchmarks/p6b39/SEALED_COHORT.json").stdout.decode().strip()
    if blob!=EXPECTED_SEALED_BLOB:
        raise RuntimeError("B39_SEALED_HOLDOUT_CHANGED_AFTER_SELECTING_CASES")
    data=json.loads(MANIFEST.read_text(encoding="utf-8"))
    cases=data["cases"]
    if [c["id"] for c in cases]!=IDS:
        raise RuntimeError("B39_CASES_CHANGED_OR_REORDERED")
    if len({c["repo"].split("/")[0].lower() for c in cases})!=8:
        raise RuntimeError("B39_NONINDEPENDENT_ORGANIZATIONS")
    out=[]
    errors=[]
    for c in cases:
        files=[]
        for path,pre,post in c["files"]:
            result={"path":path}
            for side,expected in (("before",pre),("after",post)):
                try:
                    result[side]=attest(c,side,path,expected)
                except (ValueError,OSError,UnicodeError) as exc:
                    errors.append({"id":c["id"],"path":path,"side":side,"reason":str(exc)})
                    result[side]={"state":"UNVERIFIED","reason":str(exc)}
            files.append(result)
        out.append({"case_id":c["id"],"repo":c["repo"],"group":c["group"],
                    "source_originals_verified":all(
                        v[side]["state"] in ("ABSENT_AS_PREREGISTERED",
                                             "ORIGINAL_GIT_BLOB_VERIFIED")
                        for v in files for side in ("before","after")),
                    "files":files})
    summary={"organizations_preregistered":8,"positive_organizations":4,
             "normal_policy_organizations":4,
             "original_file_entries":sum(len(c["files"]) for c in cases),
             "verified_file_entries":sum(x["source_originals_verified"] for x in out),
             "original_source_entries_verified":sum(
                 1 for x in out for f in x["files"] if
                 f["before"]["state"] in ("ABSENT_AS_PREREGISTERED",
                                         "ORIGINAL_GIT_BLOB_VERIFIED") and
                 f["after"]["state"]=="ORIGINAL_GIT_BLOB_VERIFIED"),
             "integrity_errors":len(errors),"original_code_executed":False,
             "positive_runtime_recall":"NOT_EVALUATED",
             "independent_normal_false_alarm_rate":"NOT_EVALUATED"}
    dest=BASE/"out"
    dest.mkdir(exist_ok=True)
    file=dest/"B39_ORIGINAL_GIT_INTEGRITY.json"
    file.write_text(json.dumps({"schema":"p6b39-original-source-integrity-v1",
                                "manifest_git_blob":EXPECTED_SEALED_BLOB,
                                "summary":summary,"cases":out,"errors":errors},
                               sort_keys=True,indent=2,ensure_ascii=False)+"\n")
    print(json.dumps(summary,sort_keys=True))
    if errors:
        print("B39_ORIGINAL_HOLDOUT_INTEGRITY_UNVERIFIED_WITH_VISIBLE_FAILURES")
        raise SystemExit(2)
    print("B39_ALL_ORIGINAL_GIT_TREE_BLOBS_VERIFIED_NO_EXTERNAL_CODE_EXECUTED")
if __name__=="__main__":
    main()
