"""B31: verify GitHub/Sigstore release attestation using official gh cryptography.

Cryptographic verification occurs ONLY through a fresh official GitHub CLI
attestation verify subprocess. JSON is a downstream policy input, never
a substitute for actual signature/trust-root verification. Signed build
provenance is not independent resource-owner consent.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

SCHEMA="risu-p6b31-source-verified-signed-artifact-claim-separation-v1"
PREDICATE="https://slsa.dev/provenance/v1"
STATEMENT="https://in-toto.io/Statement/v1"
REPO=re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
FILENAME=re.compile(r"^[A-Za-z0-9_.-]{1,200}$")
SHA256=re.compile(r"^[0-9a-f]{64}$")
WORKFLOW=re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml$")
SOURCE_REF=re.compile(r"^refs/(heads|tags)/[A-Za-z0-9_./-]+$")
MAX_RESULTS=3_000_000

class Refused(Exception):
    pass

def require(ok,code):
    if not ok:raise Refused(code)

def digest(path):
    h=hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda:f.read(1024*1024),b""):
            h.update(block)
    return h.hexdigest()

def safe_json(raw):
    def pairs(items):
        out={}
        for k,v in items:
            if k in out:raise Refused("DUPLICATE_VERIFICATION_JSON_KEY")
            out[k]=v
        return out
    def nonfinite(x):
        raise Refused("NONFINITE_VERIFICATION_JSON")
    try:return json.loads(raw,object_pairs_hook=pairs,parse_constant=nonfinite)
    except (UnicodeError,ValueError,RecursionError):
        raise Refused("MALFORMED_OFFICIAL_VERIFIER_JSON")

def preflight(file_path,repo,filename,signer_workflow,source_ref,expected_digest):
    path=Path(file_path)
    require(path.is_file() and not path.is_symlink(),"ARTIFACT_MISSING_OR_SYMLINK")
    require(path.stat().st_size>0,"ARTIFACT_EMPTY")
    require(type(repo) is str and REPO.fullmatch(repo) is not None and
            all(part not in (".","..") and not part.startswith("-") for part in repo.split("/")),
            "REPO_IDENTITY_INVALID")
    require(type(filename) is str and FILENAME.fullmatch(filename) is not None,
            "SIGNED_SUBJECT_FILENAME_INVALID")
    require(path.name==filename,"SIGNED_SUBJECT_FILENAME_MISMATCH")
    require(type(signer_workflow) is str and
            WORKFLOW.fullmatch(signer_workflow) is not None and
            signer_workflow.startswith(repo+"/"),
            "EXPECTED_SIGNER_WORKFLOW_MISMATCH")
    require(type(source_ref) is str and SOURCE_REF.fullmatch(source_ref) is not None and
            ".." not in source_ref,"EXPECTED_SOURCE_REF_INVALID")
    require(type(expected_digest) is str and SHA256.fullmatch(expected_digest) is not None,
            "PINNED_EXPECTED_SHA256_MISSING")
    actual=digest(path)
    require(actual==expected_digest,"ORIGINAL_SIGNED_ASSET_BYTES_CHANGED")
    return path,actual

def validate_crypto_verified_output(data,repo,filename,signer_workflow,source_ref,actual):
    # Only use after real gh attestation verify succeeded with exact inputs.
    require(type(data) is list and 1<=len(data)<=30,
            "OFFICIAL_VERIFIER_RETURNED_NO_VERIFIED_ATTESTATION")
    matches=[]
    for result in data:
        require(type(result) is dict and type(result.get("verificationResult")) is dict,
                "MALFORMED_VERIFICATION_RESULT")
        verified=result["verificationResult"]
        statement=verified.get("statement")
        require(type(statement) is dict and
                statement.get("_type")==STATEMENT and
                statement.get("predicateType")==PREDICATE,
                "ATTESTATION_PREDICATE_NOT_SLSA_V1")
        subjects=statement.get("subject")
        require(type(subjects) is list and subjects and len(subjects)<=100,
                "ATTESTATION_SUBJECT_SET_INVALID")
        predicate=statement.get("predicate")
        require(type(predicate) is dict,"SLSA_PREDICATE_MISSING")
        build=predicate.get("buildDefinition")
        params=build.get("externalParameters") if type(build) is dict else None
        workflow=params.get("workflow") if type(params) is dict else None
        require(type(workflow) is dict and
                workflow.get("repository")=="https://github.com/"+repo and
                workflow.get("path")==signer_workflow[len(repo)+1:] and
                workflow.get("ref")==source_ref,
                "ATTESTED_SOURCE_REPO_WORKFLOW_REF_MISMATCH")
        verified_time=verified.get("verifiedTimestamps")
        require(type(verified_time) is list and len(verified_time)>0,
                "CRYPTO_VERIFIED_TIMESTAMP_MISSING")
        signed=verified.get("signature")
        require(type(signed) is dict and type(signed.get("certificate")) is dict,
                "VERIFIED_SIGNER_CERTIFICATE_MISSING")
        for subject in subjects:
            if type(subject) is not dict:continue
            if subject.get("name")==filename:
                sha=(subject.get("digest") or {}).get("sha256") if type(subject.get("digest")) is dict else None
                require(sha==actual,"SIGNED_SUBJECT_DIGEST_MISMATCH")
                matches.append({"subject_sha256":sha,
                                "verified_timestamp_count":len(verified_time),
                                "signer_workflow":signer_workflow,
                                "source_ref":source_ref})
    require(len(matches)>=1,"ORIGINAL_VERIFIED_SIGNED_SUBJECT_NOT_FOUND")
    if any(x!=matches[0] for x in matches[1:]):
        raise Refused("AMBIGUOUS_VERIFIED_ATTESTATION_SUBJECT")
    return matches[0]

def verify_artifact(file_path,repo,filename,signer_workflow,source_ref,expected_digest,
                    executable="gh",timeout=120):
    path,actual=preflight(file_path,repo,filename,signer_workflow,
                           source_ref,expected_digest)
    require(executable=="gh" or (
        isinstance(executable,str) and Path(executable).name in ("gh","gh.exe")),
        "UNAPPROVED_CRYPTOGRAPHIC_VERIFIER")
    require(shutil.which(executable) is not None,"OFFICIAL_GITHUB_VERIFIER_MISSING")
    command=[executable,"attestation","verify",str(path),
             "--repo",repo,
             "--signer-workflow",signer_workflow,
             "--source-ref",source_ref,
             "--predicate-type",PREDICATE,
             "--cert-oidc-issuer","https://token.actions.githubusercontent.com",
             "--format","json"]
    try:
        completed=subprocess.run(command,text=True,capture_output=True,timeout=timeout,
                                  check=False)
    except (FileNotFoundError,subprocess.TimeoutExpired,OSError) as e:
        raise Refused("OFFICIAL_GITHUB_SIGNATURE_VERIFICATION_NOT_COMPLETED") from e
    require(completed.returncode==0,
            "OFFICIAL_SIGSTORE_SIGNATURE_IDENTITY_VERIFICATION_FAILED")
    require(0<len(completed.stdout)<MAX_RESULTS,
            "INVALID_OFFICIAL_SIGNATURE_VERIFIER_OUTPUT_SIZE")
    data=safe_json(completed.stdout)
    v=validate_crypto_verified_output(data,repo,filename,signer_workflow,source_ref,actual)
    return {
       "schema":SCHEMA,
       "status":"VERIFIED_SIGNED_SOURCE_ONLY_NOT_OWNER_CONSENT",
       "verification_mode":"LIVE_OFFICIAL_GITHUB_SIGSTORE_CRYPTOGRAPHIC_VERIFIER",
       "actual_artifact_sha256":actual,
       "signer_repository":repo,
       "original_signed_subject_name":filename,
       "attested_original_source_ref":source_ref,
       "cryptographically_verified_signer_workflow":v["signer_workflow"],
       "original_verified_timestamp_count":v["verified_timestamp_count"],
       "claim_evidence_states":{
          "original_artifact_bytes":"VERIFIED",
          "source_repository_signer_identity":"VERIFIED",
          "original_signed_SLSA_provenance":"VERIFIED",
          "specific_external_owner_approval":"UNVERIFIED",
          "same_operation_resource_effect":"UNVERIFIED",
          "one_time_resource_authorization":"UNVERIFIED",
       },
       "full_resource_owner_authorization_certified":False,
       "cross_project_resource_consent_transfer_permitted":False,
       "limitations":[
          "Independent source provenance never grants a different resource owner authorization",
          "GitHub/Sigstore official cryptographic verifier and trust root supply signature validation",
          "SLSA predicate content can be controlled by the originating workflow",
          "Valid signed release cannot certify GitHub file/DB/S3 resource changes without separately bound owner intent and original effect",
       ],
    }

def main(argv=None):
    p=argparse.ArgumentParser(description="Verify original signed release source, never infer unrelated owner consent")
    p.add_argument("--asset",required=True)
    p.add_argument("--repo",required=True)
    p.add_argument("--asset-name",required=True)
    p.add_argument("--signer-workflow",required=True)
    p.add_argument("--source-ref",required=True)
    p.add_argument("--sha256",required=True)
    p.add_argument("--out",required=True)
    args=p.parse_args(argv)
    path=Path(args.out)
    if path.exists() or not path.parent.is_dir():
        print("RISU_B31_REFUSED_INVALID_OUTPUT_DESTINATION",file=sys.stderr)
        return 2
    try:
        result=verify_artifact(args.asset,args.repo,args.asset_name,
                               args.signer_workflow,args.source_ref,args.sha256)
        with path.open("x",encoding="utf-8") as f:
            json.dump(result,f,indent=2,sort_keys=True)
            f.write("\n")
        print("RISU_B31_VERIFIED_SIGSTORE_SOURCE_NOT_UNRELATED_OWNER_CONSENT")
        return 0
    except (Refused,ValueError,TypeError,OSError,UnicodeError) as e:
        print("RISU_B31_REFUSED: "+str(e),file=sys.stderr)
        return 2
if __name__=="__main__":
    raise SystemExit(main())
