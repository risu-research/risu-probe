"""B32 original Sigstore signed source, including explicitly approved delegated signers.

Only a fresh official gh attestation verify invocation authenticates signatures.
Unsigned verificationResult JSON cannot itself prove cryptography. A true
build signature never grants authority over an unrelated resource.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

SCHEMA="risu-b32-delegated-signer-original-source-closure-v1"
STATEMENT="https://in-toto.io/Statement/v1"
PREDICATE="https://slsa.dev/provenance/v1"
ISSUER="https://token.actions.githubusercontent.com"
REPO=re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
REF=re.compile(r"^refs/(?:heads|tags)/[A-Za-z0-9_./-]+$")
SIGNER=re.compile(r"^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/\.github/workflows/([A-Za-z0-9_.-]+\.ya?ml)@(refs/(?:heads|tags)/[A-Za-z0-9_./-]+)$")
SHA40=re.compile(r"^[0-9a-f]{40}$")
SHA256=re.compile(r"^[0-9a-f]{64}$")

class Refused(Exception):
    pass
def need(ok,code):
    if not ok:raise Refused(code)
def valid_repo(x):
    return type(x) is str and REPO.fullmatch(x) is not None and all(
        part not in (".","..") and not part.startswith("-") for part in x.split("/"))
def subject_matches(s,name):
    return type(s) is str and (s==name or s=="./"+name)
def file_sha256(p):
    h=hashlib.sha256()
    with p.open("rb") as f:
        for b in iter(lambda:f.read(1024*1024),b""):h.update(b)
    return h.hexdigest()
def strict_json(raw):
    def pairs(items):
        d={}
        for k,v in items:
            if k in d:raise Refused("VERIFICATION_JSON_DUPLICATE_KEY")
            d[k]=v
        return d
    def bad(x):raise Refused("VERIFICATION_JSON_NONFINITE")
    try:return json.loads(raw,object_pairs_hook=pairs,parse_constant=bad)
    except (ValueError,UnicodeError,RecursionError) as ex:
        raise Refused("INVALID_OFFICIAL_VERIFIER_JSON") from ex

def preflight(asset,source_repo,signer_identity,source_ref,expected_sha256,allow_delegated):
    p=Path(asset)
    need(p.is_file() and not p.is_symlink() and p.stat().st_size>0,
         "ORIGINAL_RELEASE_FILE_UNAVAILABLE")
    need(valid_repo(source_repo),"INVALID_SIGNED_SOURCE_REPO")
    need(type(source_ref) is str and REF.fullmatch(source_ref) is not None and
         ".." not in source_ref.split("/"),"INVALID_EXPECTED_SOURCE_REF")
    need(type(expected_sha256) is str and SHA256.fullmatch(expected_sha256) is not None,
         "ORIGINAL_EXPECTED_SHA256_NOT_PINNED")
    need(type(signer_identity) is str and
         (m:=SIGNER.fullmatch(signer_identity)) is not None,
         "INVALID_EXPECTED_SIGNER_IDENTITY")
    signer_repo=m.group(1)+"/"+m.group(2)
    need(valid_repo(signer_repo) and ".." not in m.group(4).split("/"),
         "UNSAFE_SIGNER_REPOSITORY_OR_WORKFLOW")
    delegated=signer_repo!=source_repo
    need(type(allow_delegated) is bool,"EXPLICIT_SIGNER_POLICY_REQUIRED")
    need(not delegated or allow_delegated,"DELEGATED_SIGNER_NOT_EXPLICITLY_AUTHORIZED")
    need(p.name not in (".","..") and "/" not in p.name,
         "INVALID_SIGNED_SUBJECT_FILENAME")
    actual=file_sha256(p)
    need(actual==expected_sha256,"ORIGINAL_SIGNED_FILE_SHA256_MISMATCH")
    return p,signer_repo,actual,delegated

def inspect_verified_record(data,source_repo,signer_repo,signer_identity,
                            source_ref,filename,actual,delegated):
    """Deterministic policy rules. Call only on official gh-verified output."""
    need(type(data) is list and 1<=len(data)<=30,
         "OFFICIAL_VERIFIER_NO_VERIFIED_ATTESTATIONS")
    found=[]
    for row in data:
        need(type(row) is dict and type(row.get("verificationResult")) is dict,
             "MALFORMED_GITHUB_VERIFICATION_RECORD")
        v=row["verificationResult"]
        sig=v.get("signature")
        cert=sig.get("certificate") if type(sig) is dict else None
        need(type(cert) is dict and
             cert.get("issuer")==ISSUER and
             cert.get("subjectAlternativeName")==signer_identity and
             cert.get("buildSignerURI")==signer_identity,
             "ORIGINAL_SIGNER_CERTIFICATE_IDENTITY_MISMATCH")
        need(cert.get("sourceRepositoryURI")=="https://github.com/"+source_repo and
             cert.get("githubWorkflowRepository")==source_repo and
             cert.get("sourceRepositoryRef")==source_ref,
             "ORIGINAL_SOURCE_REPO_REF_MISMATCH")
        need(type(cert.get("sourceRepositoryDigest")) is str and
             SHA40.fullmatch(cert["sourceRepositoryDigest"]) is not None and
             type(cert.get("buildSignerDigest")) is str and
             SHA40.fullmatch(cert["buildSignerDigest"]) is not None,
             "UNBOUND_SIGNER_OR_SOURCE_COMMIT")
        m=SIGNER.fullmatch(cert["buildSignerURI"])
        need(m is not None and m.group(1)+"/"+m.group(2)==signer_repo and
             (signer_repo!=source_repo)==delegated,
             "UNEXPECTED_DELEGATION_IDENTITY")
        timestamps=v.get("verifiedTimestamps")
        need(type(timestamps) is list and len(timestamps)>0 and
             all(type(t) is dict and type(t.get("timestamp")) is str
                 for t in timestamps),
             "VERIFIED_SIGSTORE_TIMESTAMP_ABSENT")
        statement=v.get("statement")
        need(type(statement) is dict and
             statement.get("_type")==STATEMENT and
             statement.get("predicateType")==PREDICATE,
             "SIGNED_ATTESTATION_WRONG_PREDICATE_TYPE")
        pred=statement.get("predicate")
        build=pred.get("buildDefinition") if type(pred) is dict else None
        parms=build.get("externalParameters") if type(build) is dict else None
        wf=parms.get("workflow") if type(parms) is dict else None
        need(type(wf) is dict and
             wf.get("repository")=="https://github.com/"+source_repo and
             wf.get("ref")==source_ref and
             type(wf.get("path")) is str and
             wf["path"].startswith(".github/workflows/") and
             ".." not in wf["path"].split("/"),
             "SLSA_DECLARED_PRODUCER_WORKFLOW_MISMATCH")
        subjects=statement.get("subject")
        need(type(subjects) is list and 1<=len(subjects)<=200,
             "SIGNED_SUBJECT_SET_UNSUPPORTED")
        for sub in subjects:
            if type(sub) is dict and subject_matches(sub.get("name"),filename):
                d=sub.get("digest")
                need(type(d) is dict and d.get("sha256")==actual,
                     "ORIGINAL_SIGNED_SUBJECT_DIGEST_DIFFERS")
                found.append({
                    "source_sha":cert["sourceRepositoryDigest"],
                    "signer_sha":cert["buildSignerDigest"],
                    "subject_signed_name":sub["name"],
                    "original_source_workflow":wf["path"],
                    "timestamps":len(timestamps),
                })
    need(len(found)==1,"ORIGINAL_SIGNED_SUBJECT_ABSENT_OR_AMBIGUOUS")
    return found[0]

def verify_original(asset,source_repo,signer_identity,source_ref,expected_sha256,
                    allow_delegated=False):
    p,signer_repo,actual,delegated=preflight(
        asset,source_repo,signer_identity,source_ref,expected_sha256,allow_delegated)
    need(shutil.which("gh") is not None,
         "OFFICIAL_GITHUB_SIGSTORE_CRYPTOGRAPHIC_VERIFIER_MISSING")
    command=["gh","attestation","verify",str(p),"--repo",source_repo,
             "--signer-repo",signer_repo,"--cert-identity",signer_identity,
             "--cert-oidc-issuer",ISSUER,"--source-ref",source_ref,
             "--predicate-type",PREDICATE,"--format","json"]
    try:
        proc=subprocess.run(command,text=True,capture_output=True,timeout=150)
    except (OSError,subprocess.TimeoutExpired) as ex:
        raise Refused("ORIGINAL_GH_SIGNATURE_VERIFICATION_UNAVAILABLE") from ex
    need(proc.returncode==0,"ORIGINAL_GH_SIGSTORE_ATTESTATION_NOT_VERIFIED")
    need(0<len(proc.stdout)<4_000_000,
         "GITHUB_VERIFIER_OUTPUT_TOO_LARGE_OR_EMPTY")
    record=inspect_verified_record(
        strict_json(proc.stdout),source_repo,signer_repo,signer_identity,
        source_ref,p.name,actual,delegated)
    return {
        "schema":SCHEMA,
        "status":"ORIGINAL_SIGNED_SOURCE_VERIFIED_WITH_EXPLICIT_SIGNER_IDENTITY",
        "original_crypto_engine":"official-gh-attestation-verify-and-Sigstore-trust-root",
        "source_repository":source_repo,
        "signer_repository":signer_repo,
        "signer_certificate_identity":signer_identity,
        "source_ref":source_ref,
        "source_commit":record["source_sha"],
        "signer_commit":record["signer_sha"],
        "artifact_sha256":actual,
        "asset_name":p.name,
        "original_signed_subject_name":record["subject_signed_name"],
        "normalized_single_dot_slash_prefix":record["subject_signed_name"]!=p.name,
        "delegation_explicitly_accepted":delegated and allow_delegated,
        "producer_workflow":record["original_source_workflow"],
        "verified_timestamp_count":record["timestamps"],
        "claim_states":{
            "signed_artifact_bytes":"VERIFIED",
            "original_source_repository":"VERIFIED",
            "signed_source_commit_and_ref":"VERIFIED",
            "expected_signer_workflow_identity":"VERIFIED",
            "separate_resource_owner_approval":"UNVERIFIED",
            "same_operation_remote_effect":"UNVERIFIED",
            "single_use_resource_permission":"UNVERIFIED",
        },
        "grants_authority_over_unrelated_resource":False,
    }

def main(argv=None):
    parser=argparse.ArgumentParser(description="Original Sigstore provenance with exact delegated signer and source, not unrelated owner consent")
    parser.add_argument("--asset",required=True)
    parser.add_argument("--source-repo",required=True)
    parser.add_argument("--signer-identity",required=True)
    parser.add_argument("--source-ref",required=True)
    parser.add_argument("--sha256",required=True)
    parser.add_argument("--allow-delegated",action="store_true")
    parser.add_argument("--out",required=True)
    args=parser.parse_args(argv)
    dst=Path(args.out)
    if dst.exists() or not dst.parent.is_dir():
        print("RISU_B32_OUTPUT_REFUSED",file=sys.stderr)
        return 2
    try:
        result=verify_original(args.asset,args.source_repo,args.signer_identity,
                               args.source_ref,args.sha256,args.allow_delegated)
        with dst.open("x",encoding="utf-8") as f:
            json.dump(result,f,indent=2,sort_keys=True)
            f.write("\n")
        print("RISU_B32_SIGNED_SOURCE_VERIFIED_WITHOUT_RESOURCE_OWNER_AUTHORITY")
        return 0
    except (Refused,ValueError,TypeError,OSError,UnicodeError,KeyError) as ex:
        print("RISU_B32_REFUSED: "+str(ex),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
