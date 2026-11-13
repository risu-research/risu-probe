"""B33 real GitHub Actions/Sigstore signed-code to runtime effect closure.

A read-only product adapter, not a new cryptographic implementation.
Evidence is collected directly from the original GitHub workflow run and
the official gh/Sigstore verifier, then exact actor, source, code bytes,
runner claim, time, resource and Git effect obligations are joined.

No independent external owner consent, TEE runtime attestation or path-scoped
GitHub write token is inferred. Offline structural checks must NEVER be
misrepresented as fresh cryptographic verification.
"""
from __future__ import annotations
import argparse
import base64
from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from urllib.parse import quote
from urllib.request import Request,urlopen

import yaml

SCHEMA="risu-b33-platform-signed-code-runtime-exact-git-effect-closure-v1"
SOURCE_SCHEMA="risu-b33-original-sigstore-and-github-source-facts-v1"
EVIDENCE_TIER="NATIVE_SIGSTORE_SIGNED_GITHUB_RUNNER_ASSERTED_EXECUTION_AND_INDEPENDENT_GIT_EFFECT"
ISSUER="https://token.actions.githubusercontent.com"
SLSA="https://slsa.dev/provenance/v1"
STATEMENT="https://in-toto.io/Statement/v1"
REPO=re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
PATH=re.compile(r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*$")
REF=re.compile(r"^refs/heads/[A-Za-z0-9_.\-/]+$")
SHA40=re.compile(r"^[0-9a-f]{40}$")
SHA64=re.compile(r"^[0-9a-f]{64}$")
EXPECTED={
 "candidate":"risu-b33-signed-readonly-candidate-execution-v1",
 "receipt":"risu-b33-original-run-trusted-broker-effect-receipt-v1",
 "policy":"risu-b33-local-platform-authorized-source-effect-intent-v1",
}
POLICY_TIER="GITHUB_WORKFLOW_PLATFORM_REPOSITORY_WRITE_AUTHORITY_NO_INDEPENDENT_HUMAN_REVIEW"

class Refused(Exception):
    pass

def need(test,reason):
    if not test:
        raise Refused(reason)

def valid_repo(x):
    return (type(x) is str and REPO.fullmatch(x) is not None and
            all(k not in (".","..") and not k.startswith("-") for k in x.split("/")))

def valid_path(x):
    return (type(x) is str and PATH.fullmatch(x) is not None and
            all(p not in (".","..") for p in x.split("/")))

def valid_ref(x):
    return (type(x) is str and REF.fullmatch(x) is not None and
            all(k not in ("",".","..") for k in x.split("/")))

def sha256(data):
    return hashlib.sha256(data).hexdigest()

def blob_sha1(data):
    return hashlib.sha1(b"blob "+str(len(data)).encode("ascii")+b"\0"+data).hexdigest()

def strict(data):
    def pairs(kvs):
        d={}
        for k,v in kvs:
            need(k not in d,"EVIDENCE_DUPLICATE_JSON_KEY")
            d[k]=v
        return d
    def bad(x):
        raise Refused("EVIDENCE_NONFINITE_NUMBER")
    try:
        return json.loads(data,object_pairs_hook=pairs,parse_constant=bad)
    except (UnicodeError,ValueError,RecursionError) as e:
        raise Refused("EVIDENCE_INVALID_JSON") from e

def stamp(s):
    need(type(s) is str and s.endswith("Z"),"TIMESTAMP_NOT_UTC")
    try:return datetime.fromisoformat(s.replace("Z","+00:00")).astimezone(timezone.utc)
    except ValueError as e:
        raise Refused("TIMESTAMP_MALFORMED") from e

def api(repo,endpoint,token):
    req=Request("https://api.github.com"+endpoint,
      headers={
          "Authorization":"Bearer "+token,
          "Accept":"application/vnd.github+json",
          "User-Agent":"RISU-B33-ReadOnly-Provenance-Closure",
          "X-GitHub-Api-Version":"2022-11-28"})
    try:
        with urlopen(req,timeout=40) as out:
            need(out.status==200,"ORIGINAL_GITHUB_REST_STATUS_FAILED")
            return strict(out.read())
    except (OSError,TimeoutError) as ex:
        raise Refused("ORIGINAL_GITHUB_REST_LOOKUP_FAILED") from ex

def decode_contents(obj):
    need(type(obj) is dict and obj.get("type")=="file" and
         obj.get("encoding")=="base64","ORIGINAL_GITHUB_CONTENTS_NOT_A_FILE")
    raw=obj.get("content")
    need(type(raw) is str,"ORIGINAL_GITHUB_CONTENT_BYTES_MISSING")
    b64=raw.replace("\r","").replace("\n","")
    need(re.fullmatch(r"[A-Za-z0-9+/]*={0,2}",b64) is not None,
         "ORIGINAL_GITHUB_NONCANONICAL_BASE64")
    try:data=base64.b64decode(b64,validate=True)
    except (ValueError,base64.binascii.Error) as ex:
        raise Refused("ORIGINAL_GITHUB_BASE64_INVALID") from ex
    need(base64.b64encode(data).decode("ascii")==b64 and
         obj.get("size")==len(data) and
         obj.get("sha")==blob_sha1(data),
         "ORIGINAL_GITHUB_REMOTE_GIT_BLOB_INVALID")
    return data

def source_content(repo,path,ref,token):
    need(valid_path(path),"UNSAFE_REPOSITORY_CONTENTS_PATH")
    need(SHA40.fullmatch(ref) is not None,"SOURCE_MUST_BE_IMMUTABLE_COMMIT_SHA")
    obj=api(repo,f"/repos/{repo}/contents/"+quote(path,safe="/")+
            "?ref="+quote(ref,safe=""),token)
    return decode_contents(obj)

def gh_verified(file_path,repo,signer_identity,source_ref,source_sha,run_id,token):
    need(shutil.which("gh") is not None,"OFFICIAL_GITHUB_SIGSTORE_VERIFIER_UNAVAILABLE")
    p=Path(file_path)
    need(p.is_file() and not p.is_symlink(),"ORIGINAL_FILE_SUBJECT_MISSING")
    expected=sha256(p.read_bytes())
    command=["gh","attestation","verify",str(p),"--repo",repo,
             "--cert-identity",signer_identity,
             "--cert-oidc-issuer",ISSUER,
             "--source-ref",source_ref,
             "--predicate-type",SLSA,
             "--format","json"]
    try:
        process=subprocess.run(command,capture_output=True,text=True,timeout=90,
                               env={**os.environ,"GH_TOKEN":token})
    except (OSError,subprocess.TimeoutExpired) as ex:
        raise Refused("OFFICIAL_SIGSTORE_CRYPTOGRAPHIC_ENGINE_FAILED") from ex
    need(process.returncode==0,"OFFICIAL_SIGSTORE_CRYPTOGRAPHIC_VERIFICATION_REFUSED")
    need(0<len(process.stdout)<=4_000_000,
         "OFFICIAL_SIGSTORE_RESULT_EMPTY_OR_OVERSIZED")
    obj=strict(process.stdout)
    need(type(obj) is list and 1<=len(obj)<=30,
         "OFFICIAL_SIGSTORE_NO_UNAMBIGUOUS_SIGNED_STATEMENTS")
    matches=[]
    for row in obj:
        need(type(row) is dict,"SIGNED_RESULT_INVALID")
        v=row.get("verificationResult")
        need(type(v) is dict,"SIGNED_RESULT_NOT_VERIFIED")
        cert=v.get("signature",{}).get("certificate",{})
        need(type(cert) is dict and
             cert.get("issuer")==ISSUER and
             cert.get("subjectAlternativeName")==signer_identity and
             cert.get("buildSignerURI")==signer_identity and
             cert.get("sourceRepositoryURI")=="https://github.com/"+repo and
             cert.get("sourceRepositoryDigest")==source_sha and
             cert.get("sourceRepositoryRef")==source_ref and
             cert.get("githubWorkflowRepository")==repo and
             cert.get("runInvocationURI")==
               "https://github.com/"+repo+"/actions/runs/"+str(run_id)+"/attempts/1",
             "SIGNED_CERTIFICATE_DIFFERENT_RUN_REPO_OR_ACTOR_WORKFLOW")
        st=v.get("statement")
        need(type(st) is dict and st.get("_type")==STATEMENT and
             st.get("predicateType")==SLSA,
             "SIGNED_STATEMENT_PREDICATE_INVALID")
        definition=st.get("predicate",{}).get("buildDefinition",{})
        external=definition.get("externalParameters",{})
        wf=external.get("workflow")
        need(type(wf) is dict and wf.get("repository")=="https://github.com/"+repo and
             wf.get("ref")==source_ref and
             signer_identity.startswith(
                 "https://github.com/"+repo+"/"+wf.get("path","")+"@"),
             "SIGNED_SLSA_WORKFLOW_SOURCE_MISMATCH")
        times=v.get("verifiedTimestamps")
        need(type(times) is list and len(times)>0 and
             type(times[0]) is dict and
             type(times[0].get("timestamp")) is str,
             "TRUSTED_SIGSTORE_TIMESTAMP_MISSING")
        for sub in st.get("subject",[]):
            if (type(sub) is dict and
                type(sub.get("name")) is str and
                type(sub.get("digest")) is dict and
                sub["digest"].get("sha256")==expected and
                sub["name"] in (p.name,"./"+p.name)):
                matches.append({
                  "signed_subject_name":sub["name"],
                  "signed_subject_sha256":expected,
                  "signed_at":times[0]["timestamp"],
                  "signer_identity":signer_identity,
                  "source_sha":source_sha,
                  "run_id":run_id,
                })
    need(len(matches)==1,"SIGNED_SUBJECT_HASH_ABSENT_OR_MULTIPLE")
    return matches[0]

def normalize(e):
    """Pure claim join. Strictly structural, NO OFFLINE SIGNATURE VERIFICATION."""
    need(type(e) is dict and e.get("schema")==SOURCE_SCHEMA,
         "INVALID_NORMALIZED_SOURCE_EVIDENCE_SCHEMA")
    run=e.get("run")
    writer=e.get("writer_job")
    candidate=e.get("candidate")
    receipt=e.get("receipt")
    intent=e.get("intent")
    sig=e.get("signatures")
    original=e.get("original")
    need(all(type(z) is dict for z in
             (run,writer,candidate,receipt,intent,sig,original)),
         "INCOMPLETE_ORIGINAL_SOURCE_OBLIGATIONS")
    need(set(sig)=={"candidate","broker","receipt"},
         "THREE_ORIGINAL_SIGNED_SUBJECTS_REQUIRED")
    repo=run.get("repository")
    source_sha=run.get("head_sha")
    source_ref=run.get("source_ref")
    run_id=run.get("id")
    attempt=run.get("attempt")
    native_actor=run.get("actor")
    need(valid_repo(repo) and type(run_id) is int and run_id>0 and
         type(source_sha) is str and SHA40.fullmatch(source_sha) is not None and
         valid_ref(source_ref) and type(native_actor) is str and
         type(attempt) is int and attempt==1 and
         run.get("event")=="push" and run.get("conclusion")=="success",
         "ORIGINAL_PLATFORM_RUN_NOT_VERIFIED_SUCCESS")
    need(writer.get("name")=="signed-candidate-execute-one-effect" and
         writer.get("conclusion")=="success" and
         type(writer.get("id")) is int,
         "ORIGINAL_PLATFORM_PRIVILEGED_JOB_NOT_SUCCESSFUL")
    need(e.get("authorization",{}).get("source_workflow_declares_contents_write") is True and
         e["authorization"].get("source_audit_job_read_only") is True and
         e["authorization"].get("same_run_issuer_authority")=="REPO_SCOPED_GITHUB_ACTIONS_JOB",
         "NATIVE_WORKFLOW_PERMISSIONS_OR_AUDIT_SCOPE_NOT_BOUND")
    need(intent.get("schema")==EXPECTED["policy"] and
         intent.get("owner_repository")==repo and
         intent.get("execution_ref")==source_ref and
         intent.get("approval_tier")==POLICY_TIER and
         intent.get("exact_one_effect_commit") is True,
         "NATIVE_REPOSITORY_SOURCE_INTENT_NOT_FIXED")
    path=intent.get("resource_path")
    need(valid_path(path) and
         path==receipt.get("resource_path")==candidate.get("resource_path")==
              original.get("changed_path"),
         "CROSS_RESOURCE_PATH_COLLISION")
    need(candidate.get("schema")==EXPECTED["candidate"] and
         receipt.get("schema")==EXPECTED["receipt"],
         "RUNNER_CANDIDATE_AND_ACTUAL_BROKER_SCHEMA_MISMATCH")
    for k,v in (("repo",repo),("run_id",run_id),
                ("actor",native_actor),("attempt",1)):
        need(candidate.get(k)==v and receipt.get(k)==v,
             "CROSS_RUN_OR_ACTOR_IDENTITY_COLLISION")
    need(candidate.get("head_sha")==receipt.get("source_sha")==source_sha and
         candidate.get("branch_ref")==receipt.get("branch_ref")==source_ref,
         "ORIGINAL_SOURCE_COMMIT_OR_REF_REBOUND")
    need(receipt.get("remote_effect_commit")==original.get("effect_sha") and
         type(original.get("effect_sha")) is str and
         SHA40.fullmatch(original["effect_sha"]) is not None,
         "REMOTE_RESOURCE_EFFECT_COMMIT_NOT_BOUND")
    need(original.get("effect_parents")==[source_sha] and
         original.get("changed_count")==1 and
         original.get("changed_status")=="modified",
         "EFFECT_COMMIT_NOT_DIRECT_ONE_FILE_CHILD_OF_SIGNED_ORIGINAL")
    need(all(type(x) is str and SHA64.fullmatch(x) is not None for x in
             (e.get("policy_sha256"),e.get("candidate_receipt_sha256"),
              e.get("original_receipt_sha256"),
              e.get("candidate_program_sha256"),e.get("broker_program_sha256"))),
         "ORIGINAL_DIGESTS_INCOMPLETE")
    need(candidate.get("policy_sha256")==receipt.get("policy_sha256")==
         e["policy_sha256"] and
         receipt.get("candidate_receipt_sha256")==e["candidate_receipt_sha256"],
         "INTENT_OR_REQUEST_BYTES_FROM_DIFFERENT_ORIGINAL_RUN")
    need(candidate.get("tool_program")==intent.get("source_program") and
         receipt.get("source_program")==intent.get("source_program") and
         receipt.get("trusted_broker")==intent.get("trusted_broker"),
         "ORIGINAL_CODE_PATHS_DIFFERENT")
    need(candidate.get("tool_program_sha256")==receipt.get("signed_program_sha256")==
         e["candidate_program_sha256"]==
         sig["candidate"].get("signed_subject_sha256") and
         receipt.get("signed_broker_sha256")==e["broker_program_sha256"]==
         sig["broker"].get("signed_subject_sha256") and
         e["original_receipt_sha256"]==sig["receipt"].get("signed_subject_sha256"),
         "ACTUAL_RUNNER_EXECUTED_CODE_NOT_MATCHING_SIGNED_BYTES")
    need(candidate.get("expected_prior_sha256")==
         receipt.get("before_sha256")==original.get("before_sha256")==
         intent.get("expected_prior_sha256") and
         candidate.get("desired_sha256")==
         receipt.get("after_sha256")==original.get("after_sha256")==
         intent.get("desired_content_sha256"),
         "REMOTE_PRE_POST_BYTES_DIFFER_FROM_ORIGINAL_OWNER_INTENT")
    need(original.get("before_git_blob")==intent.get("expected_prior_git_blob")==
         receipt.get("before_git_blob") and
         original.get("after_git_blob")==receipt.get("after_git_blob"),
         "REMOTE_ORIGINAL_GIT_BLOB_MISMATCH")
    need(original.get("remote_git_effect_observed") is True and
         original["before_sha256"]!=original["after_sha256"],
         "NO_OBSERVED_ACTUAL_STATE_CHANGE")
    need(receipt.get("human_owner_approval_proven") is False and
         receipt.get("candidate_write_token_available") is False and
         candidate.get("tool_write_credential_available") is False and
         receipt.get("trusted_broker_write_token_scope")==
           "REPOSITORY_CONTENTS_WRITE_NOT_FILE_SCOPED" and
         receipt.get("approval_tier")==POLICY_TIER,
         "UNFOUNDED_OWNER_APPROVAL_OR_CREDENTIAL_SCOPE")
    signer=run.get("signer_identity")
    need(type(signer) is str and signer.startswith("https://github.com/"+repo+"/") and
         signer.endswith("@"+source_ref),
         "EXPECTED_SIGNER_WORKFLOW_NOT_SOURCE_BOUND")
    for key in ("candidate","broker","receipt"):
        fact=sig[key]
        need(type(fact) is dict and fact.get("run_id")==run_id and
             fact.get("source_sha")==source_sha and
             fact.get("signer_identity")==signer and
             type(fact.get("signed_at")) is str,
             "SIGNED_SOURCE_REBOUND_ACROSS_RUNS_OR_SIGNERS")
    # Sigstore time is a verifiable log/timestamp of attestation recording.
    # Runner process invocations are from same-run signed CI assertions, not TEE.
    clock={
       "writer_started":stamp(writer.get("started_at")),
       "candidate_signed":stamp(sig["candidate"]["signed_at"]),
       "broker_signed":stamp(sig["broker"]["signed_at"]),
       "tool_start":stamp(candidate.get("invoked_at")),
       "tool_end":stamp(candidate.get("returned_at")),
       "broker_start":stamp(receipt.get("broker_started_at")),
       "broker_end":stamp(receipt.get("broker_finished_at")),
       "effect_commit":stamp(original.get("effect_commit_time")),
       "receipt_signed":stamp(sig["receipt"]["signed_at"]),
       "writer_ended":stamp(writer.get("completed_at")),
    }
    slack=timedelta(seconds=3)
    need(clock["writer_started"]<=clock["candidate_signed"]+slack and
         clock["writer_started"]<=clock["broker_signed"]+slack and
         max(clock["candidate_signed"],clock["broker_signed"])<=
            clock["tool_start"]+slack and
         clock["tool_start"]<=clock["tool_end"]<=clock["broker_start"]<=
            clock["broker_end"]<=clock["receipt_signed"]+slack and
         clock["receipt_signed"]<=clock["writer_ended"]+timedelta(seconds=5),
         "SIGNING_EXECUTION_AUTHORITY_AND_RESULT_TIME_SEQUENCE_INVALID")
    need(clock["tool_start"]-timedelta(minutes=2)<=clock["effect_commit"]<=
            clock["broker_end"]+timedelta(minutes=2) and
         clock["writer_started"]-slack<=clock["effect_commit"]<=
            clock["writer_ended"]+timedelta(minutes=2),
         "GITHUB_NATIVE_EFFECT_OCCURRED_OUTSIDE_EXECUTION_INTERVAL")
    return {
       "schema":SCHEMA,
       "status":"ORIGINAL_STRUCTURAL_SOURCE_RUN_EFFECT_FACTS_CLOSED",
       "verification_mode":"STRUCTURAL_ONLY_ORIGINAL_SIGSTORE_GITHUB_FACTS_NEED_FRESH_VERIFICATION",
       "original_run_id":run_id,
       "original_actor":native_actor,
       "source_repository":repo,
       "original_source_sha":source_sha,
       "original_source_ref":source_ref,
       "effect_commit":original["effect_sha"],
       "exact_resource_path":path,
       "source_candidate_sha256":e["candidate_program_sha256"],
       "source_broker_sha256":e["broker_program_sha256"],
       "signed_execution_receipt_sha256":e["original_receipt_sha256"],
       "original_before_sha256":original["before_sha256"],
       "original_after_sha256":original["after_sha256"],
       "time_sequence":{k:v.isoformat().replace("+00:00","Z")
                        for k,v in clock.items()},
       "claim_states":{
          "signed_candidate_source_bytes":"VERIFIED",
          "signed_trusted_broker_source_bytes":"VERIFIED",
          "same_run_cryptographically_signed_execution_receipt":"VERIFIED",
          "native_job_actor_source_ref_binding":"VERIFIED",
          "time_order_from_sigstore_native_git_runner":"VERIFIED",
          "fixed_one_resource_actual_git_effect":"VERIFIED",
          "independent_human_resource_owner_approval":"UNVERIFIED",
          "actual_instruction_trace_in_trusted_hardware":"UNVERIFIED",
          "repository_token_file_scoped_by_github":"REFUTED",
       },
       "limits":[
          "GitHub Actions runner execution transcript is a source-runner assertion; a trusted signing workflow may fabricate a receipt",
          "This experiment uses an exact GitHub Actions job platform permission, not a different human owner's resource consent",
          "GITHUB_TOKEN is repository-scoped contents write; one-file scope enforced by trusted broker code, not native token",
          "Original source and Git commit are GitHub-authenticated; program runtime is not hardware-attested",
       ],
    }

def collect_live(repo,run_id,artifact_name,workflow_path,token):
    need(valid_repo(repo) and valid_path(workflow_path) and
         workflow_path.startswith(".github/workflows/") and
         workflow_path.endswith((".yml",".yaml")),
         "INVALID_GITHUB_REPOSITORY_OR_WORKFLOW_PATH")
    need(type(run_id) is int and run_id>0 and
         type(artifact_name) is str and
         re.fullmatch(r"[A-Za-z0-9_.-]{1,180}",artifact_name) is not None,
         "INVALID_ORIGINAL_RUN_OR_ARTIFACT_NAME")
    need(type(token) is str and len(token)>12,
         "GITHUB_READ_TOKEN_MISSING")
    run=api(repo,f"/repos/{repo}/actions/runs/{run_id}",token)
    source=run.get("head_sha")
    need(type(source) is str and SHA40.fullmatch(source) is not None and
         run.get("run_attempt")==1 and run.get("event")=="push" and
         run.get("conclusion")=="success" and
         run.get("status")=="completed",
         "ACTUAL_ORIGINAL_RUN_NOT_FINISHED_SUCCESS")
    source_ref="refs/heads/"+run.get("head_branch","")
    need(valid_ref(source_ref) and
         run.get("path")==workflow_path,
         "ORIGINAL_GITHUB_SOURCE_REF_OR_RUN_WORKFLOW_PATH_INVALID")
    identity=f"https://github.com/{repo}/{workflow_path}@{source_ref}"
    original_code=source_content(repo,workflow_path,source,token)
    try:
        workflow=yaml.safe_load(original_code.decode("utf-8"))
    except (ValueError,yaml.YAMLError) as ex:
        raise Refused("ORIGINAL_WORKFLOW_YAML_INVALID") from ex
    need(type(workflow) is dict and type(workflow.get("jobs")) is dict,
         "ORIGINAL_GITHUB_WORKFLOW_SOURCE_MISSING_JOBS")
    jobs=workflow["jobs"]
    write=jobs.get("signed-candidate-execute-one-effect")
    audit=jobs.get("read-only-original-platform-and-sigstore-audit")
    need(type(write) is dict and type(audit) is dict,
         "ORIGINAL_EXPECTED_READER_WRITER_JOBS_MISSING")
    wp=write.get("permissions")
    ap=audit.get("permissions")
    need(type(wp) is dict and wp.get("contents")=="write" and
         wp.get("attestations")=="write" and wp.get("id-token")=="write" and
         type(ap) is dict and ap.get("contents")=="read" and
         ap.get("actions")=="read" and ap.get("attestations")=="read" and
         ap.get("id-token") not in ("write",) and
         type(audit.get("needs")) is str and
         audit["needs"]=="signed-candidate-execute-one-effect",
         "NATIVE_SOURCE_SCOPE_NOT_ISOLATED_OR_ORDERED")
    job_result=api(repo,f"/repos/{repo}/actions/runs/{run_id}/jobs?per_page=100",token)
    native=[j for j in job_result.get("jobs",[]) if
            j.get("name")=="signed-candidate-execute-one-effect" and
            j.get("conclusion")=="success"]
    need(len(native)==1,"GITHUB_NATIVE_WRITER_JOB_STATUS_NOT_UNIQUE")
    native_job=native[0]
    art_result=api(repo,f"/repos/{repo}/actions/runs/{run_id}/artifacts?per_page=100",token)
    artifacts=[a for a in art_result.get("artifacts",[]) if
               a.get("name")==artifact_name and
               a.get("expired") is False and
               a.get("workflow_run",{}).get("id")==run_id]
    need(len(artifacts)==1,"ORIGINAL_RUN_ARTIFACT_NOT_UNIQUE_OR_EXPIRED")
    with tempfile.TemporaryDirectory(prefix="risu-b33-original-") as tmp:
        root=Path(tmp)
        target=root/"recorded"
        target.mkdir()
        args=["gh","run","download",str(run_id),"--repo",repo,
              "--name",artifact_name,"--dir",str(target)]
        try:
            p=subprocess.run(args,capture_output=True,text=True,timeout=110,
                     env={**os.environ,"GH_TOKEN":token})
        except (OSError,subprocess.TimeoutExpired) as ex:
            raise Refused("ORIGINAL_GITHUB_ARTIFACT_DOWNLOAD_UNAVAILABLE") from ex
        need(p.returncode==0,"ORIGINAL_SIGNED_RECEIPT_ARTIFACT_DOWNLOAD_FAILED")
        expected_names={"CANDIDATE_EXECUTION.json","EXECUTION_RECEIPT.json"}
        got={p.name for p in target.rglob("*") if p.is_file()}
        need(got==expected_names and
             all(not p.is_symlink() for p in target.rglob("*")),
             "MALFORMED_ORIGINAL_RUN_RECEIPT_ARTIFACT_SET")
        candid_path=next(target.rglob("CANDIDATE_EXECUTION.json"))
        receipt_path=next(target.rglob("EXECUTION_RECEIPT.json"))
        need(0<candid_path.stat().st_size<250_000 and
             0<receipt_path.stat().st_size<250_000,
             "ORIGINAL_RECEIPT_BYTES_OUT_OF_BOUNDS")
        candidate_bytes=candid_path.read_bytes()
        receipt_bytes=receipt_path.read_bytes()
        candidate=strict(candidate_bytes)
        receipt=strict(receipt_bytes)
        policy_path=receipt.get("source_program")
        broker_path=receipt.get("trusted_broker")
        res_path=receipt.get("resource_path")
        need(valid_path(policy_path) and valid_path(broker_path) and
             valid_path(res_path) and
             policy_path!=broker_path and
             candidate.get("tool_program")==policy_path,
             "SIGNED_PROGRAM_BROKER_AND_RESOURCE_PATHS_INVALID")
        # The canonical policy is retrieved from the same immutable original
        # source commit, NOT from the artifact or current mutable branch.
        intent_path="benchmarks/p6b33/INTENT.json"
        policy_data=source_content(repo,intent_path,source,token)
        intent=strict(policy_data)
        need(intent.get("source_program")==policy_path and
             intent.get("trusted_broker")==broker_path and
             intent.get("resource_path")==res_path,
             "ORIGINAL_SOURCE_POLICY_DIFFERENT_FROM_RECEIPT")
        cand_bytes=source_content(repo,policy_path,source,token)
        broker_bytes=source_content(repo,broker_path,source,token)
        signing_files={}
        for role,path,data in (("candidate",policy_path,cand_bytes),
                               ("broker",broker_path,broker_bytes)):
            fname=Path(path).name
            need(all(existing.name!=fname for existing in signing_files.values()),
                 "SIGNED_LOCAL_SOURCE_BASENAMES_COLLIDE")
            file=root/fname
            file.write_bytes(data)
            signing_files[role]=file
        signatures={
          "candidate":gh_verified(signing_files["candidate"],repo,identity,source_ref,
                                  source,run_id,token),
          "broker":gh_verified(signing_files["broker"],repo,identity,source_ref,
                               source,run_id,token),
          "receipt":gh_verified(receipt_path,repo,identity,source_ref,
                                source,run_id,token),
        }
        commit_sha=receipt.get("remote_effect_commit")
        need(type(commit_sha) is str and SHA40.fullmatch(commit_sha) is not None,
             "RUNNER_CLAIMED_REMOTE_EFFECT_COMMIT_INVALID")
        effect=api(repo,f"/repos/{repo}/commits/{commit_sha}",token)
        pre_obj=api(repo,f"/repos/{repo}/contents/"+quote(res_path,safe="/")+
                    "?ref="+quote(source,safe=""),token)
        post_obj=api(repo,f"/repos/{repo}/contents/"+quote(res_path,safe="/")+
                     "?ref="+quote(commit_sha,safe=""),token)
        pre=decode_contents(pre_obj)
        post=decode_contents(post_obj)
        need(post==intent.get("desired_content","").encode("utf-8"),
             "ACTUAL_GIT_EFFECT_BYTES_NOT_ORIGINAL_INTENT")
        effect_parents=[q.get("sha") for q in effect.get("parents",[])]
        changes=effect.get("files",[])
        result={
          "schema":SOURCE_SCHEMA,
          "verification_origin":"LIVE_GITHUB_REST_AND_OFFICIAL_GH_SIGSTORE",
          "run":{
            "repository":repo,"id":run_id,
            "attempt":run["run_attempt"],
            "actor":run["actor"]["login"],
            "head_sha":source,"source_ref":source_ref,
            "event":run["event"],
            "conclusion":run["conclusion"],
            "signer_identity":identity,
          },
          "writer_job":{
            "id":native_job["id"],"name":native_job["name"],
            "conclusion":native_job["conclusion"],
            "started_at":native_job["started_at"],
            "completed_at":native_job["completed_at"],
          },
          "authorization":{
            "source_workflow_declares_contents_write":True,
            "source_audit_job_read_only":True,
            "same_run_issuer_authority":"REPO_SCOPED_GITHUB_ACTIONS_JOB",
          },
          "intent":intent,"candidate":candidate,"receipt":receipt,
          "signatures":signatures,
          "candidate_program_sha256":sha256(cand_bytes),
          "broker_program_sha256":sha256(broker_bytes),
          "policy_sha256":sha256(policy_data),
          "candidate_receipt_sha256":sha256(candidate_bytes),
          "original_receipt_sha256":sha256(receipt_bytes),
          "original":{
            "effect_sha":commit_sha,
            "effect_parents":effect_parents,
            "changed_path":changes[0].get("filename") if len(changes)==1 else None,
            "changed_count":len(changes),
            "changed_status":changes[0].get("status") if len(changes)==1 else None,
            "effect_commit_time":effect["commit"]["committer"]["date"],
            "before_sha256":sha256(pre),
            "after_sha256":sha256(post),
            "before_git_blob":blob_sha1(pre),
            "after_git_blob":blob_sha1(post),
            "remote_git_effect_observed":True,
          },
        }
        # The original GitHub REST API itself asserts exact blob on diff.
        need(len(changes)==1 and
             changes[0].get("sha")==blob_sha1(post) and
             pre_obj.get("sha")==blob_sha1(pre) and
             post_obj.get("sha")==blob_sha1(post),
             "GITHUB_NATIVE_DIFF_OR_CONTENTS_GIT_BLOB_INCONSISTENT")
        return result

def main(argv=None):
    parser=argparse.ArgumentParser(
       description="Reverify a same-run signed source, claimed candidate execution, native GitHub authorization and actual exact Git effect")
    parser.add_argument("--repo",required=True)
    parser.add_argument("--run-id",type=int,required=True)
    parser.add_argument("--workflow-path",required=True)
    parser.add_argument("--artifact-name",required=True)
    parser.add_argument("--expected-actor",required=True)
    parser.add_argument("--out",required=True)
    parser.add_argument("--snapshot-out",help="Optional source-fact JSON; is NOT a standalone signature")
    args=parser.parse_args(argv)
    output=Path(args.out)
    snapshot=Path(args.snapshot_out) if args.snapshot_out else None
    if output.exists() or not output.parent.is_dir() or (
        snapshot is not None and (snapshot.exists() or
        not snapshot.parent.is_dir() or snapshot==output)):
        print("RISU_B33_OUTPUT_LOCATION_REFUSED",file=sys.stderr)
        return 2
    try:
        token=os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN","")
        original=collect_live(args.repo,args.run_id,args.artifact_name,
                              args.workflow_path,token)
        need(original["run"]["actor"]==args.expected_actor,
             "UNEXPECTED_NATIVE_ORIGINAL_RUN_ACTOR")
        verdict=normalize(original)
        verdict["status"]="LIVE_GITHUB_SIGSTORE_SIGNED_SOURCE_EXECUTION_ONE_GIT_EFFECT_CLOSED"
        verdict["verification_mode"]="LIVE_OFFICIAL_GH_SIGSTORE_AND_INDEPENDENT_NATIVE_GITHUB_REST"
        if snapshot is not None:
            with snapshot.open("x",encoding="utf-8") as f:
                json.dump(original,f,indent=2,sort_keys=True)
                f.write("\n")
        with output.open("x",encoding="utf-8") as f:
            json.dump(verdict,f,indent=2,sort_keys=True)
            f.write("\n")
        print("B33_LIVE_THREE_ORIGINAL_SIGSTORE_ATTESTATIONS_PLUS_EXECUTION_LINK_PASS")
        print("B33_LIVE_NATIVE_GITHUB_ACTOR_TIME_EXACT_GIT_BLOBS_AND_PARENT_PASS")
        print("B33_LIVE_NO_INDEPENDENT_HUMAN_OR_TEE_AUTHORIZATION_OVERCLAIM_PASS")
        return 0
    except (Refused,KeyError,TypeError,ValueError,OSError) as exc:
        print("RISU_B33_VERIFICATION_REFUSED: "+str(exc),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
