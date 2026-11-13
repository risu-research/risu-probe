"""RISU P6-B30: verify an actual GitHub review-to-resource-effect closure.

Checks a *live immutable* run source, exact proposal, native GitHub review,
direct commit ancestry, exact preimage/postimage SHA256 and Git blob IDs,
and changed-file cardinality. It never infers independent owner identity
from a platform approval or transfers consent across different executions.

This is a source-specific adapter for GitHub Contents PUT, not a generic
signed provenance verifier. Future adapters may reuse assess_closure()'s
obligation and binding structure without treating GitHub as universal.
"""
from __future__ import annotations
import argparse
import base64
import binascii
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
from urllib.parse import quote
import urllib.error
import urllib.request

SCHEMA="risu-p6b30-real-github-claim-effect-closure-v1"
API="https://api.github.com"
REPO=re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,99}/[a-zA-Z0-9_.-]{1,100}$")
SHA40=re.compile(r"^[a-f0-9]{40}$")
ID_ENV=re.compile(r"^[a-zA-Z0-9_.-]{1,100}$")
RUN_ORIGIN="LIVE_GITHUB_API_2022_11_28"
MAX_BYTES=2_000_000

def valid_path(path):
    return (type(path) is str and 0<len(path)<600 and
            not path.startswith("/") and
            not any(p in ("",".","..") for p in path.split("/")) and
            "\x00" not in path and "\\" not in path and
            all(ord(c)>=33 for c in path))

def digest(data):
    return hashlib.sha256(data).hexdigest()

def blob_id(data):
    raw=b"blob "+str(len(data)).encode()+b"\0"+data
    return hashlib.sha1(raw).hexdigest()

def strict_json_bytes(data):
    def pair_handler(pairs):
        mapping={}
        for k,v in pairs:
            if k in mapping:raise ValueError("ambiguous duplicate JSON keys")
            mapping[k]=v
        return mapping
    def bad_constant(x):
        raise ValueError("non-finite JSON constant")
    return json.loads(data,object_pairs_hook=pair_handler,
                      parse_constant=bad_constant)

def _read(path,token):
    if not path.startswith("/repos/") or ".." in path:
        raise ValueError("Invalid GitHub API route")
    url=API+path
    headers={
       "Accept":"application/vnd.github+json",
       "X-GitHub-Api-Version":"2022-11-28",
       "User-Agent":"risu-probe-b30-claim-effect-closure",
    }
    if token:
        headers["Authorization"]="Bearer "+token
    req=urllib.request.Request(url,headers=headers)
    try:
        with urllib.request.urlopen(req,timeout=30) as response:
            if response.status!=200:
                raise ValueError("GitHub original source did not return HTTP 200")
            data=response.read(MAX_BYTES+1)
    except (urllib.error.HTTPError,urllib.error.URLError) as e:
        raise ValueError("GitHub original data unavailable or access denied") from e
    if len(data)>MAX_BYTES:
        raise ValueError("Original GitHub payload exceeded size limit")
    return strict_json_bytes(data)

def decode_contents(original):
    if not isinstance(original,dict):
        raise ValueError("Missing GitHub contents object")
    if original.get("encoding")!="base64" or original.get("type")!="file":
        raise ValueError("Original GitHub contents not a single base64 file")
    content=original.get("content")
    if type(content) is not str:
        raise ValueError("Missing base64 payload")
    # GitHub API may fold Base64 with CR/LF; no other noncanonical bytes.
    folded=content.replace("\r","").replace("\n","")
    try:
        encoded=folded.encode("ascii")
        result=base64.b64decode(encoded,validate=True)
    except (UnicodeEncodeError,binascii.Error) as ex:
        raise ValueError("Malformed original GitHub Base64") from ex
    if base64.b64encode(result)!=encoded:
        raise ValueError("Noncanonical Base64 in original GitHub API")
    if original.get("size")!=len(result) or original.get("sha")!=blob_id(result):
        raise ValueError("GitHub Contents metadata and actual raw bytes disagree")
    return result

def iso(value):
    if type(value) is not str:
        return None
    try:
        out=datetime.fromisoformat(value.replace("Z","+00:00"))
        if out.tzinfo is None:
            return None
        return out.astimezone(timezone.utc)
    except ValueError:
        return None

def _check(name,condition,why):
    return {"obligation":name,
            "verified":bool(condition),
            "refusal_code":None if condition else why}

def assess_closure(raw):
    """Pure, deterministic statement binding; no external trust is added here.

    This function is reusable for negative fixtures. Only main() sets
    source_mode LIVE after actual GitHub GETs. Caller-controlled data cannot
    self-label as a live proof.
    """
    required={"run","approvals","environment","proposal","before",
              "after","effect_commit"}
    if type(raw) is not dict or not required.issubset(raw):
        raise ValueError("Evidence sources missing")
    run=raw["run"];reviews=raw["approvals"];env=raw["environment"]
    before=raw["before"];after=raw["after"]
    commit=raw["effect_commit"];proposal=raw["proposal"]
    if (not all(type(x) is dict for x in (run,env,before,after,commit,proposal))
          or type(reviews) is not list):
        raise ValueError("Malformed evidence source record")
    src=run.get("repository") or {}
    review_actor=run.get("actor") or {}
    trigger_actor=run.get("triggering_actor") or {}
    run_id=run.get("id");run_sha=run.get("head_sha");attempt=run.get("run_attempt")
    repo_id=src.get("id");repo_name=src.get("full_name")
    commit_sha=commit.get("sha")
    owners=proposal.get("owner_repository_id")
    path=proposal.get("resource_path")
    env_name=proposal.get("review_environment")
    env_id=env.get("id")
    expected_sha=proposal.get("expected_prior_content_sha256")
    desired_sha=proposal.get("desired_content_sha256")
    before_sha=before.get("sha")
    after_sha=after.get("sha")
    before_data=decode_contents(before)
    after_data=decode_contents(after)
    checks=[]
    def add(name,ok,code):
        checks.append(_check(name,ok,code))
    add("native_original_run_source",
        type(repo_id) is int and repo_id>0
        and type(run_id) is int and run_id>0 and
        type(attempt) is int and attempt==1 and
        type(run_sha) is str and SHA40.fullmatch(run_sha) is not None and
        type(repo_name) is str and REPO.fullmatch(repo_name) is not None and
        run.get("status")=="completed" and run.get("conclusion")=="success",
        "ORIGINAL_GITHUB_RUN_UNVERIFIED")
    add("native_original_proposal",
        proposal.get("schema")=="risu-b25-single-repo-file-owner-review-request-v1"
        and proposal.get("proposal_status")=="UNAPPROVED_UNTIL_GITHUB_ENVIRONMENT_REVIEW_EVENT"
        and proposal.get("authorization_type")=="GITHUB_REQUIRED_REVIEWER_DIRECT_HUMAN_APPROVAL"
        and proposal.get("requested_github_api_method")=="PUT"
        and proposal.get("owner_repository")==repo_name and owners==repo_id
        and valid_path(path)
        and type(env_name) is str and ID_ENV.fullmatch(env_name) is not None
        and proposal.get("requested_git_path")==
            "repos/"+str(repo_name)+"/contents/"+str(path),
        "PROPOSAL_OR_RESOURCE_SCOPE_NOT_BOUND_TO_ORIGINAL_REPOSITORY")
    add("native_run_review_environment",
        env_name==env.get("name") and
        type(env_id) is int and env_id>0 and
        env.get("can_admins_bypass") is False and
        iso(env.get("updated_at")) is not None and
        iso(run.get("run_started_at")) is not None and
        iso(env.get("updated_at"))<=iso(run.get("run_started_at")),
        "NO_HISTORICALLY_UNCHANGED_NATIVE_REVIEW_ENVIRONMENT")
    rules=env.get("protection_rules") or []
    rules=[x for x in rules if type(x) is dict] if type(rules) is list else []
    allow_ids={r.get("reviewer",{}).get("id") for x in rules
               if x.get("type")=="required_reviewers"
               for r in (x.get("reviewers") or []) if type(r) is dict and
               r.get("type")=="User" and type(r.get("reviewer")) is dict}
    approvals=[r for r in reviews if type(r) is dict and r.get("state")=="approved" and
               any(type(e) is dict and e.get("id")==env_id
                   and e.get("name")==env_name
                   for e in (r.get("environments") or []))]
    review_ids={r.get("user",{}).get("id") for r in approvals if
                type(r.get("user")) is dict and
                type(r.get("user",{}).get("id")) is int}
    add("native_approved_review_of_exact_run",
        len(approvals)>0 and bool(review_ids & allow_ids) and
        type(review_actor.get("id")) is int and
        type(trigger_actor.get("id")) is int and
        proposal.get("expected_reviewer_login") in
        [r.get("user",{}).get("login") for r in approvals
         if type(r.get("user")) is dict] and
        not any(type(r) is dict and r.get("state")=="rejected" and
                any(type(e) is dict and e.get("id")==env_id for e in
                    (r.get("environments") or [])) for r in reviews),
        "NO_ORIGINAL_RUN_SPECIFIC_HUMAN_REVIEW")
    # First-class distinction: B25 permits valid platform self-review;
    # that observation does NOT prove independent external owner consent.
    different_account=bool(
        {id for id in review_ids if id in allow_ids and
         id!=review_actor.get("id") and id!=trigger_actor.get("id")})
    self_review_protected=any(
        x.get("type")=="required_reviewers" and
        x.get("prevent_self_review") is True for x in rules)
    add("original_source_to_effect_commit_ancestry",
        type(commit_sha) is str and SHA40.fullmatch(commit_sha) is not None
        and type(commit.get("parents")) is list and
        len(commit["parents"])==1 and
        type(commit["parents"][0]) is dict and
        commit["parents"][0].get("sha")==run_sha and
        commit_sha!=run_sha,
        "EFFECT_COMMIT_NOT_DIRECT_CHILD_OF_REVIEWED_SOURCE")
    modifications=commit.get("files") or []
    add("exact_one_modified_owner_resource",
        type(modifications) is list and
        len(modifications)==1 and type(modifications[0]) is dict and
        modifications[0].get("filename")==path and
        modifications[0].get("status")=="modified" and
        modifications[0].get("sha")==after_sha and
        commit.get("stats",{}).get("total",0)>0,
        "COMMIT_MODIFIED_DIFFERENT_OR_ADDITIONAL_RESOURCE")
    add("exact_original_precondition",
        before_sha==proposal.get("expected_prior_git_blob") and
        digest(before_data)==expected_sha and
        blob_id(before_data)==before_sha,
        "ACTUAL_GIT_PREIMAGE_DIFFERS_FROM_OWNER_REQUEST")
    add("exact_original_effect_bytes",
        after_sha==proposal.get("desired_git_blob",after_sha) and
        digest(after_data)==desired_sha and
        after_data==str(proposal.get("desired_content","")).encode("utf-8") and
        blob_id(after_data)==after_sha and
        digest(before_data)!=digest(after_data),
        "ACTUAL_GIT_POSTIMAGE_DIFFERS_FROM_OWNER_REQUEST")
    add("proposal_ref_and_effect_file_ref",
        before.get("path")==path and after.get("path")==path and
        before.get("url","").find("ref=")!=-1 and
        after.get("url","").find("ref=")!=-1,
        "EFFECT_FILE_NOT_FETCHED_FROM_EXACT_IMMUTABLE_REFS")
    # This is a source-specific lower tier: platform review + concrete
    # exact resource effect, NOT a complete distinct-owner authorization.
    failures=[x["refusal_code"] for x in checks if not x["verified"]]
    observed_platform=len(failures)==0
    out={
       "schema":SCHEMA,
       "status":"RECORDED_STRUCTURE_MATCH_NOT_LIVE_PROOF"
          if observed_platform else "REFUSED_EFFECT_EVIDENCE_CLOSURE",
       "verifier_mode":"STRUCTURAL_ONLY",
       "refusals":failures,"obligations":checks,
       "source":{
           "repo_id":repo_id,"repo":repo_name,
           "run_id":run_id,"attempt":attempt,
           "run_head_commit":run_sha,
           "effect_commit":commit_sha,
           "review_environment":env_name,
           "review_user_ids":sorted(review_ids),
           "initiating_user_id":review_actor.get("id"),
           "triggering_user_id":trigger_actor.get("id"),
           "resource_path":path,
           "preimage_sha256":digest(before_data),
           "postimage_sha256":digest(after_data),
           "preimage_git_blob":blob_id(before_data),
           "postimage_git_blob":blob_id(after_data),
       },
       "supported_claims":{
           "same_run_source_to_exact_one_file_effect":False,
           "native_platform_review_history":False,
           "two_different_github_account_review":False,
           "independent_human_resource_owner":False,
           "native_github_token_file_path_scope":False,
           "owner_signed_intent":False,
           "cross_experiment_consent_transfer":False,
       },
       "observed_structural_closure":observed_platform,
       "observed_distinct_reviewer_account":different_account,
       "native_prevent_self_review_enabled":self_review_protected,
       "interpretation":"Exact Git ancestry and content are necessary but not by themselves proof of human identity, request causation, or signed owner authority.",
    }
    return out

def fetch_live(repo,run_id,environment,proposal_path,effect_commit,token=""):
    if not (type(repo) is str and REPO.fullmatch(repo) and
            type(run_id) is int and run_id>0 and
            type(environment) is str and ID_ENV.fullmatch(environment)
            and valid_path(proposal_path) and
            type(effect_commit) is str and SHA40.fullmatch(effect_commit)):
        raise ValueError("Unsafe GitHub original target arguments")
    path="/repos/"+repo
    run=_read(path+"/actions/runs/"+str(run_id),token)
    runsha=run.get("head_sha")
    if type(runsha) is not str or not SHA40.fullmatch(runsha):
        raise ValueError("GitHub original run has no immutable head commit")
    commit=_read(path+"/commits/"+effect_commit,token)
    file_path=None
    # Proposal is taken from the immutable reviewed source, not latest main.
    proposal_bytes=decode_contents(_read(
        path+"/contents/"+quote(proposal_path,safe="/")+"?ref="+runsha,token))
    if len(proposal_bytes)>20000:
        raise ValueError("Original proposal unexpectedly large")
    proposal=strict_json_bytes(proposal_bytes)
    resource=proposal.get("resource_path")
    if not valid_path(resource):
        raise ValueError("Malformed original proposal resource path")
    orig_path=path+"/contents/"+quote(resource,safe="/")
    return {
        "run":run,
        "approvals":_read(path+"/actions/runs/"+str(run_id)+"/approvals",token),
        "environment":_read(path+"/environments/"+quote(environment,safe=""),token),
        "effect_commit":commit,
        "proposal":proposal,
        "before":_read(orig_path+"?ref="+runsha,token),
        "after":_read(orig_path+"?ref="+effect_commit,token),
    }

def main(argv=None):
    p=argparse.ArgumentParser(description="Original GitHub run review to exact resource effect closure")
    p.add_argument("--repo",required=True)
    p.add_argument("--run-id",type=int,required=True)
    p.add_argument("--environment",required=True)
    p.add_argument("--proposal-path",required=True)
    p.add_argument("--effect-commit",required=True)
    p.add_argument("--out",required=True)
    args=p.parse_args(argv)
    out_path=Path(args.out)
    if not out_path.parent.is_dir() or out_path.exists():
        print("RISU_B30_OUTPUT_REFUSED",file=sys.stderr)
        return 2
    try:
        original=fetch_live(
           args.repo,args.run_id,args.environment,args.proposal_path,
           args.effect_commit,token=os.environ.get("GITHUB_TOKEN",""))
        report=assess_closure(original)
        if report["observed_structural_closure"]:
            report["verifier_mode"]="LIVE_ORIGINAL_GITHUB_REST"
            report["status"]="PLATFORM_REVIEW_AND_EXACT_GIT_EFFECT_CLOSED"
            report["supported_claims"]["same_run_source_to_exact_one_file_effect"]=True
            report["supported_claims"]["native_platform_review_history"]=True
            report["supported_claims"]["two_different_github_account_review"]=(
                report["observed_distinct_reviewer_account"] and
                report["native_prevent_self_review_enabled"])
        fd=os.open(out_path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(fd,"w",encoding="utf-8") as file:
            json.dump(report,file,sort_keys=True,indent=2)
            file.write("\n")
        print("RISU_B30_"+report["status"])
        for c in report["refusals"]:
            print("B30_REFUSED: "+c)
        return 0 if report["status"]=="PLATFORM_REVIEW_AND_EXACT_GIT_EFFECT_CLOSED" else 2
    except (ValueError,UnicodeError,OSError,TypeError,KeyError) as err:
        print("RISU_B30_ORIGINAL_GITHUB_REFUSED: "+str(err),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
