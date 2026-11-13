"""RISU Probe B29: fail-closed live GitHub independent reviewer and effect binding.

Read-only original GitHub REST verification. Never approves a deployment,
changes permissions or writes to a resource. Critically distinguishes:
  (a) platform-reviewed by the initiating account,
  (b) distinct GitHub account protected-environment approval,
  (c) independently operated human owner authorization,
  (d) claim-specific effect bound to the SAME reviewed run.

Distinct GitHub account is never sufficient evidence of a separately
controlled human or owner-controlled remote resource. All cases must
retain that explicit limitation until independently sourced ownership proof.

This module does not inherit a positive result from B25 or B28.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.request

API="https://api.github.com"
SCHEMA="risu-p6b29-original-github-review-independence-v1"
REPO_RE=re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9_.-]{1,100}$")
ENV_RE=re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
SHA_RE=re.compile(r"^[0-9a-f]{40}$")

def _is_positive_id(value):
    return type(value) is int and value > 0

def _record(label,ok,reason):
    return {"obligation":label,"verified":bool(ok),
            "refusal_code":None if ok else reason}

def _get(api_path,token):
    if not (api_path.startswith("/repos/") and
            ".." not in api_path and "?" not in api_path):
        raise ValueError("Unsafe GitHub REST path")
    request=urllib.request.Request(
        API+api_path,
        headers={"Accept":"application/vnd.github+json",
                 "X-GitHub-Api-Version":"2026-03-10",
                 "User-Agent":"risu-b29-readonly-original-audit",
                 **({"Authorization":"Bearer "+token} if token else {})})
    try:
        with urllib.request.urlopen(request,timeout=25) as r:
            if r.status!=200:raise ValueError("Original API did not return 200")
            raw=r.read(2_000_001)
    except (urllib.error.HTTPError,urllib.error.URLError) as e:
        raise ValueError("Original GitHub API unavailable / insufficient read permissions") from e
    if len(raw)>2_000_000:
        raise ValueError("Oversized original GitHub response")
    return json.loads(raw)

def acquire_original(repo,run_id,environment,effect_repo=None,effect_run_id=None,token=""):
    if (not REPO_RE.fullmatch(repo) or
        not ENV_RE.fullmatch(environment) or
        not _is_positive_id(run_id)):
        raise ValueError("Bad original GitHub target")
    if effect_repo is None:effect_repo=repo
    if effect_run_id is None:effect_run_id=run_id
    if not REPO_RE.fullmatch(effect_repo) or not _is_positive_id(effect_run_id):
        raise ValueError("Bad exact effect origin")
    primary="/repos/"+repo+"/actions/runs/"+str(run_id)
    return {
        "review_run":_get(primary,token),
        "review_events":_get(primary+"/approvals",token),
        "review_environment":_get("/repos/"+repo+"/environments/"+environment,token),
        "effect_run":_get("/repos/"+effect_repo+"/actions/runs/"+str(effect_run_id),token),
        "expected_environment":environment,
        "source":"LIVE_ORIGINAL_GITHUB_REST_READ_ONLY",
    }

def assess(data, trusted_live_original_api=False):
    """Assess independent GitHub identities and run-to-effect binding.

    A positive platform result is *not* human independence or owner control.
    A fully effective owner authorization would additionally require:
    independent operator-controlled resource, signed/approved exact intent,
    issuer and target credential scope, observed exact remote effect.
    No synthetic evidence can satisfy those by being merely labeled so.
    """
    run=data.get("review_run")
    env=data.get("review_environment")
    approvals=data.get("review_events")
    effect=data.get("effect_run")
    expected_env=data.get("expected_environment")
    if not (isinstance(run,dict) and isinstance(env,dict) and
            isinstance(approvals,list) and isinstance(effect,dict) and
            isinstance(expected_env,str)):
        raise ValueError("Missing original GitHub input records")
    _checks=[]
    def require(name,condition,reason):
        _checks.append(_record(name,condition,reason))
    src=run.get("repository") or {}
    out=effect.get("repository") or {}
    actor=run.get("actor") or {}
    trigger=run.get("triggering_actor") or {}
    actor_id=actor.get("id")
    trigger_id=trigger.get("id")
    run_id=run.get("id")
    attempt=run.get("run_attempt")
    head_sha=run.get("head_sha")
    src_id=src.get("id")
    effect_id=effect.get("id")
    effect_repo_id=out.get("id")
    effect_sha=effect.get("head_sha")
    env_id=env.get("id")
    require("github_run_identity",
        all(_is_positive_id(v) for v in (run_id,src_id,actor_id,trigger_id,attempt)) and
        type(head_sha) is str and SHA_RE.fullmatch(head_sha) is not None and
        src.get("full_name") and (run.get("status")=="completed") and
        (run.get("conclusion")=="success"),
        "GITHUB_RUN_IDENTITY_OR_EXECUTION_UNVERIFIED")
    require("review_environment_unchanged",
        env.get("name")==expected_env and _is_positive_id(env_id),
        "REVIEW_ENVIRONMENT_IDENTITY_UNVERIFIED")
    # GitHub shows current protection rules. Do not call them historical
    # approval-time protection if the environment has been edited since the
    # original run started.
    def parse_time(value):
        if type(value) is not str:
            return None
        try:
            timestamp=datetime.fromisoformat(value.replace("Z","+00:00"))
            if timestamp.tzinfo is None:
                return None
            return timestamp.astimezone(timezone.utc)
        except ValueError:
            return None
    policy_time=parse_time(env.get("updated_at"))
    run_time=parse_time(run.get("run_started_at"))
    require("environment_policy_unchanged_since_run_start",
        policy_time is not None and run_time is not None and
        policy_time <= run_time,
        "POST_HOC_ENVIRONMENT_PROTECTION_CHANGE_OR_UNVERIFIABLE_TIME")
    require("single_reviewable_run_attempt",
        attempt==1,
        "REVIEW_EVENT_NOT_BOUND_TO_SPECIFIC_RETRY_ATTEMPT")
    protection=env.get("protection_rules")
    rules=protection if isinstance(protection,list) else []
    required=[r for r in rules if isinstance(r,dict)
              and r.get("type")=="required_reviewers"]
    require("environment_has_unambiguous_required_reviewer",
        len(required)==1 and isinstance(required[0].get("reviewers"),list),
        "NATIVE_REQUIRED_REVIEWER_PROTECTION_MISSING")
    rule=required[0] if len(required)==1 else {}
    reviewers=rule.get("reviewers") or []
    allowed_ids={(r.get("reviewer") or {}).get("id") for r in reviewers
                 if isinstance(r,dict) and r.get("type")=="User" and
                 isinstance(r.get("reviewer"),dict) and _is_positive_id(
                     (r.get("reviewer") or {}).get("id"))}
    require("platform_prevents_self_review",
        rule.get("prevent_self_review") is True,
        "GITHUB_NATIVE_PREVENT_SELF_REVIEW_DISABLED")
    require("platform_prevents_admin_bypass",
        env.get("can_admins_bypass") is False,
        "GITHUB_NATIVE_ADMIN_BYPASS_NOT_DISABLED")
    branchpolicy=env.get("deployment_branch_policy") or {}
    require("native_branch_scope_protection",
        branchpolicy.get("custom_branch_policies") is True or
        branchpolicy.get("protected_branches") is True,
        "GITHUB_DEPLOYMENT_BRANCH_SCOPE_NOT_PROTECTED")
    matching=[]
    for review in approvals:
        if not isinstance(review,dict) or review.get("state")!="approved":
            continue
        related=review.get("environments") or []
        if any(isinstance(e,dict) and e.get("id")==env_id and
               e.get("name")==expected_env for e in related):
            matching.append(review)
    require("run_specific_live_approval",
        len(matching)>0,"APPROVAL_RECORD_FOR_EXACT_RUN_AND_ENVIRONMENT_MISSING")
    approved_valid=[review for review in matching if
        _is_positive_id((review.get("user") or {}).get("id")) and
        (review["user"]["id"] in allowed_ids)]
    require("reviewer_in_platform_required_user_list",
        len(approved_valid)>0,
        "APPROVER_NOT_EXACT_GITHUB_REQUIRED_USER")
    distinct=[r for r in approved_valid
              if r["user"]["id"]!=actor_id and r["user"]["id"]!=trigger_id]
    require("reviewer_distinct_from_requesting_and_retriggering_accounts",
        len(distinct)>0 and
        _is_positive_id(actor_id) and _is_positive_id(trigger_id),
        "SELF_APPROVAL_OR_NONINDEPENDENT_PLATFORM_PRINCIPAL")
    require("no_unapproved_review_present",all(
       not (isinstance(a,dict) and a.get("state")=="rejected" and
         any(isinstance(e,dict) and e.get("id")==env_id
             for e in (a.get("environments") or [])))
       for a in approvals),"REJECTED_DEPLOYMENT_NOT_APPROVED")
    require("same_reviewed_execution_as_claimed_effect",
        (_is_positive_id(effect_id) and effect_id==run_id and
         _is_positive_id(effect_repo_id) and effect_repo_id==src_id and
         effect.get("run_attempt")==attempt and effect_sha==head_sha and
         effect.get("status")=="completed" and effect.get("conclusion")=="success"),
        "CROSS_REPOSITORY_RUN_OR_REVISION_APPROVAL_STITCHING")
    # A separate real human cannot be proven merely from GitHub account IDs,
    # and a successful run is not an original-resource effect audit.
    necessary=[x for x in _checks if not x["verified"]]
    structural_match=len(necessary)==0
    platform_verified=structural_match and trusted_live_original_api is True
    review_ids=sorted({a["user"]["id"] for a in matching
                       if isinstance(a.get("user"),dict) and
                       _is_positive_id(a["user"].get("id"))})
    report={
       "schema":SCHEMA,
       "status":("PLATFORM_DISTINCT_ACCOUNT_REVIEW_BOUND_TO_SAME_RUN"
                 if platform_verified else
                 "SYNTHETIC_STRUCTURAL_MATCH_NOT_REAL_GITHUB_PROOF"
                 if structural_match else "REFUSED_UNSUPPORTED_INDEPENDENT_APPROVAL"),
       "mode":"LIVE_ORIGINAL_GITHUB_REST" if trusted_live_original_api is True
              and data.get("source")=="LIVE_ORIGINAL_GITHUB_REST_READ_ONLY"
              else "OFFLINE_TEST_OR_RECORDED_DATA",
       "structural_platform_review_rule_match":structural_match,
       "obligations":_checks,
       "refusals":[x["refusal_code"] for x in necessary],
       "original_github_review_source":{
          "repo_id":src_id,"run_id":run_id,"attempt":attempt,
          "head_sha":head_sha,"environment_id":env_id,
          "run_actor_id":actor_id,"run_trigger_id":trigger_id,
          "approved_user_ids":review_ids,
       },
       "claimed_effect_source":{
          "repo_id":effect_repo_id,"run_id":effect_id,
          "attempt":effect.get("run_attempt"),"head_sha":effect_sha,
       },
       "supported_claims":{
          "github_distinct_account_approval_same_run":platform_verified,
          "historical_protection_configuration_unmodified_since_start":
              policy_time is not None and run_time is not None and policy_time<=run_time,
          "independently_controlled_human_owner":False,
          "owner_signed_exact_resource_intent":False,
          "real_remote_resource_effect_independently_verified":False,
          "native_credential_issuer_scope_verified":False,
          "cross_experiment_approval_reuse_permitted":False,
       },
       "missing_owner_specific_proofs":[
          "Independent resource operator identity and authorized capacity",
          "Owner-originated cryptographic or platform-verifiable intent binding",
          "Scope-bound issuer credential granted for that exact intent",
          "Independent observed exact remote effects in the same authorized execution",
       ],
    }
    return report

def main(argv=None):
    p=argparse.ArgumentParser(
       description="Read-only independent-account GitHub approval and same-run effect binding audit")
    p.add_argument("--repo",required=True)
    p.add_argument("--run-id",type=int,required=True)
    p.add_argument("--environment",required=True)
    p.add_argument("--effect-repo")
    p.add_argument("--effect-run-id",type=int)
    p.add_argument("--out",required=True)
    args=p.parse_args(argv)
    output=Path(args.out)
    if output.exists() or not output.parent.is_dir():
        print("B29_REFUSED_OUTPUT_OVERWRITE_OR_DIRECTORY",file=sys.stderr)
        return 2
    try:
        originals=acquire_original(args.repo,args.run_id,args.environment,
             effect_repo=args.effect_repo,effect_run_id=args.effect_run_id,
             token=os.environ.get("GITHUB_TOKEN",""))
        report=assess(originals, trusted_live_original_api=True)
        # No credential is ever persisted; only numeric GitHub identities,
        # checked run commit and selected native environment policy status.
        fd=os.open(output,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(fd,"w",encoding="utf-8") as file:
            json.dump(report,file,indent=2,sort_keys=True)
            file.write("\n")
        print("RISU_B29_GITHUB_ORIGINAL_EVIDENCE_"+report["status"])
        for code in report["refusals"]:
            print("B29_ORIGINAL_REFUSAL: "+code)
        return 0 if report["supported_claims"][
            "github_distinct_account_approval_same_run"] else 2
    except (ValueError,TypeError,KeyError,OSError,UnicodeError) as err:
        print("B29_REFUSED_ORIGINAL_SOURCE_UNAVAILABLE_OR_MALFORMED: "+
              str(err),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
