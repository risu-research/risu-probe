"""RISU B30: heterogeneous claim-specific authority/effect obligation join.

Takes separately verified, pinned *recorded* B25/B27/B28/B29 outputs;
never treats success in one original backend as permission for a different
backend or resource. This is a proof-obligation checker, NOT a cryptographic
verification of arbitrary unsigned JSON. Original source adapters and
independent raw-audit checks must precede this cross-artifact comparison.

The 4-case study deliberately includes (1) real GitHub reviewed effect,
(2) original PostgreSQL RLS, (3) original SeaweedFS IAM and (4) original
OpenBao-to-PostgreSQL leased effect. They are separate operations.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import sys

SCHEMA="risu-b30-cross-original-claim-specific-obligation-join-v1"
B25="risu-p6b30-real-github-claim-effect-closure-v1"
B27="risu-p6b27-heterogeneous-original-backend-effect-matrix-v1"
B28="risu-b28-cross-publisher-claim-specific-evidence-certificate-v1"
B29="risu-p6b29-original-github-review-independence-v1"
ROOT_REQUIREMENTS=(
 "real_independent_owner_approval",
 "issuer_is_owner_scope_bound",
 "exact_approved_resource_identity",
 "exact_approved_result_bytes",
 "one_way_expected_state",
 "replay_refused",
 "native_revocation",
 "independent_resource_effect_audit",
)
class Rejected(Exception):
    pass
def need(ok,msg):
    if not ok:raise Rejected(msg)
def unique_key(x):
    return json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=False)
def strict_load(path):
    p=Path(path)
    need(p.is_file() and not p.is_symlink(),"EVIDENCE_FILE_MISSING_OR_SYMLINK")
    need(0<p.stat().st_size<2_000_000,"EVIDENCE_SIZE_INVALID")
    def pairs(kvs):
        d={}
        for k,v in kvs:
            if k in d: raise Rejected("EVIDENCE_DUPLICATE_JSON_KEY")
            d[k]=v
        return d
    with p.open("r",encoding="utf-8") as h:
        return json.load(h,object_pairs_hook=pairs)
def observed_case(label,subject,verified,origin,limits,refuted=()):
    need(type(verified) is dict and set(verified)==set(ROOT_REQUIREMENTS),
         "INCOMPLETE_CLAIM_OBLIGATION_LABELS")
    need(all(type(x) is bool for x in verified.values()),
         "CLAIM_OBLIGATIONS_NOT_BOOLEAN")
    refuted=set(refuted)
    need(refuted.issubset(ROOT_REQUIREMENTS) and
         not any(verified[p] for p in refuted),
         "REFUTATION_CONTRADICTS_VERIFIED_CLAIM")
    # A positive counterexample is stronger than lack of evidence. Keep
    # REFUTED and UNVERIFIED separate even though both deny certification.
    evidence_states={
       p:("VERIFIED" if verified[p] else
          "REFUTED" if p in refuted else "UNVERIFIED")
       for p in ROOT_REQUIREMENTS
    }
    return {
      "label":label,"subject":subject,"subject_key":unique_key(subject),
      "provenance":origin,
      "obligations":verified,
      "evidence_states":evidence_states,
      "supported":[p for p in ROOT_REQUIREMENTS if verified[p]],
      "refuted":[p for p in ROOT_REQUIREMENTS if p in refuted],
      "unverified":[p for p in ROOT_REQUIREMENTS
                    if not verified[p] and p not in refuted],
      "missing":[p for p in ROOT_REQUIREMENTS if not verified[p]],
      "full_owner_specific_closure":all(verified.values()),
      "limits":limits,
    }
def check_b25(b30,b29):
    need(b30.get("schema")==B25 and
         b30.get("status")=="PLATFORM_REVIEW_AND_EXACT_GIT_EFFECT_CLOSED" and
         b30.get("verifier_mode")=="LIVE_ORIGINAL_GITHUB_REST" and
         b30.get("supported_claims",{}).get(
             "same_run_source_to_exact_one_file_effect") is True,
         "GITHUB_ORIGINAL_EFFECT_NOT_LIVE_CLOSED")
    g=b30.get("source") or {}
    need(type(g.get("repo_id")) is int and
         type(g.get("run_id")) is int and g.get("attempt")==1 and
         type(g.get("resource_path")) is str and
         type(g.get("preimage_sha256")) is str and
         len(g["preimage_sha256"])==64 and
         type(g.get("postimage_sha256")) is str and
         len(g["postimage_sha256"])==64 and
         len(g.get("run_head_commit",""))==40 and
         len(g.get("effect_commit",""))==40,
         "B25_GITHUB_RESOURCE_PROVENANCE_MISSING")
    need(b29.get("schema")==B29 and b29.get("mode")=="LIVE_ORIGINAL_GITHUB_REST" and
         b29.get("status")=="REFUSED_UNSUPPORTED_INDEPENDENT_APPROVAL" and
         "SELF_APPROVAL_OR_NONINDEPENDENT_PLATFORM_PRINCIPAL" in b29.get("refusals",[]) and
         "GITHUB_NATIVE_PREVENT_SELF_REVIEW_DISABLED" in b29.get("refusals",[]),
         "B29_ACTUAL_SELF_REVIEW_NEGATIVE_MISSING")
    origin=b29.get("original_github_review_source") or {}
    effect=b29.get("claimed_effect_source") or {}
    need(
        origin.get("repo_id")==g["repo_id"] and
        origin.get("run_id")==g["run_id"] and
        origin.get("attempt")==g["attempt"] and
        origin.get("head_sha")==g["run_head_commit"] and
        effect.get("repo_id")==g["repo_id"] and
        effect.get("run_id")==g["run_id"] and
        effect.get("attempt")==g["attempt"] and
        effect.get("head_sha")==g["run_head_commit"],
        "REAL_B25_B29_DIFFERENT_RUN_PROVENANCE")
    sc=b30["supported_claims"]
    need(sc.get("native_platform_review_history") is True and
         sc.get("independent_human_resource_owner") is False and
         sc.get("native_github_token_file_path_scope") is False and
         b29.get("supported_claims",{}).get(
             "independently_controlled_human_owner") is False,
         "GITHUB_SELF_REVIEW_OVERCLAIM")
    return observed_case(
       "B25_REAL_GITHUB_OWNER_REVIEWED_ONE_FILE",
       {"kind":"github_contents_file","repo_id":g["repo_id"],
        "path":g["resource_path"],"reviewed_run":g["run_id"],
        "source_sha":g["run_head_commit"],
        "effect_commit":g["effect_commit"]},
       {
         "real_independent_owner_approval":False,
         "issuer_is_owner_scope_bound":False,
         "exact_approved_resource_identity":True,
         "exact_approved_result_bytes":True,
         "one_way_expected_state":True,
         "replay_refused":False,
         "native_revocation":False,
         "independent_resource_effect_audit":False,
       },
       "LIVE_GITHUB_B30_SOURCE_ANCESTRY_B29_REVIEWER_NEGATIVE",
       ["One-file actual Git parent/effect confirmed but original recorded independent resource audit not included in B30's source set.",
        "Native GITHUB_TOKEN is repository-scoped, not file path constrained.",
        "Reviewing user matches the actor; third-party owner consent absent."],
    )
def check_b27(matrix):
    need(matrix.get("schema")==B27 and
         matrix.get("status")=="PASS_BOTH_ORIGINAL_BACKEND_AUDITS_AND_DIFFERENTIAL_EFFECTS" and
         matrix.get("qualifying_external_implementations")==2 and
         matrix.get("not_a_security_vulnerability_claim") is True,
         "B27_ORIGINAL_EXTERNAL_HOLDOUT_NOT_INDEPENDENTLY_AUDITED")
    by={x.get("backend"):x for x in matrix.get("backends",[])
        if type(x) is dict}
    need(len(by)==2 and set(by)=={"PostgreSQL","SeaweedFS"},
         "B27_ORIGINAL_COMPARISON_BACKEND_SET_CHANGED")
    a=by["PostgreSQL"]; b=by["SeaweedFS"]
    for backend in (a,b):
        need(backend.get("actual_effect_independently_audited") is True and
             backend.get("real_unrelated_third_party_human_approval") is False,
             "B27_NATIVE_AUDIT_OR_HUMAN_OWNER_NOT_PRESERVED")
    properties=["path_object_scope","exact_desired_bytes",
                "direction_precondition","one_time_effect","native_issuer_revocation"]
    need(all(type(a.get(p)) is dict and type(b.get(p)) is dict and
             type(a[p].get("enforced")) is bool and
             type(b[p].get("enforced")) is bool for p in properties),
         "B27_INCOMPLETE_NATIVE_BACKEND_PROPERTY_RESULT")
    need([a[p]["enforced"] for p in properties]==[True]*5,
         "B27_NATIVE_POSTGRESQL_ORIGINAL_RLS_PROPERTY_REGRESSION")
    need([b[p]["enforced"] for p in properties]==[True,False,False,False,True],
         "B27_ORIGINAL_S3_PROPERTY_HOLDOUT_OUTCOME_CHANGED")
    need(a.get("observed_unauthorized_change_count")==0 and
         b.get("observed_unauthorized_cross_object_change_count")==0 and
         b.get("actor_os_uid")==65534,
         "B27_REAL_ORIGINAL_DIRECT_WRITE_NEGATIVES_MISSING")
    return [
      observed_case(
        "B27_EXTERNAL_POSTGRESQL_RLS",
        {"kind":"postgres_row","source":"B27_ORIGINAL_PG",
         "database":"risu_b27_external","object_key":"object/approved"},
        {
          "real_independent_owner_approval":False,
          "issuer_is_owner_scope_bound":False,
          "exact_approved_resource_identity":a["path_object_scope"]["enforced"],
          "exact_approved_result_bytes":a["exact_desired_bytes"]["enforced"],
          "one_way_expected_state":a["direction_precondition"]["enforced"],
          "replay_refused":a["one_time_effect"]["enforced"],
          "native_revocation":a["native_issuer_revocation"]["enforced"],
          "independent_resource_effect_audit":True,
        },
        "ORIGINAL_PG_B27_INDEPENDENT_CATALOG_AND_BYTES_RECORDED",
        ["Original external PostgreSQL publisher, but fixture issuer operated by RISU in GitHub CI.",
         "This row's exact owner approval was not made by a separate real person."],
      ),
      observed_case(
        "B27_EXTERNAL_SEAWEEDFS_S3",
        {"kind":"s3_object","source":"B27_ORIGINAL_S3",
         "bucket":"risu-b27-external","key":"approved/report.txt"},
        {
          "real_independent_owner_approval":False,
          "issuer_is_owner_scope_bound":False,
          "exact_approved_resource_identity":b["path_object_scope"]["enforced"],
          "exact_approved_result_bytes":b["exact_desired_bytes"]["enforced"],
          "one_way_expected_state":b["direction_precondition"]["enforced"],
          "replay_refused":b["one_time_effect"]["enforced"],
          "native_revocation":b["native_issuer_revocation"]["enforced"],
          "independent_resource_effect_audit":True,
        },
        "ORIGINAL_S3_B27_NATIVE_IAM_AND_BYTES_RECORDED",
        ["Original S3 IAM exact-object PutObject permits different bytes and repetitions.",
         "No third-party human owner; issuer is controlled fixture."],
        refuted=("exact_approved_result_bytes","replay_refused"),
      ),
    ]
def check_b28(cert):
    need(cert.get("schema")==B28 and
         cert.get("status")=="RECORDED_ORIGINAL_NATIVE_EVIDENCE_CONSISTENT" and
         cert.get("level")==
             "OFFLINE_CROSS_ARTIFACT_VALIDATION_NOT_A_FRESH_REMOTE_VERIFICATION" and
         cert.get("actual_native_denied_resource_cases")==14,
         "B28_ORIGINAL_ISSUER_RESOURCE_CERTIFICATE_NOT_VALID")
    claims={c.get("claim"):c.get("supported_by_recorded_evidence")
            for c in cert.get("claims",[]) if type(c) is dict}
    required={
      "one_use_wrapped_credential_delivery":True,
      "native_database_credentials_issued":True,
      "direct_unauthorized_resource_writes_denied":True,
      "approved_resource_content_transition":True,
      "duplicate_state_effect_prevented":True,
      "native_credential_revocation_enforced_at_new_login":True,
      "independent_readonly_original_data_audit":True,
      "independent_real_human_resource_owner":False,
      "externally_operated_original_services":False,
      "wrapping_token_cryptographically_binds_recipient":False,
    }
    need(all(claims.get(k) is v for k,v in required.items()),
         "B28_NATIVE_LEASE_OR_RESOURCE_SCOPE_OVERCLAIM")
    need(cert.get("owner_before_sha256")==
        "bd081656bc954bcedecb00f38b45e37d4912e6d2587a3e5dc6f89c852e86a5b3" and
         cert.get("owner_after_sha256")==
        "45a0c30f6c9e7250ce05fd258283cc431f72a59cd58e25fd4d57242fe7508a30",
         "B28_ACTUAL_POSTGRESQL_INTENDED_STATE_DIGEST_NOT_FROZEN")
    return observed_case(
       "B28_EXTERNAL_OPENBAO_POSTGRESQL_LEASE",
       {"kind":"postgres_row","source":"B28_OPENBAO_PG",
        "database":"risu_b28_external","object_key":"approved/report",
        "owner_prestate_sha256":cert["owner_before_sha256"],
        "owner_poststate_sha256":cert["owner_after_sha256"]},
       {
         "real_independent_owner_approval":False,
         "issuer_is_owner_scope_bound":True,
         "exact_approved_resource_identity":True,
         "exact_approved_result_bytes":True,
         "one_way_expected_state":True,
         "replay_refused":True,
         "native_revocation":True,
         "independent_resource_effect_audit":True,
       },
       "OPENBAO_ORIGINAL_NATIVE_LEASE_POSTGRESQL_LIVE_AUDITED_RECORDED",
       ["Original issuer and resource are from independent software publishers.",
        "Both servers, fixture identities and owner authorization are operated by RISU in CI.",
        "This certificate is offline original-record consistency, not a fresh operator signature."],
    )

def analyze(b30,b29,b27,b28):
    cases=[check_b25(b30,b29),*check_b27(b27),check_b28(b28)]
    keylist=[c["subject_key"] for c in cases]
    need(len(keylist)==len(set(keylist)),"EVIDENCE_COLLISION_BETWEEN_DIFFERENT_SUBJECTS")
    # Naive union incorrectly upgrades four independently valid *but distinct*
    # experiments into one fictional fully authorized action.
    naive={requirement:any(c["obligations"][requirement] for c in cases)
            for requirement in ROOT_REQUIREMENTS}
    # A control hypothesis deliberately treats "native platform review"
    # in B25 as if it were independent owner authorization. This is the
    # baseline's wrong inference, never endorsed by the RISU evaluator.
    naive_owner_proxy=(
        b30["supported_claims"]["native_platform_review_history"] is True
    )
    naive["real_independent_owner_approval"]=naive_owner_proxy
    strict_full=[c for c in cases if c["full_owner_specific_closure"]]
    # Find the closest provable case without transferring any claims.
    diagnostic=sorted(cases,key=lambda x:(len(x["missing"]),x["label"]))
    report={
      "schema":SCHEMA,
      "status":"FOUR_INDEPENDENT_ORIGINAL_CLAIM_SUBJECTS_NEVER_FALSE_JOINED",
      "mode":"RECORDED_ORIGINAL_GITHUB_ACTIONS_EVIDENCE_COMPARISON",
      "subject_count":len(cases),
      "subjects":cases,
      "owner_approved_full_execution_proven":len(strict_full)>0,
      "full_closure_subject_keys":[c["subject_key"] for c in strict_full],
      "proof_obligations":list(ROOT_REQUIREMENTS),
      "evidence_state_semantics":{
         "VERIFIED":"the required source-specific observation is present and matches",
         "REFUTED":"an original observed counterexample contradicts the required claim",
         "UNVERIFIED":"not established by the checked original evidence; may have other sources outside this comparison",
      },
      "explicit_original_counterexample":{
         "subject":"B27_EXTERNAL_SEAWEEDFS_S3",
         "result":"original native same-object PUT accepted different bytes and repeated PUT",
         "refuted_properties":["exact_approved_result_bytes","replay_refused"],
         "not_an_upstream_security_bug_claim":True,
      },
      "closest_individual_evidence":{
          "label":diagnostic[0]["label"],
          "missing":diagnostic[0]["missing"],
      },
      "naive_subject_agnostic_baseline":{
          "would_report_full_authorized_execution":all(naive.values()),
          "invalid_inference_used":
               "Treat any GitHub human approval as independent resource owner consent; union permissions and effects across unrelated sources",
          "evidence_conflation_count":len(cases),
      },
      "reason_for_rejection":[
        "Four original successful narrower experiments refer to distinct resources or approval runs.",
        "A valid platform human approval alone does not certify an independently controlled owner.",
        "OpenBao native leases, PostgreSQL RLS effects and S3 IAM scope do not share B25's exact authorization identity.",
        "Native S3 PutObject does not bind changed bytes or one-time state transition in this policy.",
      ],
      "limitations":[
        "This is a recorded artifact-to-claim comparison, not a fresh live verification of every B27/B28 backend.",
        "Native result records originate from earlier independent auditors and must be cryptographically/operationally verified upstream.",
        "The simplistic subject-agnostic baseline is a deliberately invalid comparator, not a measured commercial product.",
        "No independent real human owner case was obtained or claimed.",
      ],
    }
    need(report["owner_approved_full_execution_proven"] is False and
         report["naive_subject_agnostic_baseline"]["would_report_full_authorized_execution"] is True,
         "B30_HOLDOUT_UNEXPECTED_FULL_AUTHORITY_OR_BASELINE_CHANGE")
    return report

def main(argv=None):
    p=argparse.ArgumentParser(description="Compare original B25/B27/B28/B29 claims without transferring consent across subjects")
    for opt in ("b30","b29","b27","b28"):
        p.add_argument("--"+opt,required=True)
    p.add_argument("--out",required=True)
    args=p.parse_args(argv)
    target=Path(args.out)
    if target.exists() or not target.parent.is_dir():
        print("B30_CLAIM_JOIN_OUTPUT_REFUSED",file=sys.stderr)
        return 2
    try:
        report=analyze(*(strict_load(getattr(args,opt)) for opt in
                         ("b30","b29","b27","b28")))
        with target.open("x",encoding="utf-8") as f:
            json.dump(report,f,indent=2,sort_keys=True)
            f.write("\n")
        print("RISU_B30_FOUR_ORIGINAL_BACKENDS_TYPED_EVIDENCE_JOIN_PASS")
        for c in report["subjects"]:
            print(c["label"],"supported=",len(c["supported"]),
                  "missing=",",".join(c["missing"]))
        return 0
    except (Rejected,ValueError,TypeError,KeyError,AttributeError,UnicodeError,OSError) as err:
        print("RISU_B30_CLAIM_JOIN_REFUSED: "+str(err),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
