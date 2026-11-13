"""RISU P6-B27 independent two-upstream permission/effect matrix.

No imports from either resource service or runtime harness. It consumes
GitHub Action original artifacts plus their independent native audits.

Method: observed effect E for an original authorization system is checked
against a specified claim component C. A backend capability is not inferred
from a coarse native privilege alone. A successful path-scoped write does
not entail an approved value, transition direction, or single-use right.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

SCHEMA="risu-p6b27-heterogeneous-original-backend-effect-matrix-v1"
def demand(x,msg):
    if not x: raise ValueError(msg)
def file_json(path):return json.loads(Path(path).read_text("utf-8"))
def sha(content):return hashlib.sha256(content).hexdigest()
def classify_postgres(raw,ind,package):
    demand(raw.get("schema")=="risu-p6b27-native-postgres-external-v1",
           "Unrecognized native PostgreSQL original result")
    demand(ind.get("schema")=="risu-b27-independent-original-postgresql-readonly-audit-v1"
       and ind.get("status")=="PASS","PostgreSQL independent native audit not PASS")
    demand(package.get("schema")=="risu-b27-original-postgresql-distribution-v1"
       and len(package.get("postgres_binary_sha256",""))==64,
       "Upstream original PostgreSQL binary provenance absent")
    demand(raw.get("versions",{}).get("server")==ind.get("real_service_version"),
           "Independent PostgreSQL release identity disagrees")
    actual=ind["actual_data"]
    demand(actual==raw.get("after"),"Audited PostgreSQL rows disagree with original")
    before={a["object_key"]:a for a in raw["before"]}
    after={a["object_key"]:a for a in actual}
    demand(set(before)==set(after)=={"object/approved","object/same-prefix-extra","outside/foreign"},
           "Original resource set incomplete")
    diff=[k for k in before if before[k]!=after[k]]
    demand(diff==["object/approved"],"Original PostgreSQL changed more than approved target")
    demand(after["object/approved"]=={"object_key":"object/approved","body":"OWNER APPROVED VALUE",
           "owner_epoch":"e1","state":"APPROVED"},"PostgreSQL post-state not exactly approved")
    denials={x["name"]:x for x in raw["negative_cases"]}
    expected={"wrong_object","same_prefix_other_object","unapproved_body","unapproved_state",
       "update_immutable_owner_epoch","delete_target","insert_any","truncate",
       "disable_rls_ddl","replace_rls_policy_ddl","set_role_issuer","set_role_superuser",
       "row_security_off","unauthorized_principal","unapproved_select"}
    demand(set(denials)==expected and len(raw["negative_cases"])==15,
           "PostgreSQL negative control coverage absent")
    demand(denials["wrong_object"].get("affected")==0 and
           denials["same_prefix_other_object"].get("affected")==0 and
           denials["unapproved_select"].get("affected")==0,
           "Unrelated original PostgreSQL objects not native denied")
    demand(all(denials[n]["kind"]=="ERROR" for n in expected-
        {"wrong_object","same_prefix_other_object","unapproved_select"}),
           "PostgreSQL native forbidden operation unexpectedly succeeded")
    demand(sorted(x.get("affected",-9) for x in raw["concurrent_native_direct_requests"])==[0,1],
           "Missing exactly one native PostgreSQL authorized effect")
    demand(raw["restart_replay"].get("affected")==0
           and raw["attempt_replay"].get("affected")==0,
           "PostgreSQL effect replay not denied")
    demand(raw["after_owner_revocation"]["kind"]=="ERROR"
           and ind["native_privileges_after_owner_revocation"]["can_update_body"] is False,
           "PostgreSQL issuer native REVOKE not enforced")
    demand(ind["actor_cannot_bypass_row_level_security"] is True
           and ind["table_metadata"]["force_rls"] is True,
           "Original PostgreSQL RLS authority not proven")
    return {
      "backend":"PostgreSQL",
      "upstream_version":raw["versions"]["server"],
      "publisher_binary_sha256":package["postgres_binary_sha256"],
      "issuer":"native PostgreSQL fixture owner and CREATE ROLE",
      "native_policy":"FORCE RLS with USING old-state, WITH CHECK exact new-state",
      "path_object_scope":{"enforced":True,"control":"wrong_object, same_prefix_other_object"},
      "exact_desired_bytes":{"enforced":True,"control":"unapproved_body"},
      "direction_precondition":{"enforced":True,"control":"unapproved_state + source state"},
      "one_time_effect":{"enforced":True,"control":"racing UPDATE [0,1] and restart replay 0"},
      "native_issuer_revocation":{"enforced":True,"control":"owner REVOKE + live system privilege catalog"},
      "actual_effect_independently_audited":True,
      "real_unrelated_third_party_human_approval":False,
      "observed_unauthorized_change_count":0,
      "actual_changed_resources":diff,
      "evidence_type":"UNMODIFIED_EXTERNAL_SERVICE_DIRECT_NATIVE_SQL",
    }

def classify_seaweedfs(raw,ind):
    demand(raw.get("schema")=="risu-b27-unmodified-seaweedfs-native-s3-holdout-v1"
           and ind.get("schema")=="risu-b27-independent-publisher-native-s3-audit-v1"
           and ind.get("audit_status")=="PASS",
           "Native S3 original evidence or independent audit not qualified")
    demand(raw.get("release")=="4.53" and raw.get("publisher")=="seaweedfs/seaweedfs"
           and raw.get("artifact_archive_sha256")==
             "d1a7dec9f48d8b33895a0ea8951971defc2dc5312906dcc76fa5a5f74a6ee90d"
           and "4.53" in ind["real_external_binary_version"],
           "Unknown SeaweedFS official publisher artifact")
    demand(ind["actual_original_object_sha256"]==raw["final_sha256"],
           "Original S3 bytes disagree with separate native admin audit")
    demand(ind["native_issuer_exact_policy"]["Statement"][0]["Resource"]==
           "arn:aws:s3:::risu-b27-external/approved/report.txt",
           "Native publisher's IAM source policy is not exactly one object")
    demand(raw.get("actor_separate_posix_uid")==65534 and
           raw.get("native_s3_actor_calls_in_distinct_os_processes")==len(raw["cases"]) and
           raw.get("owner_admin_credential_not_forwarded_to_actor") is True and
           ind.get("native_actor_os_uid")==65534 and
           ind.get("native_os_separated_original_s3_calls")==len(raw["cases"]) and
           ind.get("trusted_issuer_process_and_server_environments_not_readable_by_actor") is True,
           "Native S3 original actor and issuer OS/process isolation evidence missing")
    for original_case in raw["cases"]:
        demand(original_case.get("agent_os_uid")==65534 and
               original_case.get("trusted_publisher_server_environment_readable") is False and
               original_case.get("trusted_owner_issuer_environment_readable") is False and
               original_case.get("native_issuer_key_only") is True and
               original_case.get("direct_original_upstream_s3") is True,
               "Native S3 direct actor bypass case lacked isolated OS provenance")
    status={c["case"]:c["native_http_status"] for c in raw["cases"]}
    demand(len(status)==len(raw["cases"])==8
           and set(status)=={"coarse_issuer_positive","exact_object_authorized",
              "same_prefix_neighbor_direct_bypass","other_object_direct_bypass",
              "agent_bucket_listing","approved_object_wrong_value",
              "approved_object_replay","issuer_native_key_revocation"},
           "Exact SeaweedFS heldout challenge set missing or duplicated")
    demand(status["coarse_issuer_positive"]==200,
           "Native S3 coarse issuer positive control missing")
    object_scope=(status["exact_object_authorized"]==200 and
                  status["same_prefix_neighbor_direct_bypass"]==403 and
                  status["other_object_direct_bypass"]==403 and
                  status["agent_bucket_listing"]==403)
    content_scope=(status["approved_object_wrong_value"]!=200)
    one_time=(status["approved_object_replay"]!=200)
    revocation=(status["issuer_native_key_revocation"]==403 and
               ind["native_actor_key_revoked"] is True)
    # Native S3 did not purport to bind bytes or one-time nonce, so these
    # are capability gaps for the RISU claim, not upstream CVEs.
    demand(ind["native_exact_key_write_allowed"] is True
           and ind["verdict"]=="EXTERNAL_NATIVE_OBJECT_SCOPE_SUPPORTED",
           "Pre-registered native S3 heldout outcome is not qualified")
    return {
      "backend":"SeaweedFS",
      "upstream_version":raw["original_binary_version"],
      "publisher_original_release_archive_sha256":raw["artifact_archive_sha256"],
      "issuer":"native original SeaweedFS IAM CreateUser/CreateAccessKey/PutUserPolicy",
      "native_policy":"S3 PutObject Resource exact ARN, direct signed S3 API",
      "path_object_scope":{"enforced":object_scope,
                           "control":"direct same-prefix + other-object + list 403"},
      "exact_desired_bytes":{"enforced":content_scope,
                             "control":"same permitted ARN, changed value, actual S3 PUT 200"},
      "direction_precondition":{"enforced":False,
                             "control":"ordinary S3 PutObject has no old-state check in this policy"},
      "one_time_effect":{"enforced":one_time,
                         "control":"repeated actual S3 PutObject 200"},
      "native_issuer_revocation":{"enforced":revocation,
                            "control":"access key Inactive + S3 PUT 403"},
      "actual_effect_independently_audited":True,
      "real_unrelated_third_party_human_approval":False,
      "observed_unauthorized_cross_object_change_count":len(ind["direct_scope_bypass_cases"]),
      "evidence_type":"UNMODIFIED_EXTERNAL_SERVICE_DIRECT_NATIVE_S3_FROM_UID_65534",
      "actor_os_uid":65534,
      "issuer_and_server_process_environment_denied_by_kernel":True,
      "separate_native_actor_process_count":len(raw["cases"]),
    }

def compare(pg,pg_audit,pg_package,s3,s3_audit):
    a=classify_postgres(pg,pg_audit,pg_package)
    b=classify_seaweedfs(s3,s3_audit)
    keys=("path_object_scope","exact_desired_bytes","direction_precondition",
          "one_time_effect","native_issuer_revocation")
    matrix=[{"property":key,
        "postgresql":a[key]["enforced"],"seaweedfs":b[key]["enforced"],
        "comparison":"SAME" if a[key]["enforced"]==b[key]["enforced"] else "DIFFERENT"}
        for key in keys]
    demand(sum(x["comparison"]=="DIFFERENT" for x in matrix)==3,
           "Pre-registered backend capability comparison changed")
    return {
        "schema":SCHEMA,
        "status":"PASS_BOTH_ORIGINAL_BACKEND_AUDITS_AND_DIFFERENTIAL_EFFECTS",
        "qualifying_external_implementations":2,
        "independent_upstream_publishers":["PostgreSQL Global Development Group",
                                         "seaweedfs/seaweedfs"],
        "protocols":["PostgreSQL SQL/RLS","S3 SigV4/IAM"],
        "backends":[a,b],
        "property_matrix":matrix,
        "observed_practical_gap":"Native S3 exact-object PUT authority permits new bytes and repeated PUT. Native PostgreSQL owner policy constrains exact new value and old-state transition.",
        "claim_scope":"Experimental synthetic owner-issued authorizations; no independent human approval, no real-world affected customer.",
        "not_a_security_vulnerability_claim":True,
        "independent_effect_checks":["native PostgreSQL catalog and table rows",
                                      "native SeaweedFS IAM policy and object GET bytes"],
    }

def main():
    p=argparse.ArgumentParser()
    for name in ["postgres","postgres_audit","postgres_package","seaweedfs","seaweedfs_audit"]:
        p.add_argument("--"+name.replace("_","-"),required=True)
    p.add_argument("--out",required=True)
    args=p.parse_args()
    output=compare(*(file_json(getattr(args,name)) for name in (
       "postgres","postgres_audit","postgres_package","seaweedfs","seaweedfs_audit")))
    Path(args.out).write_text(json.dumps(output,indent=2,sort_keys=True)+"\n")
    print("RISU_B27_EXTERNAL_TWO_ORIGINAL_BACKEND_CLAIM_SPECIFIC_EFFECT_MATRIX_PASS")
    for r in output["property_matrix"]:
        print(r["property"],"postgres:",r["postgresql"],"s3:",r["seaweedfs"])
if __name__=="__main__":main()
