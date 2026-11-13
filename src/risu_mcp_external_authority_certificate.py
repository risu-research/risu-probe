"""RISU P6-B28: offline, fail-closed issuer-to-effect evidence verifier.

This is an explicitly bounded evidence format, not an authentication system.
Never turns claim/case self-report into proof of an independently operated
service. It checks original observed evidence against a separately authored
original PostgreSQL+OpenBao live auditor and exact pinned release identity.

Run: risu-probe verify-mcp-external-authority --evidence-dir DIR --out result.json
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys

SCHEMA="risu-b28-cross-publisher-claim-specific-evidence-certificate-v1"
SOURCE_SCHEMA="risu-b28-original-openbao-postgresql-external-issuer-v1"
AUDIT_SCHEMA="risu-b28-independent-original-publisher-issuer-resource-audit-v1"
BINARY_SCHEMA="risu-b28-original-openbao-official-binary-provenance-v1"
EXPECTED_CHECKSUMS_FILE="d839d376448eceef3ccb5cdd44c4a0749a92a6e4aa2fdaf47255cfa949dfb77e"
EXPECTED_ARCHIVE="582b1f3c2fdc5afd443b2d57a225ef654de75adea609fdb66731fd582a9cbc96"
EXPECTED_BEFORE=[
 {"body":"ORIGINAL APPROVED","object_key":"approved/report","owner_epoch":"e1","state":"WAITING"},
 {"body":"NEIGHBOR","object_key":"approved/report-extra","owner_epoch":"e1","state":"WAITING"},
 {"body":"FOREIGN","object_key":"foreign/other","owner_epoch":"e1","state":"WAITING"},
]
EXPECTED_AFTER=[dict(x) for x in EXPECTED_BEFORE]
EXPECTED_AFTER[0]["body"]="APPROVED CONTENT"
EXPECTED_AFTER[0]["state"]="APPROVED"
NEGATIVES={
 "outside_object","same_prefix_neighbor","wrong_approved_content","wrong_direction",
 "owner_epoch_tamper","delete","insert","truncate","disable_rls","drop_policy",
 "set_role_postgres","row_security_off","read_other_object","read_prefix_neighbor",
}
ZERO_ROWS={"outside_object","same_prefix_neighbor",
           "read_other_object","read_prefix_neighbor"}
FILENAMES={
 "binary":"issuer_original_binary_identity.json",
 "original":"original_native_issuer_resource_result.json",
 "audit":"independent_original_backend_audit.json",
}
class EvidenceRefused(Exception):
    pass
def check(ok,why):
    if not ok:raise EvidenceRefused(why)
def canonical(d):
    return json.dumps(d,sort_keys=True,separators=(",",":"),ensure_ascii=False,
                      allow_nan=False).encode("utf-8")
def h(d):return hashlib.sha256(canonical(d)).hexdigest()
def strict_json(data):
    def pairs(items):
        result={}
        for key,value in items:
            if key in result:raise ValueError("duplicate JSON key")
            result[key]=value
        return result
    try:return json.loads(data,object_pairs_hook=pairs)
    except (ValueError,RecursionError,UnicodeError):
        raise EvidenceRefused("MALFORMED_OR_AMBIGUOUS_EVIDENCE")
def file_read(base,relative):
    path=base/relative
    check(path.is_file() and not path.is_symlink(),"MISSING_OR_SYMLINKED_ORIGINAL_EVIDENCE")
    check(0<path.stat().st_size<2000000,"OVERSIZED_ORIGINAL_EVIDENCE")
    try:raw=path.read_bytes()
    except OSError:raise EvidenceRefused("UNREADABLE_ORIGINAL_EVIDENCE")
    data=strict_json(raw.decode("utf-8"))
    check(type(data) is dict,"EVIDENCE_ROOT_MUST_BE_OBJECT")
    return data,hashlib.sha256(raw).hexdigest()
def verify_evidence(binary,original,audit,hashes=None):
    check(binary.get("schema")==BINARY_SCHEMA and
          binary.get("publisher")=="openbao/openbao" and
          binary.get("version")=="v2.7.2" and
          binary.get("official_checksums_file_sha256")==EXPECTED_CHECKSUMS_FILE and
          binary.get("archive_sha256")==EXPECTED_ARCHIVE and
          re.fullmatch(r"[0-9a-f]{64}",binary.get("original_executable_sha256","")) is not None,
          "EXTERNAL_ISSUER_RELEASE_NOT_PINNED")
    check(original.get("schema")==SOURCE_SCHEMA and
          original.get("issuer_original_upstream")=="openbao/openbao" and
          original.get("resource_original_upstream")=="PostgreSQL Global Development Group" and
          original.get("issuer_version_pin")=="v2.7.2" and
          "2.7.2" in original.get("actual_issuer_binary_version",""),
          "ORIGINAL_PUBLISHER_ISSUER_IDENTITY_UNVERIFIED")
    check(audit.get("schema")==AUDIT_SCHEMA and audit.get("status")=="PASS" and
          audit.get("auditor_imports_experimental_runtime") is False,
          "INDEPENDENT_ORIGINAL_SERVICE_AUDIT_MISSING")
    check(audit.get("native_openbao_version")==original.get("actual_issuer_binary_version")
          and audit.get("native_postgresql_version")==original.get("actual_pg_version"),
          "INDEPENDENT_AUDIT_NATIVE_VERSION_MISMATCH")
    check(original.get("native_before")==EXPECTED_BEFORE and
          original.get("native_after")==EXPECTED_AFTER and
          original.get("native_before_sha256")==h(EXPECTED_BEFORE) and
          original.get("native_after_sha256")==h(EXPECTED_AFTER),
          "OWNER_DECLARED_PRE_OR_POST_RESOURCE_EFFECT_CHANGED")
    check(audit.get("original_postgres_actual_rows")==EXPECTED_AFTER,
          "INDEPENDENT_ORIGINAL_POSTGRES_BYTES_MISMATCH")
    check(original.get("issuer_native_dynamic_database_plugin")==
           "postgresql-database-plugin" and
          original.get("postgresql_native_role_present_before_revoke") is True and
          original.get("postgresql_native_role_present_after_revoke") is False,
          "REAL_NATIVE_ISSUER_DB_ROLE_LIFECYCLE_MISSING")
    check(original.get("secrets_persisted") is False and
          audit.get("secrets_in_audit") is False and
          original.get("issuer_native_root_operator_token_in_actor") is False and
          audit.get("native_agent_sees_root_issuer_credential") is False,
          "EVIDENCE_LEAKED_OR_PRESERVED_PRIVILEGED_CREDENTIAL")
    check(original.get("unrelated_external_human_owner") is False and
          original.get("third_party_operated_service") is False and
          audit.get("independently_owned_human_or_service_operator") is False and
          original.get("trusted_fixture_administrator") is True,
          "UNSUPPORTED_INDEPENDENT_REAL_OWNER_CLAIM")
    first=original.get("untrusted_actor_pre",{})
    effect=original.get("untrusted_actor_effect",{})
    last=original.get("untrusted_actor_after_revocation",{})
    check(first.get("phase")=="pre_authorized_effect" and
          effect.get("phase")=="after_authorized_effect" and
          last.get("phase")=="after_native_issuer_revocation",
          "PRE_EXECUTION_AND_EFFECT_SEQUENCE_MISSING")
    check(first.get("actor_uid")==65534 and last.get("actor_uid")==65534 and
          audit.get("actor_os_uid")==65534 and
          first.get("issuer_process_env_denied") is True and
          first.get("openbao_process_env_denied") is True and
          first.get("actor_used_risu_gateway") is False,
          "DIRECT_UNTRUSTED_PRINCIPAL_BOUNDARY_MISSING")
    check(first.get("native_credential_delivery")==
             "OpenBao native single-use response wrapping" and
          first.get("native_one_use_first_http")==200 and
          first.get("native_one_use_repeat_http") in (400,403) and
          first.get("native_wrapped_token_recredential_http") in (400,403) and
          first.get("anonymous_issuer_http") in (400,403) and
          first.get("other_issuer_role_http") in (400,403) and
          first.get("issuer_config_http") in (400,403),
          "NATIVE_ISSUER_ONE_TIME_DELIVERY_NOT_VERIFIED")
    lease=original.get("native_issuer_lease_id","")
    username=original.get("native_issuer_dynamic_username","")
    check(re.fullmatch(r"database/creds/b28-write/[A-Za-z0-9-]+",lease) is not None and
          re.fullmatch(r"[A-Za-z0-9_-]{5,110}",username) is not None and
          lease==first.get("lease_id") and
          username==first.get("native_database_username"),
          "ISSUER_LEASE_OR_DYNAMIC_ROLE_NOT_BOUND_TO_ACTOR_RECORD")
    cases=first.get("native_database_denied_cases")
    check(type(cases) is list and len(cases)==len(NEGATIVES) and
          {x.get("name") for x in cases if type(x) is dict}==NEGATIVES,
          "ORIGINAL_RESOURCE_ATTACK_COVERAGE_MISSING")
    for c in cases:
        check(type(c) is dict,"MALFORMED_RESOURCE_ATTACK_CASE")
        name=c["name"]
        if name in ZERO_ROWS:
            check(c.get("ok") is True and c.get("rows")==0,
                  "UNAUTHORIZED_DIRECT_NATIVE_SQL_OBJECT_VISIBLE_OR_CHANGED")
        else:
            check(c.get("ok") is False,
                  "UNAUTHORIZED_DIRECT_NATIVE_SQL_PERMISSION_GRANTED")
    check(effect.get("approved")=={"ok":True,"rows":1,"category":"ok"} and
          effect.get("same_credential_replay")=={"ok":True,"rows":0,"category":"ok"} and
          audit.get("authorized_direct_native_sql_changed_rows")==1 and
          audit.get("native_replay_changed_rows")==0,
          "ORIGINAL_NATIVE_EFFECT_OR_REPLAY_UNVERIFIED")
    check(last.get("fresh_native_postgres_login_denied") is True and
          last.get("denial_category")!="ok" and
          audit.get("native_dynamic_lease_revoke_authenticated_pg_login_denial") is True and
          audit.get("native_postgres_role_created_then_removed") is True,
          "ORIGINAL_ISSUER_REVOCATION_NOT_PROVEN")
    check(audit.get("native_denied_sql_controls")==len(NEGATIVES) and
          audit.get("original_openbao_database_mount_present") is True and
          audit.get("original_openbao_native_dynamic_issuer_role_present") is True,
          "INDEPENDENT_NATIVE_ISSUER_AUDIT_INCOMPLETE")
    table=audit.get("original_postgres_table_metadata",{})
    check(table=={"rls":True,"force_rls":True,"actual_owner":"b28_owner",
                  "native_policies":2},
          "REAL_NATIVE_RESOURCE_OWNER_RLS_MISSING")
    privileges=audit.get("native_resource_role_privileges")
    check(privileges=={"can_update_state":True,"can_update_body":True,
           "can_update_epoch":False,"can_delete":False,"can_insert":False},
          "REAL_NATIVE_DB_RESOURCE_PRIVILEGES_INCOMPLETE")
    policies=audit.get("original_postgres_policy_catalog")
    check(type(policies) is list and len(policies)==2 and
          {p.get("cmd") for p in policies}=={"SELECT","UPDATE"},
          "NATIVE_PRESTATE_AND_POSTSTATE_POLICIES_INCOMPLETE")
    write=next(p for p in policies if p["cmd"]=="UPDATE")
    read=next(p for p in policies if p["cmd"]=="SELECT")
    check("b28_template_writer" in write.get("roles","") and
          "approved/report" in write.get("qual","") and
          "WAITING" in write.get("qual","") and
          "ORIGINAL APPROVED" in write.get("qual","") and
          "APPROVED CONTENT" in write.get("with_check","") and
          "approved/report" in read.get("qual",""),
          "NATIVE_APPROVED_ROW_AND_DIRECTION_POLICY_INCOMPLETE")
    roles=audit.get("original_postgres_role_catalog")
    check(type(roles) is list and len(roles)==3 and
          {r.get("rolname") for r in roles}==
          {"b28_owner","b28_bao_issuer","b28_template_writer"},
          "NATIVE_ORIGINAL_ISSUER_RESOURCE_PRINCIPALS_MISSING")
    role_map={r["rolname"]:r for r in roles}
    check(role_map["b28_bao_issuer"]["rolsuper"] is False and
          role_map["b28_bao_issuer"]["rolbypassrls"] is False and
          role_map["b28_template_writer"]["rolcanlogin"] is False,
          "ISSUER_NATIVE_POSTGRES_ROOT_OR_DIRECT_LOGIN")
    # Transparent distinction between observations and unproven claims.
    claim_rows=[
        ("separate_original_software_publishers",True),
        ("one_use_wrapped_credential_delivery",True),
        ("native_database_credentials_issued",True),
        ("direct_unauthorized_resource_writes_denied",True),
        ("approved_resource_content_transition",True),
        ("duplicate_state_effect_prevented",True),
        ("native_credential_revocation_enforced_at_new_login",True),
        ("independent_readonly_original_data_audit",True),
        ("independent_real_human_resource_owner",False),
        ("externally_operated_original_services",False),
        ("wrapping_token_cryptographically_binds_recipient",False),
        ("resistance_to_malicious_resource_superuser",False),
    ]
    evidence_sha=hashes if hashes is not None else {}
    result={
        "schema":SCHEMA,
        "status":"RECORDED_ORIGINAL_NATIVE_EVIDENCE_CONSISTENT",
        "level":"OFFLINE_CROSS_ARTIFACT_VALIDATION_NOT_A_FRESH_REMOTE_VERIFICATION",
        "observed_external_software_publishers":["openbao/openbao",
                               "PostgreSQL Global Development Group"],
        "actual_native_denied_resource_cases":len(NEGATIVES),
        "claims":[{"claim":name,"supported_by_recorded_evidence":supported}
                  for name,supported in claim_rows],
        "original_evidence_file_sha256":evidence_sha,
        "owner_before_sha256":original["native_before_sha256"],
        "owner_after_sha256":original["native_after_sha256"],
        "limitations":[
          "CI fixture administrator controls both hosted original services",
          "No independent second real human owner was authenticated",
          "One-use wrapping token is bearer and not cryptographically recipient-bound",
          "One-use delivery and PostgreSQL old-state effect guard are distinct",
          "Native OpenBao token TTL/lease revocation does not imply arbitrary application effect undo",
          "An offline checker compares recorded native reports, not live backend state",
        ],
    }
    return result

def verify_dir(evidence_dir):
    base=Path(evidence_dir)
    check(base.is_dir() and not base.is_symlink(),"MISSING_OR_SYMLINKED_EVIDENCE_DIR")
    objects={}
    digests={}
    for category,name in FILENAMES.items():
        objects[category],digests[name]=file_read(base,name)
    return verify_evidence(objects["binary"],objects["original"],
                           objects["audit"],digests)

def main(argv=None):
    p=argparse.ArgumentParser(description="Verify claim-specific B28 recorded issuer-to-effect evidence")
    p.add_argument("--evidence-dir",required=True)
    p.add_argument("--out",required=True)
    args=p.parse_args(argv)
    dest=Path(args.out)
    try:
        check(not dest.exists() and dest.parent.is_dir(),
              "REFUSE_OVERWRITE_OR_MISSING_OUTPUT_DIRECTORY")
        report=verify_dir(args.evidence_dir)
        fd=os.open(dest,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(fd,"w",encoding="utf-8") as file:
            json.dump(report,file,sort_keys=True,indent=2)
            file.write("\n")
        print("RISU_B28_EXTERNAL_ISSUER_ORIGINAL_RESOURCE_CERTIFICATE_PASS")
        return 0
    except (EvidenceRefused,OSError,UnicodeError,TypeError,KeyError,ValueError) as e:
        print("RISU_B28_EVIDENCE_REFUSED: "+str(e),file=sys.stderr)
        return 2
if __name__=="__main__":
    raise SystemExit(main())
