"""Independent B28 read-only verifier for two original publisher services.

Imports neither the RISU orchestrator nor the agent. Privileged auditor
queries original OpenBao HTTP API with a trusted root operator token and
original PostgreSQL syscatalog/rows through the native psql client.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.error
import urllib.request

EXPECTED={
 "approved/report":{"object_key":"approved/report","state":"APPROVED",
                    "body":"APPROVED CONTENT","owner_epoch":"e1"},
 "approved/report-extra":{"object_key":"approved/report-extra",
                           "state":"WAITING","body":"NEIGHBOR","owner_epoch":"e1"},
 "foreign/other":{"object_key":"foreign/other",
                  "state":"WAITING","body":"FOREIGN","owner_epoch":"e1"},
}
BEFORE={
 "approved/report":{"object_key":"approved/report","state":"WAITING",
                    "body":"ORIGINAL APPROVED","owner_epoch":"e1"},
 "approved/report-extra":EXPECTED["approved/report-extra"],
 "foreign/other":EXPECTED["foreign/other"],
}
NEGATIVES={"outside_object","same_prefix_neighbor","wrong_approved_content",
 "wrong_direction","owner_epoch_tamper","delete","insert","truncate",
 "disable_rls","drop_policy","set_role_postgres","row_security_off",
 "read_other_object","read_prefix_neighbor"}
def demand(ok,msg):
    if not ok:raise ValueError(msg)
def digest(x):
    return hashlib.sha256(json.dumps(x,sort_keys=True,separators=(",",":")).encode()).hexdigest()
def sql(q):
    p=subprocess.run(["runuser","-u","postgres","--","psql","-X","-q",
                       "-v","ON_ERROR_STOP=1","-At","-d","risu_b28_external"],
                     input=q,text=True,capture_output=True,timeout=30)
    demand(p.returncode==0,"Original PostgreSQL native catalog read failed")
    return p.stdout.strip()
def native_json(q):return json.loads(sql(q))
def service_get(path):
    request=urllib.request.Request(os.environ["BAO_ADDR"].rstrip("/")+"/v1/"+path,
                                   headers={"X-Vault-Token":os.environ["BAO_TOKEN"]})
    with urllib.request.urlopen(request,timeout=15) as response:
        demand(response.status==200,"Original OpenBao read-only operator API failed")
        return json.load(response)
def indexed(rows):
    return {x["object_key"]:x for x in rows}
def audit(data):
    demand(data.get("schema")=="risu-b28-original-openbao-postgresql-external-issuer-v1",
           "Unexpected B28 upstream issuer record format")
    demand(data.get("issuer_original_upstream")=="openbao/openbao" and
           data.get("resource_original_upstream")=="PostgreSQL Global Development Group"
           and data.get("issuer_version_pin")=="v2.7.2" and
           "2.7.2" in data["actual_issuer_binary_version"],
           "Independent third publisher/version could not be pinned")
    demand(data.get("unrelated_external_human_owner") is False
           and data.get("third_party_operated_service") is False
           and data.get("trusted_fixture_administrator") is True,
           "Experiment made unsupported real third-party ownership claim")
    demand(data.get("secrets_persisted") is False
           and data.get("issuer_native_root_operator_token_in_actor") is False,
           "Secret material or privileged root token apparently exposed to agent")
    pres=data["untrusted_actor_pre"]
    eff=data["untrusted_actor_effect"]
    post=data["untrusted_actor_after_revocation"]
    demand(pres.get("phase")=="pre_authorized_effect"
       and eff.get("phase")=="after_authorized_effect"
       and post.get("phase")=="after_native_issuer_revocation",
       "Original permission decision and effect phases missing")
    demand(pres.get("actor_uid")==65534 and post.get("actor_uid")==65534
       and pres.get("issuer_process_env_denied") is True
       and pres.get("openbao_process_env_denied") is True
       and pres.get("actor_used_risu_gateway") is False,
       "Native original issuer/actor process and credential separation unverified")
    demand(pres.get("anonymous_issuer_http") in (400,403)
       and pres.get("other_issuer_role_http") in (400,403)
       and pres.get("issuer_config_http") in (400,403),
       "Original OpenBao policy permits unapproved issuer API paths")
    demand(pres.get("native_one_use_first_http")==200
       and pres.get("native_one_use_repeat_http") in (400,403),
       "Original OpenBao one-use token did not constrain credential issuance")
    negatives=pres["native_database_denied_cases"]
    demand(len(negatives)==len(NEGATIVES) and
        {x["name"] for x in negatives}==NEGATIVES,
        "Original native SQL denied-case coverage incomplete")
    allow_zero={"outside_object","same_prefix_neighbor","read_other_object",
                "read_prefix_neighbor"}
    for n in negatives:
        if n["name"] in allow_zero:
            demand(n["ok"] is True and n["rows"]==0,
                   "Native original PostgreSQL exposed/modified unauthorized object")
        else:
            demand(n["ok"] is False,
                   "Original PostgreSQL accepted unauthorized native SQL: "+n["name"])
    demand(eff.get("approved")=={"ok":True,"rows":1,"category":"ok"}
       and eff.get("same_credential_replay")=={"ok":True,"rows":0,"category":"ok"},
       "Original PostgreSQL desired transition or one-way replay differs")
    demand(post.get("fresh_native_postgres_login_denied") is True
           and post.get("denial_category")!="ok",
           "Revoked original OpenBao lease did not reject fresh PostgreSQL login")
    demand(data.get("postgresql_native_role_present_before_revoke") is True
       and data.get("postgresql_native_role_present_after_revoke") is False,
       "Original PostgreSQL login not confirmed created and revoked")
    demand(pres["native_database_username"]==data["native_issuer_dynamic_username"]
       and pres["lease_id"]==data["native_issuer_lease_id"],
       "Original OpenBao granted-user or lease changed during audit")
    username=pres["native_database_username"]
    demand(type(username) is str and re.fullmatch(r"[A-Za-z0-9_-]{5,110}",username)
           is not None,"Unsafe native PostgreSQL credential name")
    demand(data["native_before_sha256"]==digest(data["native_before"])
           and data["native_after_sha256"]==digest(data["native_after"]),
           "Evidence body hashes are inconsistent")
    demand(indexed(data["native_before"])==BEFORE
           and indexed(data["native_after"])==EXPECTED,
           "Recorded original resource value differs from owner authorization")
    remote=native_json("""SELECT coalesce(json_agg(row_to_json(x) ORDER BY x.object_key),'[]'::json)
       FROM (SELECT object_key,state,body,owner_epoch FROM b28.resources ORDER BY object_key) x;""")
    demand(indexed(remote)==EXPECTED,
           "Independently read original PostgreSQL rows differ from authorized effect")
    role_present=sql("SELECT count(*) FROM pg_roles WHERE rolname='"+username+"';")
    demand(role_present=="0",
           "OpenBao issuer's original dynamic PostgreSQL role still active")
    roles=native_json("""SELECT json_agg(row_to_json(q) ORDER BY q.rolname) FROM (
        SELECT rolname,rolsuper,rolbypassrls,rolcreaterole,rolcanlogin FROM pg_roles
        WHERE rolname IN ('b28_owner','b28_bao_issuer','b28_template_writer')
        ORDER BY rolname) q;""")
    demand(len(roles)==3,"Real original issuer/owner/template SQL roles missing")
    byname={x["rolname"]:x for x in roles}
    demand(byname["b28_bao_issuer"]["rolsuper"] is False
       and byname["b28_bao_issuer"]["rolbypassrls"] is False
       and byname["b28_bao_issuer"]["rolcreaterole"] is True
       and byname["b28_template_writer"]["rolcanlogin"] is False,
       "Issuer can bypass native PostgreSQL RLS or template is a direct login")
    meta=native_json("""SELECT c.relrowsecurity AS rls,c.relforcerowsecurity AS force_rls,
       pg_get_userbyid(c.relowner) AS actual_owner,
       (SELECT count(*) FROM pg_policy p WHERE p.polrelid=c.oid) AS native_policies
       FROM pg_class c JOIN pg_namespace n ON c.relnamespace=n.oid
       WHERE n.nspname='b28' AND c.relname='resources';""")
    demand(meta=={"rls":True,"force_rls":True,"actual_owner":"b28_owner",
                  "native_policies":2},
           "Native PostgreSQL resource-side forced owner policy missing")
    policies=native_json("""SELECT coalesce(json_agg(row_to_json(q) ORDER BY q.policyname),'[]'::json) FROM (
       SELECT policyname,cmd,roles::text AS roles,qual,with_check
       FROM pg_policies WHERE schemaname='b28' AND tablename='resources') q;""")
    demand(len(policies)==2,"Unexpected native PostgreSQL policy change")
    write=next((x for x in policies if x["cmd"]=="UPDATE"),None)
    select=next((x for x in policies if x["cmd"]=="SELECT"),None)
    demand(write is not None and select is not None
           and "b28_template_writer" in write["roles"]
           and "approved/report" in write["qual"]
           and "WAITING" in write["qual"]
           and "ORIGINAL APPROVED" in write["qual"]
           and "APPROVED CONTENT" in write["with_check"]
           and "approved/report" in select["qual"],
           "Native original PostgreSQL old/new scope policy not present")
    privileges=native_json("""SELECT
       has_column_privilege('b28_template_writer','b28.resources','state','UPDATE') AS can_update_state,
       has_column_privilege('b28_template_writer','b28.resources','body','UPDATE') AS can_update_body,
       has_column_privilege('b28_template_writer','b28.resources','owner_epoch','UPDATE') AS can_update_epoch,
       has_table_privilege('b28_template_writer','b28.resources','DELETE') AS can_delete,
       has_table_privilege('b28_template_writer','b28.resources','INSERT') AS can_insert;""")
    demand(privileges=={"can_update_state":True,"can_update_body":True,
            "can_update_epoch":False,"can_delete":False,"can_insert":False},
           "Native original resource privilege scope not enforced")
    mounts=service_get("sys/mounts")
    demand("database/" in mounts.get("data",{}),
           "Original OpenBao issuer database secrets engine missing")
    role=service_get("database/roles/b28-write")
    role_data=role.get("data") or {}
    demand(role_data.get("db_name")=="b28"
       and "b28_template_writer" in str(role_data.get("creation_statements",""))
       and int(role_data.get("default_ttl",0))>0,
       "Original OpenBao dynamic PostgreSQL issuer role configuration differs")
    health=service_get("sys/health")
    demand(health.get("initialized") is True and health.get("sealed") is False,
           "Original OpenBao issuer not serving at independent audit time")
    evidence={
      "schema":"risu-b28-independent-original-publisher-issuer-resource-audit-v1",
      "status":"PASS",
      "native_openbao_version":data["actual_issuer_binary_version"],
      "native_postgresql_version":data["actual_pg_version"],
      "original_issuer":"OpenBao v2.7.2 database secrets, native lease and unique username",
      "original_resource":"PostgreSQL RLS forced owned table",
      "native_dynamic_lease_revoke_authenticated_pg_login_denial":True,
      "native_postgres_role_created_then_removed":True,
      "original_postgres_actual_rows":remote,
      "original_postgres_role_catalog":roles,
      "original_postgres_table_metadata":meta,
      "original_postgres_policy_catalog":policies,
      "native_resource_role_privileges":privileges,
      "original_openbao_database_mount_present":True,
      "original_openbao_native_dynamic_issuer_role_present":True,
      "actor_os_uid":65534,
      "native_denied_sql_controls":len(negatives),
      "authorized_direct_native_sql_changed_rows":1,
      "native_replay_changed_rows":0,
      "native_agent_sees_root_issuer_credential":False,
      "independently_owned_human_or_service_operator":False,
      "auditor_imports_experimental_runtime":False,
      "secrets_in_audit":False,
    }
    return evidence

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--observed",required=True)
    parser.add_argument("--out",required=True)
    args=parser.parse_args()
    record=json.loads(Path(args.observed).read_text())
    outcome=audit(record)
    Path(args.out).write_text(json.dumps(outcome,indent=2,sort_keys=True)+"\n")
    print("B28_INDEPENDENT_EXTERNAL_OPENBAO_POSTGRES_NATIVE_EFFECT_AUDIT_PASS")
if __name__=="__main__":main()
