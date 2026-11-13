"""Independent B27 auditor, intentionally never importing the issuer/harness.

Reads actual original PostgreSQL catalog, principal attributes, access-control
and protected rows from its own superuser connection; checks report separately.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

EXPECTED_BEFORE={
 "object/approved":("WAITING","ORIGINAL APPROVED","e1"),
 "object/same-prefix-extra":("WAITING","SECOND RESOURCE","e1"),
 "outside/foreign":("WAITING","FOREIGN RESOURCE","e1"),
}
EXPECTED_AFTER={**EXPECTED_BEFORE,"object/approved":("APPROVED","OWNER APPROVED VALUE","e1")}
NEGATIVES={"wrong_object","same_prefix_other_object","unapproved_body",
 "unapproved_state","update_immutable_owner_epoch","delete_target",
 "insert_any","truncate","disable_rls_ddl","replace_rls_policy_ddl",
 "set_role_issuer","set_role_superuser","row_security_off",
 "unauthorized_principal","unapproved_select"}
ACTOR="risu_b27_actor"
OWNER="risu_b27_issuer"
OTHER="risu_b27_other"

def require(ok,msg):
    if not ok:raise ValueError(msg)

def sql(q):
    r=subprocess.run(["runuser","-u","postgres","--","psql","-X","-q",
        "-v","ON_ERROR_STOP=1","-At","-d","risu_b27_external"],
        text=True,input=q,capture_output=True,timeout=40)
    require(r.returncode==0,"Independent SQL lookup failed: "+r.stderr[-400:])
    return r.stdout.strip()

def sql_json(q):return json.loads(sql("SELECT row_to_json(x) FROM ("+q+") x;"))

def verify(report):
    require(report.get("schema")=="risu-p6b27-native-postgres-external-v1","Bad B27 run schema")
    require(report.get("third_party_human_owner") is False,
            "Synthetic fixture cannot claim third-party human authority")
    require(report.get("owner_role")==OWNER and report.get("actor_role")==ACTOR
       and report.get("unauthorized_role")==OTHER,"Unexpected principal identities")
    require(report.get("actor_os_uid")==65534,"Agent command was not run in nobody UID")
    require(report.get("one_actual_authorized_effect")==1,"One exact write missing")
    require(len(report["negative_cases"])==len(NEGATIVES)
       and {x["name"] for x in report["negative_cases"]}==NEGATIVES,
       "Negative tests missing or duplicated")
    for case in report["negative_cases"]:
        name=case["name"]
        if name in ("wrong_object","same_prefix_other_object"):
            require(case.get("kind")=="DML" and case.get("affected")==0,
                    name+" did not produce native UPDATE zero-row refusal")
        elif name=="unapproved_select":
            require(case.get("kind")=="SQL" and case.get("affected")==0,
                    "Unauthorized native SELECT exposed another object")
        else:
            require(case.get("kind")=="ERROR" and case.get("exit_code",0)!=0,
                    name+" unexpectedly bypassed original PostgreSQL policy")
    race=report["concurrent_native_direct_requests"]
    require(len(race)==2 and sorted(x.get("affected",-5) for x in race)==[0,1]
        and all(x.get("kind")=="DML" for x in race),
        "One-time direction-bound write not verified under concurrent requests")
    for key in ("attempt_replay","restart_replay"):
        require(report[key].get("kind")=="DML" and report[key].get("affected")==0,
                "Original PostgreSQL returned a replay write")
    require(report["after_owner_revocation"]["kind"]=="ERROR",
            "Post-revocation write was not denied by PostgreSQL")
    require(report.get("owner_credentials_in_output") is False,"Secrets may be present in report")
    before={r["object_key"]:(r["state"],r["body"],r["owner_epoch"]) for r in report["before"]}
    after={r["object_key"]:(r["state"],r["body"],r["owner_epoch"]) for r in report["after"]}
    require(before==EXPECTED_BEFORE and after==EXPECTED_AFTER,
            "Claimed PostgreSQL state or control object differs")
    live=json.loads(sql("""SELECT coalesce(json_agg(row_to_json(t) ORDER BY t.object_key),'[]'::json)
        FROM (SELECT object_key,state,body,owner_epoch FROM protected.resources ORDER BY object_key) t;"""))
    actual={r["object_key"]:(r["state"],r["body"],r["owner_epoch"]) for r in live}
    require(actual==EXPECTED_AFTER,"Actual native PostgreSQL data differs from allowed state")
    meta=sql_json("""SELECT c.relrowsecurity AS rls, c.relforcerowsecurity AS force_rls,
       pg_get_userbyid(c.relowner) AS owner,
       (SELECT count(*) FROM pg_policy p WHERE p.polrelid=c.oid) AS num_policies
       FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
       WHERE n.nspname='protected' AND c.relname='resources'""")
    require(meta=={"rls":True,"force_rls":True,"owner":OWNER,"num_policies":2},
            "Native resource-server row security is missing or not forced")
    roles=json.loads(sql("""SELECT json_agg(row_to_json(q)) FROM (
        SELECT rolname,rolsuper,rolbypassrls,rolcreatedb,rolcreaterole
        FROM pg_roles WHERE rolname IN ('risu_b27_actor','risu_b27_other','risu_b27_issuer')
        ORDER BY rolname) q;"""))
    require(len(roles)==3,"Database native principals missing")
    byname={r["rolname"]:r for r in roles}
    for r in (ACTOR,OTHER):
        require(byname[r]["rolsuper"] is False
            and byname[r]["rolbypassrls"] is False
            and byname[r]["rolcreatedb"] is False
            and byname[r]["rolcreaterole"] is False,
            "Untrusted actor can bypass native row-level security")
    require(byname[OWNER]["rolcreaterole"] is True,
            "Independent owner did not hold native role issuer permission")
    # Read PostgreSQL's own policy catalog, not the benchmark source.
    policies=json.loads(sql("""SELECT json_agg(row_to_json(q) ORDER BY q.policyname) FROM (
       SELECT policyname,cmd,roles::text AS roles,
         qual,with_check FROM pg_policies
       WHERE schemaname='protected' AND tablename='resources') q;"""))
    require(len(policies)==2,"Unexpected original PostgreSQL policy set")
    bycmd={p["cmd"]:p for p in policies}
    require(set(bycmd)=={"SELECT","UPDATE"},"Expected native SELECT/UPDATE policies absent")
    for p in policies:
        require(ACTOR in p["roles"],"External role not native-policy scoped")
    require("object/approved" in bycmd["SELECT"]["qual"]
            and "object/approved" in bycmd["UPDATE"]["qual"]
            and "WAITING" in bycmd["UPDATE"]["qual"]
            and "ORIGINAL APPROVED" in bycmd["UPDATE"]["qual"]
            and "OWNER APPROVED VALUE" in bycmd["UPDATE"]["with_check"],
            "Native server did not retain object- and direction-scoped approval")
    priv=sql_json("""SELECT
       has_table_privilege('risu_b27_actor','protected.resources','INSERT') AS can_insert,
       has_table_privilege('risu_b27_actor','protected.resources','DELETE') AS can_delete,
       has_table_privilege('risu_b27_actor','protected.resources','TRUNCATE') AS can_truncate,
       has_column_privilege('risu_b27_actor','protected.resources','state','UPDATE') AS can_update_state,
       has_column_privilege('risu_b27_actor','protected.resources','body','UPDATE') AS can_update_body,
       has_column_privilege('risu_b27_actor','protected.resources','owner_epoch','UPDATE') AS can_update_epoch,
       has_column_privilege('risu_b27_other','protected.resources','state','UPDATE') AS other_can_update
       """)
    require(priv=={"can_insert":False,"can_delete":False,"can_truncate":False,
                  "can_update_state":False,"can_update_body":False,
                  "can_update_epoch":False,"other_can_update":False},
            "Native PostgreSQL owner revocation/column scope not enforced")
    evidence={
        "schema":"risu-b27-independent-original-postgresql-readonly-audit-v1",
        "status":"PASS",
        "backend":"PostgreSQL native server, independent implementation",
        "real_service_version":sql("SHOW server_version;"),
        "policy_catalog":policies,"roles_redacted":roles,"table_metadata":meta,
        "native_privileges_after_owner_revocation":priv,
        "actual_data":live,"original_cases":len(report["negative_cases"]),
        "actual_native_concurrent_writes":sorted(x["affected"] for x in race),
        "one_modified_original_resource":True,
        "other_two_original_resources_unchanged":True,
        "owner_can_modify_native_policy":True,
        "actor_cannot_bypass_row_level_security":True,
        "third_party_external_human_approval":False,
        "audit_imports_issuer_or_gateway_code":False,
    }
    return evidence

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--result",required=True)
    p.add_argument("--out",required=True)
    args=p.parse_args()
    report=json.loads(Path(args.result).read_text())
    verified=verify(report)
    Path(args.out).write_text(json.dumps(verified,indent=2,sort_keys=True)+"\n")
    print("B27_INDEPENDENT_POSTGRES_NATIVE_RLS_CATALOG_AND_REAL_EFFECT_PASS")
if __name__=="__main__":main()
