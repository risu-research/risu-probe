"""P6-B27 external original PostgreSQL RLS effect test.

This test uses a distribution-installed, unmodified PostgreSQL server.
A native SQL owner (not the actor) provisions a role and native RLS.
The actor accesses PostgreSQL directly, bypassing RISU code entirely.
Only the synthetic fixture owner is represented; no third-party human.
"""
from __future__ import annotations
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import pwd
import secrets
import subprocess
import time

DATABASE="risu_b27_external"
OWNER="risu_b27_issuer"
ACTOR="risu_b27_actor"
OTHER="risu_b27_other"
TABLE="protected.resources"
ROWS=[
    {"object_key":"object/approved","state":"WAITING","body":"ORIGINAL APPROVED","owner_epoch":"e1"},
    {"object_key":"object/same-prefix-extra","state":"WAITING","body":"SECOND RESOURCE","owner_epoch":"e1"},
    {"object_key":"outside/foreign","state":"WAITING","body":"FOREIGN RESOURCE","owner_epoch":"e1"},
]
AFTER="OWNER APPROVED VALUE"
SQL_APPROVE=("UPDATE protected.resources SET state='APPROVED', "
             "body='OWNER APPROVED VALUE' WHERE object_key='object/approved';")
EXPECTED_DENIED={
    "wrong_object":0,
    "same_prefix_other_object":0,
    "unapproved_body":-1,
    "unapproved_state":-1,
    "update_immutable_owner_epoch":-1,
    "delete_target":-1,
    "insert_any":-1,
    "truncate":-1,
    "disable_rls_ddl":-1,
    "replace_rls_policy_ddl":-1,
    "set_role_issuer":-1,
    "set_role_superuser":-1,
    "row_security_off":-1,
    "unauthorized_principal":-1,
    "unapproved_select":0,
}
QUERY_CASES={
    "wrong_object": ("actor", "UPDATE protected.resources SET state='APPROVED',body='OWNER APPROVED VALUE' WHERE object_key='outside/foreign';"),
    "same_prefix_other_object": ("actor", "UPDATE protected.resources SET state='APPROVED',body='OWNER APPROVED VALUE' WHERE object_key='object/same-prefix-extra';"),
    "unapproved_body": ("actor", "UPDATE protected.resources SET state='APPROVED',body='ALTERED CONTENT' WHERE object_key='object/approved';"),
    "unapproved_state": ("actor", "UPDATE protected.resources SET state='OTHER',body='OWNER APPROVED VALUE' WHERE object_key='object/approved';"),
    "update_immutable_owner_epoch": ("actor", "UPDATE protected.resources SET owner_epoch='e2' WHERE object_key='object/approved';"),
    "delete_target": ("actor", "DELETE FROM protected.resources WHERE object_key='object/approved';"),
    "insert_any": ("actor", "INSERT INTO protected.resources(object_key,state,body,owner_epoch) VALUES('object/new','APPROVED','OWNER APPROVED VALUE','e1');"),
    "truncate": ("actor", "TRUNCATE protected.resources;"),
    "disable_rls_ddl": ("actor", "ALTER TABLE protected.resources DISABLE ROW LEVEL SECURITY;"),
    "replace_rls_policy_ddl": ("actor", "DROP POLICY b27_write_exact ON protected.resources;"),
    "set_role_issuer": ("actor", "SET ROLE risu_b27_issuer;"),
    "set_role_superuser": ("actor", "SET ROLE postgres;"),
    "row_security_off": ("actor", "SET row_security = off; SELECT * FROM protected.resources;"),
    "unauthorized_principal": ("other", SQL_APPROVE),
    "unapproved_select": ("actor", "SELECT object_key FROM protected.resources WHERE object_key='outside/foreign';"),
}
UID_AGENT="nobody"
def must(ok,msg):
    if not ok: raise AssertionError(msg)

def call(cmd,sql=None,env=None,uid=None,timeout=40):
    e=os.environ.copy()
    if env:e.update(env)
    # Cross-process OS boundary: agent never receives issuer password.
    identity={}
    if uid:
        ident=pwd.getpwnam(uid)
        # No user-controlled shell, fork hook, or credential in argv.
        identity={"user":ident.pw_uid,"group":ident.pw_gid,"extra_groups":[]}
    return subprocess.run(cmd,input=sql,text=True,capture_output=True,
                          env=e,timeout=timeout,**identity)
def privileged(sql,db="postgres"):
    cmd=["runuser","-u","postgres","--","psql","-X","-q",
         "-v","ON_ERROR_STOP=1","-At","-d",db]
    r=call(cmd,sql)
    must(r.returncode==0,"PostgreSQL fixture admin setup failed: "+r.stderr[-500:])
    return r.stdout.strip()

def sql_role(role,password,sql,uid=UID_AGENT):
    cmd=["/usr/bin/psql","-X","-q","-v","ON_ERROR_STOP=1",
         "-At","-h","127.0.0.1","-p","5432","-U",role,"-d",DATABASE]
    return call(cmd,sql,env={"PGPASSWORD":password,"PGCONNECT_TIMEOUT":"8"},uid=uid)

def must_sql(role,password,sql):
    r=sql_role(role,password,sql,uid=None) # Owner provisioning runs from trusted launcher.
    must(r.returncode==0,"Owner SQL failed: "+r.stderr[-550:])
    return r.stdout.strip()

def snapshot():
    raw=privileged("""SELECT coalesce(json_agg(row_to_json(q) ORDER BY q.object_key),'[]'::json)
     FROM (SELECT object_key,state,body,owner_epoch FROM protected.resources ORDER BY object_key) q;""",DATABASE)
    return json.loads(raw)

def one_query(name,role,passphrase,sql):
    r=sql_role(role,passphrase,sql)
    # psql -q -At produces rows but not UPDATE N. Use nonquiet for command tags.
    if r.returncode!=0:
        return {"name":name,"kind":"ERROR","exit_code":r.returncode,
                "sqlstate":None,"output_lines":0}
    if sql.lstrip().upper().startswith("SELECT"):
        return {"name":name,"kind":"SELECT","exit_code":0,
                "output_lines":len([a for a in r.stdout.splitlines() if a.strip()])}
    # For UPDATE, capture native command tag using unquiet psql without echoing SQL.
    ur=sql_role(role,passphrase,sql.replace(";", " RETURNING 1;") if False else "SELECT 1;")
    must(ur.returncode==0,"PostgreSQL actor health")
    return {"name":name,"kind":"ACCEPTED_STATEMENT","exit_code":0,
            "output_lines":len([a for a in r.stdout.splitlines() if a.strip()])}

def statement(role,password,sql,uid=UID_AGENT):
    cmd=["/usr/bin/psql","-X","-v","ON_ERROR_STOP=1","-At",
         "-h","127.0.0.1","-p","5432","-U",role,"-d",DATABASE]
    r=call(cmd,sql,env={"PGPASSWORD":password,"PGCONNECT_TIMEOUT":"8"},uid=uid)
    if r.returncode:
        return {"kind":"ERROR","exit_code":r.returncode,"affected":None,
                "native_error_category":("permission" if "permission" in r.stderr.lower() or "policy" in r.stderr.lower() else "auth")}
    lines=[x.strip() for x in r.stdout.splitlines() if x.strip()]
    tag=next((l for l in reversed(lines) if l.startswith(("UPDATE ","DELETE ","INSERT ","TRUNCATE "))),None)
    if tag:
        try:n=int(tag.rsplit(" ",1)[-1])
        except ValueError:n=0
        return {"kind":"DML","exit_code":0,"affected":n}
    return {"kind":"SQL","exit_code":0,
            "affected":len([l for l in lines if not l.startswith(("SET","ALTER","DROP","CREATE"))])}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--out",required=True)
    args=ap.parse_args()
    must(os.geteuid()==0,"trusted fixture launcher must run as root")
    root=Path(args.out).resolve();root.mkdir(parents=True,exist_ok=True)
    owner_password=secrets.token_urlsafe(30)
    actor_password=secrets.token_urlsafe(30)
    other_password=secrets.token_urlsafe(30)
    privileged("CREATE ROLE "+OWNER+" LOGIN CREATEROLE NOSUPERUSER NOBYPASSRLS PASSWORD '"+owner_password+"';")
    privileged("CREATE DATABASE "+DATABASE+" OWNER "+OWNER+";")
    owner_ddl="""
CREATE SCHEMA protected AUTHORIZATION risu_b27_issuer;
CREATE TABLE protected.resources(
 object_key TEXT PRIMARY KEY, state TEXT NOT NULL, body TEXT NOT NULL,
 owner_epoch TEXT NOT NULL
);
INSERT INTO protected.resources VALUES
 ('object/approved','WAITING','ORIGINAL APPROVED','e1'),
 ('object/same-prefix-extra','WAITING','SECOND RESOURCE','e1'),
 ('outside/foreign','WAITING','FOREIGN RESOURCE','e1');
CREATE ROLE risu_b27_actor LOGIN NOSUPERUSER NOCREATEDB NOBYPASSRLS PASSWORD 'ACTOR_SECRET';
CREATE ROLE risu_b27_other LOGIN NOSUPERUSER NOCREATEDB NOBYPASSRLS PASSWORD 'OTHER_SECRET';
GRANT CONNECT ON DATABASE risu_b27_external TO risu_b27_actor,risu_b27_other;
GRANT USAGE ON SCHEMA protected TO risu_b27_actor,risu_b27_other;
GRANT SELECT(object_key,state,body,owner_epoch), UPDATE(state,body)
 ON protected.resources TO risu_b27_actor;
ALTER TABLE protected.resources ENABLE ROW LEVEL SECURITY;
ALTER TABLE protected.resources FORCE ROW LEVEL SECURITY;
CREATE POLICY b27_read_target ON protected.resources FOR SELECT TO risu_b27_actor
 USING (object_key='object/approved');
CREATE POLICY b27_write_exact ON protected.resources FOR UPDATE TO risu_b27_actor
 USING (object_key='object/approved' AND state='WAITING' AND body='ORIGINAL APPROVED')
 WITH CHECK (object_key='object/approved' AND state='APPROVED'
             AND body='OWNER APPROVED VALUE' AND owner_epoch='e1');
"""
    must_sql(OWNER,owner_password,
             owner_ddl.replace("ACTOR_SECRET",actor_password).replace("OTHER_SECRET",other_password))
    before=snapshot()
    must(before==ROWS,"Fixture mismatch before any agent execution")
    versions={"server":privileged("SHOW server_version;",DATABASE),
              "binary":call(["/usr/bin/psql","--version"]).stdout.strip()}
    cases=[]
    for name,(identity,sql) in QUERY_CASES.items():
        role,password=(ACTOR,actor_password) if identity=="actor" else (OTHER,other_password)
        result=statement(role,password,sql)
        result["name"]=name
        # Correctly scoped but nonexistent rows can yield UPDATE 0 (not an SQL error).
        if name in ("wrong_object","same_prefix_other_object"):
            must(result["kind"]=="DML" and result["affected"]==0,
                 name+" should be UPDATE 0, got "+str(result))
        elif name=="unapproved_select":
            must(result["kind"]=="SQL" and result["affected"]==0,
                 "other object cannot be SELECTed")
        else:
            must(result["kind"]=="ERROR",name+" unexpectedly succeeded")
        must(snapshot()==before,name+" changed protected DB state")
        cases.append(result)
    # An attacker can invoke native PostgreSQL directly; no RISU gateway is in path.
    def approved():
        return statement(ACTOR,actor_password,SQL_APPROVE)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        f=[pool.submit(approved) for _ in range(2)]
        concurrent_results=[z.result() for z in f]
    observed=sorted([r["affected"] for r in concurrent_results])
    must(observed==[0,1],"Expected one successful PostgreSQL native UPDATE, got "+str(observed))
    after=snapshot()
    expected=[dict(x) for x in ROWS]
    expected[0].update(state="APPROVED",body=AFTER)
    must(after==expected,"Native PostgreSQL resource effect differs from approved target")
    replay=statement(ACTOR,actor_password,SQL_APPROVE)
    must(replay["kind"]=="DML" and replay["affected"]==0,
         "Native RLS must prevent replay")
    # PostgreSQL restart: validate enforcement is durable, not process-local state.
    s=call(["service","postgresql","restart"],timeout=90)
    must(s.returncode==0,"PostgreSQL restart failed: "+s.stderr[-200:])
    time.sleep(1)
    must(snapshot()==after,"PostgreSQL effect not durable after server restart")
    restart_replay=statement(ACTOR,actor_password,SQL_APPROVE)
    must(restart_replay["kind"]=="DML" and restart_replay["affected"]==0,
         "Replay after original service restart should update zero rows")
    must_sql(OWNER,owner_password,"REVOKE UPDATE(state,body) ON protected.resources FROM risu_b27_actor;")
    revoked=statement(ACTOR,actor_password,SQL_APPROVE)
    must(revoked["kind"]=="ERROR","Issuer's native REVOKE did not constrain actor")
    must(snapshot()==after,"Unauthorized request after REVOKE changed owner resource")
    result={
        "schema":"risu-p6b27-native-postgres-external-v1",
        "original_upstream":"PostgreSQL Global Development Group",
        "platform":"native distribution-installed PostgreSQL, no RISU gateway",
        "versions":versions,"database":DATABASE,"owner_role":OWNER,
        "actor_role":ACTOR,"unauthorized_role":OTHER,
        "separate_database_roles":3,"actor_os_uid":pwd.getpwnam(UID_AGENT).pw_uid,
        "owner_issuer_manages_native_role_and_rls":True,
        "policy_type":"PostgreSQL native row-level security USING/WITH CHECK",
        "before":before,"after":after,"negative_cases":cases,
        "concurrent_native_direct_requests":concurrent_results,
        "one_actual_authorized_effect":sum(z["affected"] for z in concurrent_results),
        "attempt_replay":replay,"restart_replay":restart_replay,
        "after_owner_revocation":revoked,
        "owner_credentials_in_output":False,
        "third_party_human_owner":False,
        "claims":"Controlled CI principals; original upstream PostgreSQL engine and native credential/policy issuer",
    }
    out=root/"original_external_postgres_result.json"
    out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print("B27_EXTERNAL_POSTGRESQL_NATIVE_POLICY_AND_EFFECT_PASS")
    print(json.dumps({"denied_cases":len(cases),"native_updates":observed,
                      "replay_after_restart":restart_replay["affected"],
                      "owner_revocation":"denied","version":versions["server"]}))
if __name__=="__main__":main()
