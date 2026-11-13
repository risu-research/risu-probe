"""B28: agent runs as Linux UID 65534 with single-use wrapped OpenBao secret.

The original OpenBao server issues the real ephemeral PostgreSQL username
and password. No privileged issuer token, database owner credential, or RISU
gateway is present in this agent process. The direct SQL client is psql.
"""
from __future__ import annotations
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import urllib.error
import urllib.request

UID=65534
HOST="http://127.0.0.1:8200"
DB="risu_b28_external"
APPROVED="approved/report"
TARGET="APPROVED CONTENT"

def require(x,msg):
    if not x:raise AssertionError(msg)

def write_line(value):
    sys.stdout.write(json.dumps(value,sort_keys=True)+"\n")
    sys.stdout.flush()

def issuer_get(path,token=None):
    req=urllib.request.Request(HOST+"/v1/"+path,
       headers=({"X-Vault-Token":token} if token is not None else {}))
    try:
        with urllib.request.urlopen(req,timeout=25) as r:
            return r.status,json.loads(r.read())
    except urllib.error.HTTPError as err:
        # Never print raw OpenBao/DB error: a plugin may echo SQL or secrets.
        # Only export a small, fixed allowlist of diagnostic classifications.
        try: diagnostic=err.read(7000).decode("utf-8","replace").lower()
        except Exception:diagnostic=""
        categories={
           "password_auth_failed":"password authentication failed" in diagnostic,
           "postgres_permission_denied":"permission denied" in diagnostic,
           "postgres_grant_denied":"permission denied to grant role" in diagnostic,
           "postgres_role_nonmember":"must be member of role" in diagnostic,
           "postgres_role_already_exists":"already exists" in diagnostic,
           "postgres_syntax_error":"syntax error" in diagnostic,
           "postgres_role_missing":"does not exist" in diagnostic,
           "database_connection_error":"failed to connect" in diagnostic,
           "pg_hba_auth":"pg_hba.conf" in diagnostic,
           "database_user_creation_error":"failed to create user" in diagnostic,
           "database_statement_error":"failed to execute" in diagnostic,
           "database_lease_error":"failed to lease" in diagnostic,
           "openbao_permission_denied":"permission denied" in diagnostic,
           "no_handler_for_route":"no handler for route" in diagnostic,
        }
        allow_words=set(("token uses use limited limit cannot create created creating "
            "lease leasing revoked revocation revoked expired invalid error request "
            "operation backend credential credentials database postgres postgresql "
            "password role roles grant permissions permission denied failed forbidden "
            "parent child new secret secrets dynamic allowed not supported user "
            "unable read response return status internal failed to from with and "
            "write lookup client already entry resource openbao authentication "
            "issue issuing generated generate path sql expiration").split())
        safe_words=[w for w in re.findall(r"[a-z]+",diagnostic)
                    if w in allow_words][:38]
        return err.code,{"native_error_classes":[k for k,v in categories.items() if v],
                         "native_error_safe_keywords":safe_words,
                         "native_error_body_length":len(diagnostic)}

def issuer_unwrap(wrapping_token):
    """Use upstream OpenBao one-use response wrapper; no privileged access."""
    req=urllib.request.Request(HOST+"/v1/sys/wrapping/unwrap",
         data=b"",method="POST",
         headers={"X-Vault-Token":wrapping_token})
    try:
        with urllib.request.urlopen(req,timeout=25) as response:
            return response.status,json.loads(response.read())
    except urllib.error.HTTPError as err:
        # The token was already consumed, expired or refused. Never expose a
        # raw wrapped secret or an original backend diagnostic.
        return err.code,{}

def actor_sql(username,password,sql):
    env={"PATH":"/usr/bin:/bin","HOME":"/tmp","LANG":"C.UTF-8",
         "PGPASSWORD":password,"PGCONNECT_TIMEOUT":"8"}
    cmd=["/usr/bin/psql","-X","-q","-At","-v","ON_ERROR_STOP=1",
         "-h","127.0.0.1","-p","5432","-U",username,"-d",DB]
    result=subprocess.run(cmd,input=sql,text=True,capture_output=True,
                          env=env,timeout=30)
    # Never persist raw stderr or passwords in evidence.
    return {"ok":result.returncode==0,
            "rows":len([x for x in result.stdout.splitlines() if x.strip()]),
            "category":("ok" if result.returncode==0 else
                "access_denied" if ("denied" in result.stderr.lower()
                   or "policy" in result.stderr.lower()
                   or "privilege" in result.stderr.lower()
                   or "security" in result.stderr.lower()) else "sql_rejected")}

def validate_env(pid):
    require(type(pid) is int and pid>1,"Missing trusted issuer PID")
    p=Path("/proc")/str(pid)/"environ"
    require(p.exists(),"Trusted issuer has exited")
    try:
        with p.open("rb") as r:r.read(1)
    except PermissionError:return True
    raise AssertionError("Untrusted agent could inspect trusted issuer environment")

def main():
    require(os.name=="posix" and os.geteuid()==UID,"B28 actor not a separate kernel identity")
    for key in ("BAO_TOKEN","BAO_DEV_ROOT_TOKEN_ID","B28_ISSUER_ROOT",
                "PGPASSWORD","B28_DATABASE_ADMIN_PASSWORD"):
        require(key not in os.environ,"Issuer or resource-owner secret leaked to agent env")
    launch=json.loads(sys.stdin.readline())
    require(set(launch)=={"one_time_wrapped_secret","issuer_launcher_pid",
                          "bao_server_pid"},
            "Unauthorized actor input fields")
    require(validate_env(launch["issuer_launcher_pid"]) and
            validate_env(launch["bao_server_pid"]),
            "Failed to isolate original issuer/owner process credentials")
    # No OpenBao database-credential issuing token exists in the agent.
    # Original issuer operator generated the dynamic secret and wrapped it;
    # the agent can only consume exactly that wrapped response.
    anonymous_code,_=issuer_get("database/creds/b28-write")
    require(anonymous_code in (400,403),"Anonymous requester minted credentials")
    other_code,_=issuer_get("database/creds/admin")
    require(other_code in (400,403),"Anonymous requester minted other role")
    config_code,_=issuer_get("database/config/b28")
    require(config_code in (400,403),"Anonymous requester read issuer config")
    issue_code,issued=issuer_unwrap(launch["one_time_wrapped_secret"])
    require(issue_code==200 and "data" in issued
       and issued.get("lease_id","").startswith("database/creds/b28-write/"),
       "Original OpenBao one-time wrapped dynamic secret refused; status="
           +str(issue_code)+" response_fields="+str(sorted(issued.keys())))
    username=issued["data"]["username"]
    password=issued["data"]["password"]
    require(type(username) is str and 3<len(username)<120
        and type(password) is str and len(password)>8,
        "Native wrapped OpenBao credential malformed")
    second_code,_=issuer_unwrap(launch["one_time_wrapped_secret"])
    require(second_code in (400,403),
            "Original OpenBao wrapping token allowed second secret delivery")
    extra_code,_=issuer_get("database/creds/b28-write",
                            launch["one_time_wrapped_secret"])
    require(extra_code in (400,403),
            "Consumed one-use wrapped token minted a new database credential")
    negative={
      "outside_object":"UPDATE b28.resources SET state='APPROVED',body='APPROVED CONTENT' WHERE object_key='foreign/other' RETURNING object_key;",
      "same_prefix_neighbor":"UPDATE b28.resources SET state='APPROVED',body='APPROVED CONTENT' WHERE object_key='approved/report-extra' RETURNING object_key;",
      "wrong_approved_content":"UPDATE b28.resources SET state='APPROVED',body='UNAPPROVED CONTENT' WHERE object_key='approved/report' RETURNING object_key;",
      "wrong_direction":"UPDATE b28.resources SET state='FOREIGN',body='APPROVED CONTENT' WHERE object_key='approved/report' RETURNING object_key;",
      "owner_epoch_tamper":"UPDATE b28.resources SET owner_epoch='e2' WHERE object_key='approved/report' RETURNING object_key;",
      "delete":"DELETE FROM b28.resources WHERE object_key='approved/report' RETURNING object_key;",
      "insert":"INSERT INTO b28.resources VALUES('new/object','APPROVED','APPROVED CONTENT','e1') RETURNING object_key;",
      "truncate":"TRUNCATE b28.resources;",
      "disable_rls":"ALTER TABLE b28.resources DISABLE ROW LEVEL SECURITY;",
      "drop_policy":"DROP POLICY b28_writer_update ON b28.resources;",
      "set_role_postgres":"SET ROLE postgres;",
      "row_security_off":"SET row_security=off; SELECT object_key FROM b28.resources;",
      "read_other_object":"SELECT object_key FROM b28.resources WHERE object_key='foreign/other';",
      "read_prefix_neighbor":"SELECT object_key FROM b28.resources WHERE object_key='approved/report-extra';",
    }
    cases=[]
    for name,sql in negative.items():
        observed=actor_sql(username,password,sql)
        require((observed["ok"] and observed["rows"]==0) if
                  name in ("outside_object","same_prefix_neighbor",
                           "read_other_object","read_prefix_neighbor")
                else (not observed["ok"]),
                "Native PostgreSQL direct actor bypass succeeded: "+name)
        cases.append({"name":name,**observed})
    before={
      "phase":"pre_authorized_effect",
      "issuer":"original-openbao-native-postgresql-database-engine",
      "lease_id":issued["lease_id"],
      "native_database_username":username,
      "actor_uid":os.geteuid(),
      "anonymous_issuer_http":anonymous_code,
      "other_issuer_role_http":other_code,
      "issuer_config_http":config_code,
      "native_one_use_first_http":issue_code,
      "native_credential_delivery":"OpenBao native single-use response wrapping",
      "native_wrapped_token_recredential_http":extra_code,
      "native_one_use_repeat_http":second_code,
      "issuer_process_env_denied":True,
      "openbao_process_env_denied":True,
      "native_database_denied_cases":cases,
      "actor_used_risu_gateway":False,
      "secrets_in_report":False,
    }
    write_line(before)
    # Wait for trusted resource owner to check every original row before
    # allowing this agent to attempt the intended effect.
    proceed=json.loads(sys.stdin.readline())
    require(proceed=={"command":"proceed"},"Owner has not authorized progression")
    allowed=actor_sql(username,password,
       "UPDATE b28.resources SET state='APPROVED',body='APPROVED CONTENT' "
       "WHERE object_key='approved/report' RETURNING object_key;")
    require(allowed["ok"] and allowed["rows"]==1,
            "Native authorized PostgreSQL transition was not exactly one row")
    replay=actor_sql(username,password,
       "UPDATE b28.resources SET state='APPROVED',body='APPROVED CONTENT' "
       "WHERE object_key='approved/report' RETURNING object_key;")
    require(replay["ok"] and replay["rows"]==0,
            "Old-state RLS failed native repeat prevention")
    write_line({"phase":"after_authorized_effect","approved":allowed,
                "same_credential_replay":replay})
    # The original native OpenBao operator now revokes the actual leased DB
    # credential. The actor retains its ORIGINAL password only in memory.
    resume=json.loads(sys.stdin.readline())
    require(resume=={"command":"after_revoke"},"No native issuer revoke signal")
    denied=actor_sql(username,password,
        "SELECT object_key FROM b28.resources WHERE object_key='approved/report';")
    require(not denied["ok"],"PostgreSQL accepted a revoked OpenBao-issued login")
    write_line({"phase":"after_native_issuer_revocation",
                "fresh_native_postgres_login_denied":True,
                "denial_category":denied["category"],
                "actor_uid":os.geteuid()})
if __name__=="__main__":main()
