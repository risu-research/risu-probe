"""P6-B28: original OpenBao dynamic credentials and original PostgreSQL RLS.

Trusted CI fixture owner/issuer orchestrates. Linux UID 65534 agent runs
the separate, unmodified-API client. All native secrets stay in memory or
root-only temporary startup log, never in persisted evidence artifacts.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

DB="risu_b28_external"
OWNER="b28_owner"
DB_ISSUER="b28_bao_issuer"
TEMPLATE="b28_template_writer"
KEY="approved/report"
INITIAL=[
 {"object_key":"approved/report","state":"WAITING","body":"ORIGINAL APPROVED","owner_epoch":"e1"},
 {"object_key":"approved/report-extra","state":"WAITING","body":"NEIGHBOR","owner_epoch":"e1"},
 {"object_key":"foreign/other","state":"WAITING","body":"FOREIGN","owner_epoch":"e1"},
]
EXPECTED=[{**v} for v in INITIAL]
EXPECTED[0].update(state="APPROVED",body="APPROVED CONTENT")
EXPECTED_NAMES={
 "outside_object","same_prefix_neighbor","wrong_approved_content",
 "wrong_direction","owner_epoch_tamper","delete","insert","truncate",
 "disable_rls","drop_policy","set_role_postgres","row_security_off",
 "read_other_object","read_prefix_neighbor",
}
def must(ok,msg):
    if not ok:raise AssertionError(msg)
def subprocess_call(cmd,stdin=None,env=None,timeout=45):
    clean=os.environ.copy()
    if env:clean.update(env)
    return subprocess.run(cmd,input=stdin,text=True,capture_output=True,
                          env=clean,timeout=timeout)
def privileged(sql,db="postgres"):
    p=subprocess_call(["runuser","-u","postgres","--","psql","-X","-q",
               "-v","ON_ERROR_STOP=1","-At","-d",db],sql)
    must(p.returncode==0,"Original PostgreSQL fixture owner setup failed: "+p.stderr[-400:])
    return p.stdout.strip()
def sql_json(sql):
    return json.loads(privileged(sql,DB))
def original_rows():
    return sql_json("""SELECT coalesce(json_agg(row_to_json(x) ORDER BY x.object_key),'[]'::json)
       FROM (SELECT object_key,state,body,owner_epoch FROM b28.resources ORDER BY object_key) x;""")
def hash_content(v):
    return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(",",":")).encode()).hexdigest()
def configure_postgres():
    admin_pw=secrets.token_urlsafe(24)
    issuer_pw=secrets.token_urlsafe(24)
    privileged(
       "CREATE ROLE b28_owner LOGIN NOSUPERUSER NOCREATEROLE NOBYPASSRLS PASSWORD '"+admin_pw+"';\n"
       "CREATE ROLE b28_bao_issuer LOGIN CREATEROLE NOSUPERUSER NOBYPASSRLS PASSWORD '"+issuer_pw+"';\n"
       "CREATE ROLE b28_template_writer NOLOGIN NOSUPERUSER NOBYPASSRLS;\n"
       "GRANT b28_template_writer TO b28_bao_issuer WITH ADMIN OPTION;\n"
       "CREATE DATABASE "+DB+" OWNER b28_owner;")
    privileged("""
       SET ROLE b28_owner;
       CREATE SCHEMA b28;
       CREATE TABLE b28.resources(object_key text PRIMARY KEY,state text NOT NULL,
                                  body text NOT NULL,owner_epoch text NOT NULL);
       INSERT INTO b28.resources VALUES
          ('approved/report','WAITING','ORIGINAL APPROVED','e1'),
          ('approved/report-extra','WAITING','NEIGHBOR','e1'),
          ('foreign/other','WAITING','FOREIGN','e1');
       ALTER TABLE b28.resources ENABLE ROW LEVEL SECURITY;
       ALTER TABLE b28.resources FORCE ROW LEVEL SECURITY;
       CREATE POLICY b28_writer_select ON b28.resources FOR SELECT
           TO b28_template_writer USING (object_key='approved/report');
       CREATE POLICY b28_writer_update ON b28.resources FOR UPDATE
           TO b28_template_writer
           USING (object_key='approved/report' AND state='WAITING'
                  AND body='ORIGINAL APPROVED' AND owner_epoch='e1')
           WITH CHECK (object_key='approved/report' AND state='APPROVED'
                       AND body='APPROVED CONTENT' AND owner_epoch='e1');
       GRANT USAGE ON SCHEMA b28 TO b28_template_writer;
       GRANT SELECT(object_key,state,body,owner_epoch),UPDATE(state,body)
         ON b28.resources TO b28_template_writer;
       RESET ROLE;""",DB)
    must(original_rows()==INITIAL,"Unexpected original PostgreSQL prestate")
    return issuer_pw

def issuer_cmd(binary,token,args,timeout=50):
    env={"BAO_ADDR":"http://127.0.0.1:8200",
         "BAO_TOKEN":token,"BAO_TOKEN_PATH":"/dev/null"}
    p=subprocess_call([str(binary),*args],env=env,timeout=timeout)
    must(p.returncode==0,"Original OpenBao API configuration or revocation failed"
         +" (exit "+str(p.returncode)+")")
    return p.stdout.strip()
def boot_issuer(binary,private):
    private.mkdir(parents=True,exist_ok=True)
    private.chmod(0o700)
    log_file=private/"original_openbao_dev_private_do_not_archive.log"
    with log_file.open("w") as s:
        server=subprocess.Popen([str(binary),"server","-dev",
           "-dev-listen-address=127.0.0.1:8200","-dev-no-store-token"],
           stdout=s,stderr=subprocess.STDOUT,
           env={"PATH":"/usr/bin:/bin","HOME":str(private),
                "BAO_TOKEN_PATH":"/dev/null","LANG":"C.UTF-8"},
           start_new_session=True)
    # OpenBao dev issues the root token, printing it only in a root-only file.
    root_token=None
    for _ in range(90):
        must(server.poll() is None,"Original issuer terminated before startup")
        raw=log_file.read_text(errors="replace")
        found=re.search(r"Root Token:\s*([^\s]+)",raw)
        if found:
            root_token=found.group(1)
            try:
                r=urllib.request.urlopen(
                    "http://127.0.0.1:8200/v1/sys/health",timeout=3)
                if r.status==200:break
            except Exception:pass
        time.sleep(.3)
    must(root_token is not None,"Original OpenBao root token unavailable")
    must(server.poll() is None,"Original OpenBao server stopped")
    return server,root_token

def configure_issuer(binary,root_token,issuer_password):
    issuer_cmd(binary,root_token,["secrets","enable","database"])
    # This connection is administered by the original OpenBao PostgreSQL
    # database plugin using a narrowly scoped non-superuser, never the
    # resource owner or PostgreSQL superuser account.
    issuer_cmd(binary,root_token,[
      "write","database/config/b28",
      "plugin_name=postgresql-database-plugin",
      "allowed_roles=b28-write",
      "connection_url=postgresql://{{username}}:{{password}}@127.0.0.1:5432/"
          +DB+"?sslmode=disable",
      "username="+DB_ISSUER,
      "password="+issuer_password,
      "password_authentication=scram-sha-256",
    ])
    creation=(
       """CREATE ROLE "{{name}}" WITH LOGIN INHERIT PASSWORD '{{password}}' """
       """VALID UNTIL '{{expiration}}'; GRANT b28_template_writer TO "{{name}}";"""
    )
    revocation=(
       """REVOKE b28_template_writer FROM "{{name}}"; DROP ROLE IF EXISTS "{{name}}";"""
    )
    issuer_cmd(binary,root_token,[
       "write","database/roles/b28-write","db_name=b28",
       "creation_statements="+creation,
       "revocation_statements="+revocation,
       "default_ttl=5m","max_ttl=10m",
    ])
    policy='path "database/creds/b28-write" { capabilities = ["read"] }\n'
    policy_path=Path(tempfile.mkstemp(prefix="b28-owner-policy-",suffix=".hcl")[1])
    try:
        policy_path.write_text(policy)
        policy_path.chmod(0o600)
        issuer_cmd(binary,root_token,["policy","write","b28_actor_only",str(policy_path)])
    finally:
        policy_path.unlink()
    def issue_one_use(use_limit):
        j=json.loads(issuer_cmd(binary,root_token,[
          "token","create","-policy=b28_actor_only","-no-default-policy",
          "-use-limit="+str(use_limit),"-ttl=5m","-format=json"
        ]))
        token=j["auth"]["client_token"]
        must(len(token)>15,"Original OpenBao issued implausible short token")
        return token
    return issue_one_use(1),issue_one_use(0)

def materialize_actor():
    trusted=Path(__file__).with_name("untrusted_openbao_pg_actor.py")
    target_dir=Path(tempfile.mkdtemp(prefix="risu-b28-agent-",dir="/tmp"))
    target_dir.chmod(0o755)
    target=target_dir/trusted.name
    target.write_bytes(trusted.read_bytes())
    target.chmod(0o644)
    st=target.stat()
    must(st.st_uid==0 and (st.st_mode&0o022)==0,
          "Agent executable is not owner-pinned and nonwritable")
    return target_dir,target

def live_report(out,script,bao_process,root_token,bao_binary,
                actor_token,prober_token):
    actor_user=pwd.getpwnam("nobody")
    clean_env={"PATH":"/usr/bin:/bin","HOME":"/tmp","LANG":"C.UTF-8",
               "PYTHONUNBUFFERED":"1","PYTHONDONTWRITEBYTECODE":"1"}
    child=subprocess.Popen([sys.executable,str(script)],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        text=True,bufsize=1,env=clean_env,
        user=actor_user.pw_uid,group=actor_user.pw_gid,extra_groups=[])
    def send(item):
        child.stdin.write(json.dumps(item)+"\n")
        child.stdin.flush()
    def phase(label):
        line=child.stdout.readline()
        if not line:
            err=child.stderr.read(1500)
            raise AssertionError("B28 native untrusted actor exited before "+label+
                                 ", error="+err[-850:])
        data=json.loads(line)
        must(data.get("phase")==label,"Native agent phase discrepancy")
        return data
    try:
        send({"restricted_bao_token":actor_token,
              "other_role_token":prober_token,
              "issuer_launcher_pid":os.getpid(),
              "bao_server_pid":bao_process.pid})
        first=phase("pre_authorized_effect")
        must(first["actor_uid"]==65534 and
             first["issuer_process_env_denied"] is True and
             first["openbao_process_env_denied"] is True,
             "Original issuer vs attacker kernel isolation failed")
        must({x["name"] for x in first["native_database_denied_cases"]}==EXPECTED_NAMES
             and len(first["native_database_denied_cases"])==len(EXPECTED_NAMES),
             "Native unauthorized SQL test set was not complete")
        must(original_rows()==INITIAL,
             "Denied native PostgreSQL requests unexpectedly changed owner row(s)")
        send({"command":"proceed"})
        second=phase("after_authorized_effect")
        must(second["approved"]["ok"] and second["approved"]["rows"]==1 and
             second["same_credential_replay"]["rows"]==0,
             "Original PostgreSQL direction-constrained effect/replay failed")
        after=original_rows()
        must(after==EXPECTED,"Native resource bytes or unaffected controls changed")
        username=first["native_database_username"]
        must(re.fullmatch(r"[A-Za-z0-9_-]{5,110}",username) is not None,
             "Unexpected original OpenBao generated username")
        native_exists=privileged(
           "SELECT count(*) FROM pg_roles WHERE rolname='"+username+"';")
        must(native_exists=="1","Original OpenBao issued SQL login not present")
        lease_id=first["lease_id"]
        must(re.fullmatch(r"database/creds/b28-write/[A-Za-z0-9-]+",lease_id),
             "Unexpected external issuer lease identifier")
        issuer_cmd(bao_binary,root_token,["lease","revoke",lease_id])
        for _ in range(16):
            native_exists=privileged(
               "SELECT count(*) FROM pg_roles WHERE rolname='"+username+"';")
            if native_exists=="0":break
            time.sleep(.3)
        must(native_exists=="0","Original OpenBao revocation did not remove native PG role")
        send({"command":"after_revoke"})
        third=phase("after_native_issuer_revocation")
        must(third["fresh_native_postgres_login_denied"] is True
             and third["actor_uid"]==65534,
             "Native PostgreSQL still accepts revoked ephemeral credential")
        child.stdin.close()
        code=child.wait(timeout=35)
        if code!=0:
            raise AssertionError("B28 untrusted agent failed after revoke: "+
                               child.stderr.read(700))
        evidence={
          "schema":"risu-b28-original-openbao-postgresql-external-issuer-v1",
          "actual_issuer_binary_version":issuer_cmd(bao_binary,root_token,["version"]),
          "actual_pg_version":privileged("SHOW server_version;",DB),
          "issuer_original_upstream":"openbao/openbao",
          "resource_original_upstream":"PostgreSQL Global Development Group",
          "issuer_version_pin":"v2.7.2",
          "issuer_running_pid":bao_process.pid,
          "issuer_native_dynamic_database_plugin":"postgresql-database-plugin",
          "issuer_native_root_operator_token_in_actor":False,
          "trusted_fixture_administrator":True,
          "unrelated_external_human_owner":False,
          "third_party_operated_service":False,
          "native_before":INITIAL,
          "native_after":after,
          "native_before_sha256":hash_content(INITIAL),
          "native_after_sha256":hash_content(after),
          "native_issuer_dynamic_username":username,
          "native_issuer_lease_id":lease_id,
          "postgresql_native_role_present_before_revoke":True,
          "postgresql_native_role_present_after_revoke":False,
          "untrusted_actor_pre":first,
          "untrusted_actor_effect":second,
          "untrusted_actor_after_revocation":third,
          "secrets_persisted":False,
        }
        (out/"original_native_issuer_resource_result.json").write_text(
            json.dumps(evidence,indent=2,sort_keys=True)+"\n")
        return evidence
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=10)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--bao-binary",required=True)
    p.add_argument("--out",required=True)
    args=p.parse_args()
    must(os.geteuid()==0,"Trusted owner orchestrator must run as Linux root")
    bao=Path(args.bao_binary).resolve()
    must(bao.is_file(),"Original upstream OpenBao binary missing")
    out=Path(args.out).resolve()
    out.mkdir(parents=True,exist_ok=True)
    original_pg=configure_postgres()
    server=None
    temp_dir=None
    try:
        server,root=boot_issuer(bao,out/"private")
        try:
            authorized_token,probe_token=configure_issuer(bao,root,original_pg)
            temp_dir,untrusted_script=materialize_actor()
            record=live_report(out,untrusted_script,server,root,bao,
                               authorized_token,probe_token)
            # Independent script independently queries original PostgreSQL
            # system catalogs and original OpenBao HTTP service. It imports
            # no orchestration or agent modules and receives no actor creds.
            independent=Path(__file__).with_name("independent_b28_openbao_pg_audit.py")
            audit_env=os.environ.copy()
            audit_env["BAO_ADDR"]="http://127.0.0.1:8200"
            audit_env["BAO_TOKEN"]=root
            out_audit=out/"independent_original_backend_audit.json"
            verified=subprocess_call([sys.executable,str(independent),
                "--observed",str(out/"original_native_issuer_resource_result.json"),
                "--out",str(out_audit)],env=audit_env,timeout=45)
            must(verified.returncode==0,
                 "Independent OpenBao/Postgres original issuer audit rejected: "+
                  verified.stderr[-450:])
            tampered={**record}
            tampered["untrusted_actor_effect"]={
                "phase":"after_authorized_effect",
                "approved":{"ok":True,"rows":2},
                "same_credential_replay":{"ok":True,"rows":0}}
            invalid=out/"TAMPERED_NEGATIVE_RESULT.json"
            invalid.write_text(json.dumps(tampered))
            bad=subprocess_call([sys.executable,str(independent),
                "--observed",str(invalid),
                "--out",str(out/"INVALID_SHOULD_NOT_EXIST.json")],
                env=audit_env,timeout=45)
            must(bad.returncode!=0 and
                  not (out/"INVALID_SHOULD_NOT_EXIST.json").exists(),
                  "Independent original issuer auditor accepted altered effect")
            print("B28_ORIGINAL_OPENBAO_NATIVE_DATABASE_LEASE_AND_POSTGRESQL_EFFECT_PASS")
            print(json.dumps({
                "dynamic_issuer":"OpenBao 2.7.2",
                "original_resource":"PostgreSQL",
                "direct_sql_denied_controls":len(EXPECTED_NAMES),
                "authorized_rows_modified":1,"replay_rows_modified":0,
                "revoked_lease_fresh_login":"denied",
                "independent_native_audit":"PASS",
                "untrusted_agent_linux_uid":65534
            },sort_keys=True))
        finally:
            if temp_dir:shutil.rmtree(temp_dir)
    finally:
        if server is not None:
            server.terminate()
            try:server.wait(timeout=12)
            except subprocess.TimeoutExpired:server.kill();server.wait()
        # Never archive private OpenBao root token or startup logs.
        shutil.rmtree(out/"private",ignore_errors=True)
if __name__=="__main__":main()
