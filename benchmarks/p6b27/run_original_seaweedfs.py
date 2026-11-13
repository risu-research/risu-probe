"""P6-B27 SeaweedFS 4.53 untouched original S3/IAM independent-backend holdout.

Owner uses native upstream IAM APIs; the agent uses upstream S3 directly.
Never upgrades an unsupported policy to broad scope to make target success.
The original binary is obtained and SHA-256 pinned by the GitHub workflow.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import tempfile
import shutil
from urllib.parse import unquote
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, EndpointConnectionError

BUCKET="risu-b27-external"
EXACT="approved/report.txt"
NEIGHBOR="approved/report-extra.txt"
OTHER="other/report.txt"
COARSE="controls/coarse.txt"
PRESET={EXACT:b"RISU-B27-ORIGINAL\n",NEIGHBOR:b"NEIGHBOR-MUST-REMAIN\n",
        OTHER:b"OTHER-MUST-REMAIN\n",COARSE:b"COARSE-INITIAL\n"}
APPROVED=b"RISU-B27-APPROVED\n"
CHANGED=b"RISU-B27-UNAPPROVED-CONTENT\n"
COARSE_AFTER=b"RISU-B27-COARSE-CONTROL\n"
VERSION="4.53"
ENDPOINT="http://127.0.0.1:8333"
CLIENT_CONFIG=Config(signature_version="s3v4",s3={"addressing_style":"path"},
                     retries={"max_attempts":1})
def hash_bytes(data):return hashlib.sha256(data).hexdigest()
def assert_true(x,msg):
    if not x:raise AssertionError(msg)
def client(service,key,secret):
    return boto3.client(service,endpoint_url=ENDPOINT,region_name="us-east-1",
                        aws_access_key_id=key,aws_secret_access_key=secret,
                        config=CLIENT_CONFIG)
def s3_get(admin,key):
    return admin.get_object(Bucket=BUCKET,Key=key)["Body"].read()
def state(admin):
    return {k:hash_bytes(s3_get(admin,k)) for k in PRESET}
def native_request(service,action,**args):
    try:
        val=getattr(service,action)(**args)
        return {"status":val["ResponseMetadata"].get("HTTPStatusCode",200),"error_code":None}
    except ClientError as e:
        return {"status":e.response["ResponseMetadata"].get("HTTPStatusCode",0),
                "error_code":e.response["Error"].get("Code","unknown")}
    except EndpointConnectionError:
        return {"status":0,"error_code":"ENDPOINT_UNAVAILABLE"}
def case(name,actor_credential,action,admin,server_pid,client_script,**args):
    """The actor calls original S3 from a different kernel UID.

    The issuer's admin secret is in root-only orchestration and root-owned
    SeaweedFS env; neither is supplied through argv, stdin or child env.
    """
    import base64
    import pwd
    assert_true(os.geteuid()==0,
                "B27 owner/issuer launcher must be privileged and distinct from actor")
    for k,v in list(args.items()):
        if k=="Body":
            assert_true(type(v) is bytes,"S3 witness only permits literal bytes")
            args[k]=base64.b64encode(v).decode("ascii")
    actor_payload={
        "actor_key_id":actor_credential["AccessKeyId"],
        "actor_secret":actor_credential["SecretAccessKey"],
        "action":action,"args":args,
        "owner_launcher_pid":os.getpid(),
        "publisher_server_pid":server_pid,
    }
    nobody=pwd.getpwnam("nobody")
    minimal_env={"PATH":os.environ.get("PATH","/usr/bin:/bin"),
                 "HOME":"/tmp","TMPDIR":"/tmp","LANG":"C.UTF-8",
                 "PYTHONDONTWRITEBYTECODE":"1","PYTHONNOUSERSITE":"1"}
    child=subprocess.run(
        [sys.executable,str(client_script)],
        input=json.dumps(actor_payload),text=True,capture_output=True,
        env=minimal_env,user=nobody.pw_uid,group=nobody.pw_gid,
        extra_groups=[],timeout=40,
    )
    assert_true(child.returncode==0,
          "Untrusted separate-UID S3 call failed: "+child.stderr[-600:])
    decision=json.loads(child.stdout)
    assert_true(decision["agent_os_uid"]==65534 and
        decision["trusted_publisher_server_environment_readable"] is False and
        decision["trusted_owner_issuer_environment_readable"] is False and
        decision["native_issuer_key_only"] is True and
        decision["direct_original_upstream_s3"] is True,
        "B27 kernel process isolation / native S3 boundary did not hold")
    return {
        "case":name,"native_http_status":decision["native_http_status"],
        "error_code":decision["native_error_code"],
        "agent_os_uid":decision["agent_os_uid"],
        "trusted_publisher_server_environment_readable":False,
        "trusted_owner_issuer_environment_readable":False,
        "native_issuer_key_only":True,
        "direct_original_upstream_s3":True,
        "actual_remote_sha256":state(admin),
    }
def run(binary,out):
    data=out/"seaweed-original-state"
    data.mkdir(exist_ok=True)
    key="B27ADMIN"+secrets.token_hex(12)
    secret=secrets.token_urlsafe(28)
    env=os.environ.copy()
    env.update({"AWS_ACCESS_KEY_ID":key,"AWS_SECRET_ACCESS_KEY":secret,
                "S3_BUCKET":BUCKET})
    # GitHub hosted checkout resides under /home/runner, which is not
    # traversable by UID nobody. Trusted root relocates exact source bytes
    # into its own world-readable, nonwritable-to-agent /tmp directory.
    client_dir=Path(tempfile.mkdtemp(prefix="risu-b27-original-s3-",dir="/tmp"))
    client_dir.chmod(0o755)
    client_script=client_dir/"seaweedfs_untrusted_client.py"
    client_script.write_bytes(
        Path(__file__).with_name("seaweedfs_untrusted_client.py").read_bytes())
    client_script.chmod(0o644)
    assert_true(client_script.stat().st_uid==0
        and (client_script.stat().st_mode & 0o022)==0,
        "Trusted original S3 actor source file not root-owned and immutable by agent")
    log=open(out/"original_server_private.log","w")
    # Original SeaweedFS 4.53 mini defaults embedded IAM to read-only.
    # This documented native config enables the owner's IAM issuer API.
    process=subprocess.Popen([str(binary),"mini","-dir="+str(data),
                              "-s3.iam.readOnly=false"],
                             env=env,stdout=log,stderr=subprocess.STDOUT,
                             start_new_session=True)
    try:
        admin=client("s3",key,secret)
        err=None
        for _ in range(90):
            if process.poll() is not None:
                raise RuntimeError("Original SeaweedFS terminated during startup")
            try:
                admin.list_buckets()
                err=None
                break
            except Exception as ex:
                err=ex
                time.sleep(1)
        assert_true(err is None,"Original S3 endpoint did not become healthy")
        try:
            admin.create_bucket(Bucket=BUCKET)
        except ClientError as e:
            if e.response["Error"].get("Code") not in ("BucketAlreadyOwnedByYou","BucketAlreadyExists"):
                raise
        for name,body in PRESET.items():
            admin.put_object(Bucket=BUCKET,Key=name,Body=body)
        before=state(admin)
        assert_true(before=={k:hash_bytes(v) for k,v in PRESET.items()},
                    "Owner could not establish original-byte controls")
        iam=client("iam",key,secret)
        # Only upstream publisher's IAM methods mint the credentials.
        iam.create_user(UserName="risu_b27_exact")
        iam.create_user(UserName="risu_b27_coarse")
        exact_policy={"Version":"2012-10-17","Statement":[{
          "Effect":"Allow","Action":["s3:PutObject"],
          "Resource":["arn:aws:s3:::"+BUCKET+"/"+EXACT]}]}
        coarse_policy={"Version":"2012-10-17","Statement":[{
          "Effect":"Allow","Action":["s3:PutObject"],
          "Resource":["arn:aws:s3:::"+BUCKET+"/*"]}]}
        iam.put_user_policy(UserName="risu_b27_exact",PolicyName="exact_object_only",
                            PolicyDocument=json.dumps(exact_policy))
        iam.put_user_policy(UserName="risu_b27_coarse",PolicyName="coarse_control",
                            PolicyDocument=json.dumps(coarse_policy))
        exact_key=iam.create_access_key(UserName="risu_b27_exact")["AccessKey"]
        coarse_key=iam.create_access_key(UserName="risu_b27_coarse")["AccessKey"]
        # Agent and broader-control identities only receive their native IAM
        # access keys inside separate unprivileged OS child invocations.
        # This trusted owner/issuer process never executes direct actor S3 calls.
        cases=[]
        cases.append(case("coarse_issuer_positive",coarse_key,"put_object",admin,process.pid,client_script,
              Bucket=BUCKET,Key=COARSE,Body=COARSE_AFTER))
        assert_true(cases[-1]["native_http_status"]==200,
                    "Native publisher IAM bucket-wide baseline grant did not work")
        cases.append(case("exact_object_authorized",exact_key,"put_object",admin,process.pid,client_script,
              Bucket=BUCKET,Key=EXACT,Body=APPROVED))
        cases.append(case("same_prefix_neighbor_direct_bypass",exact_key,"put_object",admin,process.pid,client_script,
              Bucket=BUCKET,Key=NEIGHBOR,Body=b"B27-POSSIBLE-UNAUTHORIZED-NEIGHBOR\n"))
        cases.append(case("other_object_direct_bypass",exact_key,"put_object",admin,process.pid,client_script,
              Bucket=BUCKET,Key=OTHER,Body=b"B27-POSSIBLE-UNAUTHORIZED-FOREIGN\n"))
        cases.append(case("agent_bucket_listing",exact_key,"list_objects_v2",admin,process.pid,client_script,
              Bucket=BUCKET))
        if cases[1]["native_http_status"]==200:
            cases.append(case("approved_object_wrong_value",exact_key,"put_object",admin,process.pid,client_script,
                  Bucket=BUCKET,Key=EXACT,Body=CHANGED))
            cases.append(case("approved_object_replay",exact_key,"put_object",admin,process.pid,client_script,
                  Bucket=BUCKET,Key=EXACT,Body=APPROVED))
        # Native IAM issuer revokes access after all direct-source attempts.
        iam.update_access_key(UserName="risu_b27_exact",
                              AccessKeyId=exact_key["AccessKeyId"],Status="Inactive")
        cases.append(case("issuer_native_key_revocation",exact_key,"put_object",admin,process.pid,client_script,
              Bucket=BUCKET,Key=EXACT,Body=b"AFTER-NATIVE-ISSUER-REVOCATION\n"))
        final=state(admin)
        report={
          "schema":"risu-b27-unmodified-seaweedfs-native-s3-holdout-v1",
          "publisher":"seaweedfs/seaweedfs","release":VERSION,
          "artifact_archive_sha256":"d1a7dec9f48d8b33895a0ea8951971defc2dc5312906dcc76fa5a5f74a6ee90d",
          "original_binary_sha256":hash_bytes(binary.read_bytes()),
          "original_binary_version":subprocess.run([str(binary),"version"],
                    text=True,capture_output=True,timeout=15).stdout.strip()[:300],
          "endpoint":"local isolated S3 service on GitHub CI",
          "iam_issuer":"native original embedded IAM API",
          "exact_policy":exact_policy,"coarse_policy":coarse_policy,
          "real_third_party_human_approval":False,
          "real_third_party_hosting":False,
          "before_sha256":before,"final_sha256":final,
          "cases":cases,
          "actor_separate_posix_uid":65534,
          "native_s3_actor_calls_in_distinct_os_processes":len(cases),
          "owner_admin_credential_not_forwarded_to_actor":True,
          "root_fixture_administrator_trusted":True,
          "key_secret_material_persisted":False,
          "evaluation_protocol":"benchmarks/p6b27/SEAWEEDFS_HOLDOUT_LOCK.md",
        }
        (out/"seaweedfs_live_observation.json").write_text(
            json.dumps(report,indent=2,sort_keys=True)+"\n")
        # A separately authored read-only auditor checks native policy / actual S3 bytes.
        audit_env=os.environ.copy()
        audit_env.update({"B27_OWNER_AWS_ACCESS_KEY":key,
                          "B27_OWNER_AWS_SECRET_KEY":secret})
        auditor=Path(__file__).with_name("independent_seaweedfs_audit.py")
        check=subprocess.run([sys.executable,str(auditor),
                "--observation",str(out/"seaweedfs_live_observation.json"),
                "--out",str(out/"seaweedfs_independent_audit.json")],
                env=audit_env,text=True,capture_output=True,timeout=50)
        assert_true(check.returncode==0,
                    "Independent original S3 audit refused: "+check.stderr[-650:])
        verdict=json.loads((out/"seaweedfs_independent_audit.json").read_text())
        # Tampered case evidence must fail independently, without changing
        # the published server or test rules.
        forged=json.loads((out/"seaweedfs_live_observation.json").read_text())
        forged["cases"][0]["native_http_status"]=403
        (out/"invalid_case_for_auditor_only.json").write_text(json.dumps(forged))
        negative=subprocess.run([sys.executable,str(auditor),
             "--observation",str(out/"invalid_case_for_auditor_only.json"),
             "--out",str(out/"INVALID_REPORT_SHOULD_NOT_EXIST.json")],
             env=audit_env,text=True,capture_output=True,timeout=40)
        assert_true(negative.returncode!=0 and not
              (out/"INVALID_REPORT_SHOULD_NOT_EXIST.json").exists(),
              "Independent S3 auditor accepted modified original result")
        print("B27_SEAWEEDFS_INDEPENDENT_AUDIT_TAMPER_NEGATIVE_PASS")
        print("B27_ORIGINAL_SEAWEEDFS_EXTERNAL_BACKEND_HOLDOUT_MEASURED")
        print(json.dumps({"native_iam":True,"verdict":verdict["verdict"],
             "exact_object":cases[1]["native_http_status"],
             "neighbor":cases[2]["native_http_status"],
             "foreign":cases[3]["native_http_status"],
             "revocation":cases[-1]["native_http_status"],
             "audit":verdict["audit_status"]},sort_keys=True))
    finally:
        process.terminate()
        try:process.wait(timeout=12)
        except subprocess.TimeoutExpired:process.kill();process.wait()
        log.close()
        shutil.rmtree(client_dir)
        # Server logs may include transient credentials; never archive them.

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--weed",required=True)
    ap.add_argument("--out",required=True)
    args=ap.parse_args()
    binary=Path(args.weed).resolve()
    assert_true(binary.is_file(),"Missing upstream official release binary")
    out=Path(args.out).resolve();out.mkdir(parents=True,exist_ok=True)
    run(binary,out)
if __name__=="__main__":main()
