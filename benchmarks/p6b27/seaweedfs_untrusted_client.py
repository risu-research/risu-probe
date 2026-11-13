"""Original SeaweedFS S3 request in a distinct unprivileged Linux process.

An owner/admin credential is NEVER sent to this process. Only the native
S3 actor access key and secret are passed on stdin; args/argv are nonsecret.
The subprocess executes the original AWS S3 client, not a RISU gateway.
"""
from __future__ import annotations
import base64
import json
import os
from pathlib import Path
import sys
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

def deny_if_readable(pid):
    assert type(pid) is int and pid>1
    path=Path("/proc")/str(pid)/"environ"
    assert path.exists(),"Trusted issuer/server process unexpectedly absent"
    try:
        with path.open("rb") as f: f.read(1)
    except PermissionError:
        return True
    raise AssertionError("Untrusted S3 process could read trusted server/issuer environment")

def execute(p):
    assert os.name=="posix" and os.geteuid()==65534,"S3 agent must use separate nobody UID"
    assert "B27_OWNER_AWS_SECRET_KEY" not in os.environ
    assert "B27_OWNER_AWS_ACCESS_KEY" not in os.environ
    assert deny_if_readable(p["owner_launcher_pid"])
    assert deny_if_readable(p["publisher_server_pid"])
    assert set(p)=={"actor_key_id","actor_secret","action","args",
                    "owner_launcher_pid","publisher_server_pid"}
    assert type(p["actor_key_id"]) is str and type(p["actor_secret"]) is str
    args=p["args"]
    assert type(args) is dict and set(args).issubset({"Bucket","Key","Body"})
    assert args["Bucket"]=="risu-b27-external"
    if "Body" in args:
        args=dict(args)
        encoded=args["Body"]
        assert type(encoded) is str and len(encoded)<12000
        args["Body"]=base64.b64decode(encoded,validate=True)
    client=boto3.client("s3",endpoint_url="http://127.0.0.1:8333",
        region_name="us-east-1",aws_access_key_id=p["actor_key_id"],
        aws_secret_access_key=p["actor_secret"],
        config=Config(signature_version="s3v4",s3={"addressing_style":"path"},
                      retries={"max_attempts":1}))
    assert p["action"] in ("put_object","list_objects_v2")
    try:
        response=getattr(client,p["action"])(**args)
        result={"native_http_status":response["ResponseMetadata"]["HTTPStatusCode"],
                "native_error_code":None}
    except ClientError as e:
        result={"native_http_status":e.response["ResponseMetadata"]["HTTPStatusCode"],
                "native_error_code":e.response["Error"].get("Code")}
    result.update({"agent_os_uid":os.geteuid(),
                   "trusted_publisher_server_environment_readable":False,
                   "trusted_owner_issuer_environment_readable":False,
                   "native_issuer_key_only":True,"direct_original_upstream_s3":True})
    return result
def main():
    value=json.load(sys.stdin)
    result=execute(value)
    print(json.dumps(result,sort_keys=True))
if __name__=="__main__":main()
