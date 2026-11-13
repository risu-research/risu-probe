"""Independent read-only audit of an original SeaweedFS 4.53 S3/IAM server.

This code does not import the experimental caller, RISU broker, or authority
evaluator. It independently queries actual object bytes and native IAM policy.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
from urllib.parse import unquote
import boto3
from botocore.config import Config

BUCKET="risu-b27-external"
OBJECTS={
 "approved/report.txt":b"RISU-B27-ORIGINAL\n",
 "approved/report-extra.txt":b"NEIGHBOR-MUST-REMAIN\n",
 "other/report.txt":b"OTHER-MUST-REMAIN\n",
 "controls/coarse.txt":b"COARSE-INITIAL\n",
}
APPROVED=b"RISU-B27-APPROVED\n"
BAD=b"RISU-B27-UNAPPROVED-CONTENT\n"
CHANGES={
 "coarse_issuer_positive":("controls/coarse.txt",b"RISU-B27-COARSE-CONTROL\n"),
 "exact_object_authorized":("approved/report.txt",APPROVED),
 "same_prefix_neighbor_direct_bypass":("approved/report-extra.txt",
                                       b"B27-POSSIBLE-UNAUTHORIZED-NEIGHBOR\n"),
 "other_object_direct_bypass":("other/report.txt",b"B27-POSSIBLE-UNAUTHORIZED-FOREIGN\n"),
 "approved_object_wrong_value":("approved/report.txt",BAD),
 "approved_object_replay":("approved/report.txt",APPROVED),
 "issuer_native_key_revocation":("approved/report.txt",
                                 b"AFTER-NATIVE-ISSUER-REVOCATION\n"),
}
BASE_ORDER=["coarse_issuer_positive","exact_object_authorized",
 "same_prefix_neighbor_direct_bypass","other_object_direct_bypass",
 "agent_bucket_listing"]
AFTER_ORDER=["approved_object_wrong_value","approved_object_replay"]
LAST="issuer_native_key_revocation"
def sha(data):return hashlib.sha256(data).hexdigest()
def demand(ok,msg):
    if not ok:raise ValueError(msg)
def client(service):
    return boto3.client(service,endpoint_url="http://127.0.0.1:8333",
        region_name="us-east-1",
        aws_access_key_id=os.environ["B27_OWNER_AWS_ACCESS_KEY"],
        aws_secret_access_key=os.environ["B27_OWNER_AWS_SECRET_KEY"],
        config=Config(signature_version="s3v4",s3={"addressing_style":"path"},
                      retries={"max_attempts":1}))
def get_bytes(s3,key):
    return s3.get_object(Bucket=BUCKET,Key=key)["Body"].read()
def parse_policy(x):
    v=x["PolicyDocument"]
    if not isinstance(v,dict):
        v=json.loads(unquote(v))
    return v
def audit(data):
    demand(data.get("schema")=="risu-b27-unmodified-seaweedfs-native-s3-holdout-v1",
           "Unexpected external S3 result schema")
    demand(data.get("publisher")=="seaweedfs/seaweedfs"
       and data.get("release")=="4.53","Unpinned external server release")
    demand(data.get("artifact_archive_sha256")==
       "d1a7dec9f48d8b33895a0ea8951971defc2dc5312906dcc76fa5a5f74a6ee90d",
       "Upstream published binary archive not fixed")
    demand(data.get("real_third_party_human_approval") is False
       and data.get("real_third_party_hosting") is False,
       "Unsupported third-party human/hosting claim")
    demand(data.get("key_secret_material_persisted") is False,
           "Agent/admin credential secrets should not be archived")
    demand("4.53" in data.get("original_binary_version",""),
           "Original server binary version mismatch")
    requested=data["cases"]
    names=[c["case"] for c in requested]
    expected=BASE_ORDER+(AFTER_ORDER if
        requested[1]["native_http_status"]==200 else [])+[LAST]
    demand(names==expected,"Native S3 heldout test scope was changed or truncated")
    demand(requested[0]["native_http_status"]==200,
           "Original SeaweedFS native IAM coarse control did not function")
    require_deny={"same_prefix_neighbor_direct_bypass",
                  "other_object_direct_bypass","agent_bucket_listing"}
    for c in requested:
        demand(type(c["native_http_status"]) is int and
               c["native_http_status"] in (200,403),
               "Unsupported original API outcome; do not misclassify setup failure")
    # Independently replay every original state transition; a 403/deny must
    # preserve all bytes, and accepted effect must change only requested key.
    virtual=dict(OBJECTS)
    demand(data["before_sha256"]=={k:sha(v) for k,v in virtual.items()},
           "Publisher original precondition bytes mismatched")
    for c in requested:
        name,status=c["case"],c["native_http_status"]
        if status==200 and name in CHANGES:
            target,new=CHANGES[name]
            virtual[target]=new
        target_sha={k:sha(v) for k,v in virtual.items()}
        demand(c.get("actual_remote_sha256")==target_sha,
               "Original S3 case "+name+" actual byte state disagrees with recorded verdict")
    expected_end={k:sha(v) for k,v in virtual.items()}
    demand(data["final_sha256"]==expected_end,
           "Original S3 final state claim disagrees with case-by-case effects")
    # Fresh remote queries, independent of the benchmark's S3 read calls.
    s3=client("s3");iam=client("iam")
    fresh={k:sha(get_bytes(s3,k)) for k in OBJECTS}
    demand(fresh==expected_end,"Independent remote S3 GET detected a changed effect")
    native_exact=parse_policy(iam.get_user_policy(
        UserName="risu_b27_exact",PolicyName="exact_object_only"))
    native_coarse=parse_policy(iam.get_user_policy(
        UserName="risu_b27_coarse",PolicyName="coarse_control"))
    demand(native_exact==data["exact_policy"],"Native issued exact scope differs")
    demand(native_coarse==data["coarse_policy"],"Native coarse control differs")
    require_resource="arn:aws:s3:::"+BUCKET+"/approved/report.txt"
    demand(native_exact["Statement"][0]["Resource"]==[require_resource],
           "Native IAM authorization expanded beyond one original object")
    keys=iam.list_access_keys(UserName="risu_b27_exact")["AccessKeyMetadata"]
    demand(len(keys)==1 and keys[0]["Status"]=="Inactive",
           "Original upstream IAM has not revoked the original actor credential")
    byname={c["case"]:c["native_http_status"] for c in requested}
    out_of_scope=[k for k in ("same_prefix_neighbor_direct_bypass",
                            "other_object_direct_bypass") if byname[k]==200]
    list_exposed=byname["agent_bucket_listing"]==200
    exact_allowed=(byname["exact_object_authorized"]==200)
    revocation_denied=(byname[LAST]==403)
    if out_of_scope or list_exposed:
        verdict="EXTERNAL_SCOPE_BYPASS_OBSERVED"
    elif not exact_allowed:
        verdict="EXTERNAL_NATIVE_POLICY_REJECTS_VALID_TARGET"
    else:
        verdict="EXTERNAL_NATIVE_OBJECT_SCOPE_SUPPORTED"
    if not revocation_denied:
        verdict="EXTERNAL_KEY_REVOCATION_BYPASS"
    return {
        "schema":"risu-b27-independent-publisher-native-s3-audit-v1",
        "audit_status":"PASS",
        "verdict":verdict,
        "real_external_binary_version":data["original_binary_version"],
        "native_issuer_exact_policy":native_exact,
        "native_issuer_coarse_control_policy":native_coarse,
        "native_actor_key_revoked":True,
        "native_exact_key_write_allowed":exact_allowed,
        "direct_scope_bypass_cases":out_of_scope,
        "cross_object_list_exposed":list_exposed,
        "native_content_binding":("UNSUPPORTED_BY_NATIVE_PUT_OBJECT"
             if exact_allowed and byname["approved_object_wrong_value"]==200
             else "NOT_PROVEN"),
        "native_one_time_consumption":("NOT_ENFORCED"
             if exact_allowed and byname["approved_object_replay"]==200
             else "NOT_PROVEN"),
        "revocation_after_usable_key_verified":exact_allowed and revocation_denied,
        "actual_original_object_sha256":fresh,
        "actual_outcome_count":len(requested),
        "external_third_party_human_owner":False,
        "independent_audit_imports_risu_or_harness":False,
    }
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--observation",required=True)
    p.add_argument("--out",required=True)
    args=p.parse_args()
    result=json.loads(Path(args.observation).read_text())
    verified=audit(result)
    Path(args.out).write_text(json.dumps(verified,indent=2,sort_keys=True)+"\n")
    print("B27_SEAWEEDFS_INDEPENDENT_ORIGINAL_S3_IAM_EFFECT_AUDIT_PASS",verified["verdict"])
if __name__=="__main__":main()
