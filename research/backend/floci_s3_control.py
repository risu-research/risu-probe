#!/usr/bin/env python3
"""Independent S3-compatible backend control; records exact wire-level effects."""
import concurrent.futures
import hashlib
import json
import os
import sys
import time
import boto3
from botocore.client import Config
from botocore.exceptions import ClientError

endpoint=os.environ.get("S3_TEST_ENDPOINT","http://127.0.0.1:4566")
client=boto3.client("s3",region_name="us-east-1",endpoint_url=endpoint,
 aws_access_key_id="test",aws_secret_access_key="test",
 config=Config(s3={"addressing_style":"path"},retries={"max_attempts":0}))
bucket="risu-condition-2026"
rows=[]
def invoke(name,method,expect_status=None,**kw):
 try:
  ans=getattr(client,method)(Bucket=bucket,**kw)
  status=ans.get("ResponseMetadata",{}).get("HTTPStatusCode",200)
  err=None
  result=ans
 except ClientError as exc:
  status=exc.response["ResponseMetadata"]["HTTPStatusCode"]
  err=exc.response.get("Error",{}).get("Code")
  result=None
  ans={}
 item={"case":name,"status":status,"error":err,
  "expect":expect_status,"pass":status==expect_status if expect_status is not None else None}
 rows.append(item)
 print("RISU_CONTROL",json.dumps(item,sort_keys=True),flush=True)
 return result,status
def read_body(key):
 try:
  x=client.get_object(Bucket=bucket,Key=key)
  return x["Body"].read().decode(),200
 except ClientError as e:
  return None,e.response["ResponseMetadata"]["HTTPStatusCode"]
for attempt in range(25):
 try:
  client.create_bucket(Bucket=bucket)
  break
 except Exception as e:
  if attempt==24:raise
  time.sleep(.6)
# Same correctness controls used on the Overcast pre/post historical implementations.
invoke("ordinary-first","put_object",200,Key="ordinary",Body=b"A")
invoke("ordinary-second","put_object",200,Key="ordinary",Body=b"B")
r={"case":"ordinary-body","body":read_body("ordinary")[0],"expect":"B"}
r["pass"]=r["body"]=="B";rows.append(r)
invoke("none-absent","put_object",200,Key="new",Body=b"first",IfNoneMatch="*")
invoke("initial-protected","put_object",200,Key="protected",Body=b"before")
invoke("none-existing","put_object",412,Key="protected",Body=b"bad",IfNoneMatch="*")
r={"case":"none-existing-body","body":read_body("protected")[0],"expect":"before"}
r["pass"]=r["body"]=="before";rows.append(r)
p,_=invoke("match-initial","put_object",200,Key="match",Body=b"before")
if p is not None:
 invoke("match-current","put_object",200,Key="match",Body=b"good",IfMatch=p["ETag"])
p,_=invoke("stale-initial","put_object",200,Key="stale",Body=b"one")
if p is not None:
 etag=p["ETag"]
 invoke("stale-mutator","put_object",200,Key="stale",Body=b"two")
 invoke("match-stale","put_object",412,Key="stale",Body=b"bad",IfMatch=etag)
 r={"case":"match-stale-body","body":read_body("stale")[0],"expect":"two"}
 r["pass"]=r["body"]=="two";rows.append(r)
invoke("match-missing","put_object",404,Key="missing",Body=b"bad",IfMatch='"00000000000000000000000000000000"')
# Holdout operation-family check: CopyObject destination preconditions (AWS Oct. 2025).
invoke("copy-source-initial","put_object",200,Key="copy-source",Body=b"source")
invoke("copy-dest-initial","put_object",200,Key="copy-dest",Body=b"preserved")
invoke("copy-none-existing","copy_object",412,Key="copy-dest",
       CopySource={"Bucket":bucket,"Key":"copy-source"},IfNoneMatch="*")
r={"case":"copy-none-existing-body","body":read_body("copy-dest")[0],"expect":"preserved"}
r["pass"]=r["body"]=="preserved";rows.append(r)
invoke("copy-stale-initial","put_object",200,Key="copy-stale",Body=b"preserved")
invoke("copy-match-stale","copy_object",412,Key="copy-stale",
       CopySource={"Bucket":bucket,"Key":"copy-source"},IfMatch='"00000000000000000000000000000000"')
r={"case":"copy-match-stale-body","body":read_body("copy-stale")[0],"expect":"preserved"}
r["pass"]=r["body"]=="preserved";rows.append(r)
def contender(i):
 try:
  r=client.put_object(Bucket=bucket,Key="race",Body=("writer-%02d"%i).encode(),IfNoneMatch="*")
  return r.get("ResponseMetadata",{}).get("HTTPStatusCode",200)
 except ClientError as e:
  return e.response["ResponseMetadata"]["HTTPStatusCode"]
with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
 statuses=list(pool.map(contender,range(12)))
race={"case":"concurrent-first-writer","wins":statuses.count(200),"rejects":statuses.count(412),
      "other_statuses":sorted(set(statuses)-{200,412}),"total":12}
race["pass"]=race["wins"]==1 and race["rejects"]==11 and not race["other_statuses"]
rows.append(race)
print("RISU_CONTROL_RACE",json.dumps(race,sort_keys=True))
result={"backend":"floci","version":"2.0.1","endpoint":"127.0.0.1:4566",
        "cases":rows,"all_pass":all(x.get("pass") is True for x in rows),
        "boto3_version":boto3.__version__}
out=os.environ.get("S3_CONTROL_OUTPUT","control-results.json")
with open(out,"w") as f:json.dump(result,f,indent=2)
print("RISU_CONTROL_SUMMARY",json.dumps({"all_pass":result["all_pass"],
  "cases":len(rows),"fails":[r["case"] for r in rows if not r.get("pass")]}),flush=True)
# Keep partial/negative controls as data, rather than hiding any mismatch.
sys.exit(0)
