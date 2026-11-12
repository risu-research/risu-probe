#!/usr/bin/env python3
"""Probe HTTP/1.1 persistent-connection aftermath of failed S3 conditional writes.

This intentionally bypasses boto3 and SigV4 to distinguish object-state correctness
from transport framing. Never write to public networks: bound to localhost only.
"""
import http.client, json, os, time
from urllib.parse import urlparse

endpoint=os.environ.get("S3_TEST_ENDPOINT","http://127.0.0.1:4566")
host=urlparse(endpoint).hostname
port=urlparse(endpoint).port
if host not in ("localhost","127.0.0.1","::1"): raise ValueError("local-only control")
version=os.environ.get("S3_BACKEND_VERSION","unknown")
results=[]

def conn():
    return http.client.HTTPConnection(host,port,timeout=5)
def perform(c,method,path,body=None,headers=None):
    data=body if body is not None else b""
    heads={"Content-Type":"application/octet-stream",**(headers or {})}
    c.request(method,path,body=data if method=="PUT" else None,headers=heads)
    r=c.getresponse()
    b=r.read()
    return {"status":r.status,"body":b.decode("utf-8","replace")[:350],
            "will_close":bool(r.will_close), "connection_header":r.getheader("Connection")}
def run_case(name,failed_method="none",rejected_body=b"blocked",close=False):
    key=f"risu-{name}.txt"
    c=conn()
    first=perform(c,"PUT",f"/risu-wire-test/{key}",b"original")
    cond={"If-None-Match":"*"} if failed_method=="none" else {"If-Match":'"00000000000000000000000000000000"'}
    if close: cond["Connection"]="close"
    denied=perform(c,"PUT",f"/risu-wire-test/{key}",rejected_body,cond)
    try:
        same=perform(c,"GET",f"/risu-wire-test/{key}")
    except Exception as err:
        same={"exception":type(err).__name__,"detail":str(err)[:200]}
    try:c.close()
    except Exception:pass
    f=conn()
    try:fresh=perform(f,"GET",f"/risu-wire-test/{key}")
    except Exception as err:fresh={"exception":type(err).__name__,"detail":str(err)[:200]}
    finally:f.close()
    record={"case":name,"first":first,"denied":denied,
            "same_connection_after":same,"new_connection_after":fresh}
    results.append(record)
    print("RISU_HTTP11_CASE",json.dumps(record,sort_keys=True),flush=True)

for attempt in range(30):
    try:
        c=conn()
        bucket=perform(c,"PUT","/risu-wire-test")
        c.close()
        print("RISU_HTTP11_BUCKET",json.dumps(bucket),flush=True)
        if bucket["status"] not in (200,201,204):raise RuntimeError(bucket)
        break
    except Exception:
        if attempt==29:raise
        time.sleep(.5)
run_case("none-nonempty",rejected_body=b"blocked-payload")
run_case("none-zero",rejected_body=b"")
run_case("none-close",rejected_body=b"blocked-payload",close=True)
run_case("match-nonempty",failed_method="match",rejected_body=b"blocked-payload")
run_case("match-zero",failed_method="match",rejected_body=b"")
summary={"backend":"floci","version":version,"results":results}
with open(os.environ.get("HTTP11_CONTROL_OUTPUT","http11.json"),"w") as out:json.dump(summary,out,indent=2)
print("RISU_HTTP11_SUMMARY",json.dumps({"cases":len(results),"version":version}),flush=True)
