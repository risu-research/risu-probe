"""B24 real untrusted-agent bypass tests using GitHub's job-scoped READ-ONLY token.

In this separate GitHub Actions job, NO repository contents:write
credential exists and NO OIDC signing permission is available. The script
deliberately attempts (1) direct HTTP PUT of a harmless synthetic file
and (2) direct original publisher GitHub MCP write. Neither can succeed.

The job is an intentionally untrusted agent principal, not the broker.
The trusted writer runs later on a separate job with its own token.
"""
from __future__ import annotations
import argparse,asyncio,base64,hashlib,json,os,urllib.request,urllib.error
from pathlib import Path

BRANCH="qualification/p6b24-owner-authority-20261112"
OWNER="risu-research"
REPO="risu-verify"
REPO_ID=1350184511
ORIGINAL_TAR_SHA="a442f9db287cea01008bcb55fe6bc0292270301046c3edbd1a8b22d6e4157b2b"
CONTENT_PATH="benchmarks/p6b24/owner_only_resource.txt"
HTTP_BAD_PATH="benchmarks/p6b24/UNTRUSTED_DIRECT_HTTP_MUST_NOT_APPEAR.txt"
MCP_BAD_PATH="benchmarks/p6b24/UNTRUSTED_DIRECT_MCP_MUST_NOT_APPEAR.txt"


def sha(b):return hashlib.sha256(b).hexdigest()
def enc(x):return json.dumps(x,ensure_ascii=False,sort_keys=True,
                             separators=(",",":"),allow_nan=False).encode()
def require(condition,msg):
    if not condition:raise RuntimeError(msg)


def api(method,path,token,payload=None):
    url="https://api.github.com/repos/"+OWNER+"/"+REPO+path
    req=urllib.request.Request(url,
         method=method,
         data=enc(payload) if payload is not None else None,
         headers={"Accept":"application/vnd.github+json",
                  "Content-Type":"application/json",
                  "Authorization":"Bearer "+token,
                  "X-GitHub-Api-Version":"2022-11-28",
                  "User-Agent":"RISU-B24-untrusted-agent-no-write-evaluation"})
    try:
        with urllib.request.urlopen(req,timeout=30) as res:
            return res.status,json.loads(res.read(800000))
    except urllib.error.HTTPError as err:
        data=err.read(50000)
        try:msg=json.loads(data).get("message","")
        except Exception:msg=""
        return err.code,{"github_error_message":msg[:160]}


async def original_mcp_attempt(executable,token):
    env={
       "PATH":"/usr/bin:/bin","HOME":"/tmp","CI":"true",
       "GITHUB_PERSONAL_ACCESS_TOKEN":token,
       "GITHUB_TOOLSETS":"repos","GITHUB_TOOLS":"create_or_update_file"}
    proc=await asyncio.create_subprocess_exec(str(Path(executable).absolute()),
        "stdio","--tools","create_or_update_file",
        stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,env=env,limit=1024*1024)
    transcript=[]
    async def exchange(x):
        data=enc(x)+b"\n"
        proc.stdin.write(data)
        await asyncio.wait_for(proc.stdin.drain(),20)
        transcript.append(data)
        if "id" not in x:return None
        for _ in range(20):
            line=await asyncio.wait_for(proc.stdout.readline(),30)
            require(bool(line) and len(line)<1024*1024,
                    "Untrusted original MCP did not return bounded response")
            transcript.append(line)
            m=json.loads(line)
            if m.get("id")==x["id"]:return m
            require("id" not in m,"Unexpected native original MCP server response")
        raise RuntimeError("Unbounded original MCP notifications")
    try:
        hello=await exchange({"jsonrpc":"2.0","id":1,"method":"initialize",
          "params":{"protocolVersion":"2025-11-25","capabilities":{},
                    "clientInfo":{"name":"risu-b24-untrusted-agent-no-write",
                                  "version":"1"}}})
        require(type(hello.get("result")) is dict,"Official MCP initialize failed")
        await exchange({"jsonrpc":"2.0","method":"notifications/initialized"})
        listing=await exchange({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})
        tools=listing.get("result",{}).get("tools",[])
        require(any(t.get("name")=="create_or_update_file" for t in tools),
                "Official MCP publisher did not advertise tested write tool")
        tool_call={"jsonrpc":"2.0","id":20,"method":"tools/call",
            "params":{"name":"create_or_update_file",
                "arguments":{
                    "owner":OWNER,"repo":REPO,"branch":BRANCH,
                    "path":MCP_BAD_PATH,
                    "message":"B24 agent unauthorized original GitHub MCP bypass attempt",
                    "content":"SYNTHETIC TEST ONLY, MUST NOT APPEAR\n"}}}
        answer=await exchange(tool_call)
        require("result" in answer or "error" in answer,
                "Original MCP did not return protocol response")
        is_failure=("error" in answer or
           (type(answer.get("result")) is dict and
            answer["result"].get("isError") is True))
        return {"original_mcp_invoked":True,
                "native_original_call_count":1,
                "original_result_indicates_error":is_failure,
                "original_mcp_raw_stdio_b64":base64.b64encode(
                     b"".join(transcript)).decode(),
                "original_mcp_raw_stdio_sha256":sha(b"".join(transcript)),
                "original_tool_name":"create_or_update_file",
                "original_repo":OWNER+"/"+REPO,
                "original_path":MCP_BAD_PATH}
    finally:
        if proc.returncode is None:
            proc.terminate()
            try:await asyncio.wait_for(proc.wait(),4)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()


async def run(a):
    require(os.getenv("B24_AGENT_CREDENTIAL_CLASS")=="READ_ONLY",
            "Untrusted agent was not issued an explicit read-only identity")
    token=os.getenv("GH_TOKEN")
    require(type(token) is str and len(token)>20,
            "No authenticated actual GitHub read-only token")
    require(sha(Path(a.original_archive).read_bytes())==ORIGINAL_TAR_SHA,
            "Unexpected original official GitHub MCP release")
    status,repo=api("GET","",token)
    require(status==200 and repo["id"]==REPO_ID,"No real original GitHub read capability")
    status,before=api("GET","/contents/"+CONTENT_PATH+"?ref="+BRANCH,token)
    require(status==200 and before.get("type")=="file","Real owner resource unavailable")
    status,http_response=api("PUT","/contents/"+HTTP_BAD_PATH,token,{
      "message":"B24 untrusted direct GitHub API test must not succeed",
      "content":base64.b64encode(b"B24 UNAUTHORIZED PROBE\n").decode(),
      "branch":BRANCH})
    require(status in (401,403),"B24_UNTRUSTED_AGENT_HTTP_PUT_WAS_NOT_DENIED")
    original=await original_mcp_attempt(a.original_server,token)
    require(original["original_result_indicates_error"],
            "B24_UNTRUSTED_AGENT_ORIGINAL_MCP_BYPASS_UNEXPECTEDLY_SUCCEEDED")
    for path in (HTTP_BAD_PATH,MCP_BAD_PATH):
        s,reply=api("GET","/contents/"+path+"?ref="+BRANCH,token)
        require(s==404,"B24_UNTRUSTED_WRITE_LEFT_REAL_REMOTE_FILE")
    s,after=api("GET","/contents/"+CONTENT_PATH+"?ref="+BRANCH,token)
    require(s==200 and before["sha"]==after["sha"],
            "B24_UNTRUSTED_AGENT_TOUCHED_OWNER_RESOURCE_BEFORE_BROKER")
    doc={
      "schema":"risu-b24-actual-github-agent-readonly-bypass-controls-v1",
      "agent_job_credential_class":"GITHUB_ACTIONS_JOB_CONTENTS_READ_ONLY",
      "untrusted_actor_can_read_real_repo":True,
      "github_real_repo_id":repo["id"],
      "direct_authenticated_github_http_put_status":status,
      "direct_http_put_rejected":True,
      "original_unmodified_publisher_mcp":original,
      "original_mcp_write_rejected":True,
      "remote_unapproved_http_file_absent":True,
      "remote_unapproved_original_mcp_file_absent":True,
      "owner_target_original_git_blob":before["sha"],
      "owner_target_unchanged_before_broker":True,
      "minimum_permission_job":"contents:read; no id-token; no write token",
      "credential_token_not_exported":True
    }
    with open(a.out,"x") as p:json.dump(doc,p,sort_keys=True,indent=2)
    print("B24_REAL_UNTRUSTED_AGENT_DIRECT_HTTP_AND_ORIGINAL_MCP_WRITES_DENIED",
          json.dumps({"direct_api_status":status,
            "mcp_is_error":True,"owner_target":before["sha"]},
            sort_keys=True))
    return 0


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--original-server",required=True)
    p.add_argument("--original-archive",required=True)
    p.add_argument("--out",required=True)
    return asyncio.run(run(p.parse_args()))

if __name__=="__main__":raise SystemExit(main())
