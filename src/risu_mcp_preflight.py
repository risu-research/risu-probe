"""RISU P6-B22: fail-closed pre-execution MCP grant enforcement for a sandboxed file writer.

The verifier is a separate unprivileged OS user; the grant is signed by a
different OS account that owns the targeted resource directory. Unlike B21,
a denied call is NOT forwarded to the original MCP server.

This bounded first implementation deliberately only supports the source
unmodified 'write_file' tool with text, append=false, a *direct child* path
of a signed fixture-owned directory and a pinned upstream wheel.

CAUTION: This gateway protects the INVOCATION it forwards. Unmodified server
code may still contain unobserved actions, race windows or non-file effects.
Production ownership, user authentication, OAuth and isolation are not
proven by a synthetic CI OS account.
"""
from __future__ import annotations
import argparse
import asyncio
import base64
from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import zipfile

ROOT_SCHEMA="risu-b22-os-owner-root-v1"
GRANT_SCHEMA="risu-b22-precall-owner-grant-v1"
REV_SCHEMA="risu-b22-owner-revocation-v1"
PREFIX=b"RISU-B22-OS-OWNER-PRECALL-V1\x00"
REV_PREFIX=b"RISU-B22-OS-OWNER-REVOCATION-V1\x00"
HEXDIGEST=re.compile(r"[0-9a-f]{64}\Z")
MAX_TEXT=4096


class Refused(Exception):
    def __init__(self,code):
        self.code=code
        super().__init__(code)


def demand(ok,why):
    if not ok:raise Refused(why)


def canonical(x):
    return json.dumps(x,sort_keys=True,separators=(",",":"),
                      ensure_ascii=False,allow_nan=False).encode("utf-8")


def digest(x):return hashlib.sha256(x).hexdigest()


def read_document(path,limit=131072):
    path=Path(path)
    demand(path.is_file() and not path.is_symlink() and
           0<path.stat().st_size<=limit,"MISSING_OR_UNSAFE_AUTHORITY_DOCUMENT")
    try:
        def pairs(seq):
            out={}
            for k,v in seq:
                if k in out:raise ValueError("duplicate JSON key")
                out[k]=v
            return out
        return json.loads(path.read_text("utf-8"),object_pairs_hook=pairs)
    except (ValueError,UnicodeError,OSError,RecursionError):
        raise Refused("UNREADABLE_OR_AMBIGUOUS_AUTHORITY_DOCUMENT")


def utc(raw):
    demand(type(raw) is str and raw.endswith("Z") and len(raw)<=32,
           "UNTRUSTED_TIME")
    try:val=datetime.fromisoformat(raw.replace("Z","+00:00"))
    except ValueError:raise Refused("UNTRUSTED_TIME")
    return val


def b64(raw,size):
    demand(type(raw) is str and len(raw)<200,"MALFORMED_SIGNED_DATA")
    try:v=base64.b64decode(raw,validate=True)
    except Exception:raise Refused("MALFORMED_SIGNED_DATA")
    demand(len(v)==size,"MALFORMED_SIGNED_DATA")
    return v


def signature(body,encoded,public,prefix):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    try:
        Ed25519PublicKey.from_public_bytes(b64(public,32)).verify(
            b64(encoded,64),prefix+canonical(body))
    except (InvalidSignature,ValueError):
        raise Refused("INVALID_OWNER_CRYPTOGRAPHIC_SIGNATURE")


def file_state(target):
    try:
        s=os.lstat(target)
    except FileNotFoundError:return {"exists":False,"sha256":None,"bytes":0}
    demand(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size<=MAX_TEXT,
           "UNSAFE_NONREGULAR_OR_OVERSIZED_TARGET")
    with open(target,"rb") as f:raw=f.read(MAX_TEXT+1)
    demand(len(raw)<=MAX_TEXT,"UNSAFE_OVERSIZED_TARGET")
    return {"exists":True,"sha256":digest(raw),"bytes":len(raw)}


def safe_directory(raw,owner_uid,executor_uid):
    demand(type(raw) is str and raw.startswith("/") and
           not any(p in (".","..") for p in Path(raw).parts) and
           len(raw)<280,"UNSAFE_OWNER_RESOURCE_DIRECTORY")
    p=Path(raw)
    demand(p.is_dir() and not p.is_symlink(),"UNSAFE_OWNER_RESOURCE_DIRECTORY")
    fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        st=os.fstat(fd)
        demand(stat.S_ISDIR(st.st_mode) and
               st.st_uid==owner_uid and st.st_uid!=executor_uid,
               "RESOURCE_DIRECTORY_NOT_OWNED_BY_DISTINCT_PRINCIPAL")
        demand((st.st_mode&stat.S_IWOTH)==0,
               "WORLD_WRITABLE_RESOURCE_DIRECTORY")
    finally:os.close(fd)
    demand(p.resolve()==p,"OWNER_RESOURCE_DIRECTORY_PATH_ALIASED")
    return p


def trust_owner(trust_path,sha_pin):
    demand(type(sha_pin) is str and HEXDIGEST.fullmatch(sha_pin),
           "MISSING_EXTERNALLY_PINNED_OWNER_TRUST_ROOT")
    root=read_document(trust_path)
    demand(digest(Path(trust_path).read_bytes())==sha_pin,
           "OWNER_TRUST_ROOT_SHA_NOT_PINNED")
    demand(type(root) is dict and set(root)=={
       "schema","issuer","owner_uid","executor_uid","resource_dir",
       "resource_id","key_id","ed25519_public_key_b64",
       "approved_tool","server_module","wheel_sha256","trust_level"},
       "UNEXPECTED_TRUST_ROOT_FIELDS")
    demand(root["schema"]==ROOT_SCHEMA and
           root["trust_level"]=="OS_UID_ISOLATED_FIXTURE_ONLY" and
           root["approved_tool"]=="write_file" and
           root["server_module"]=="filesystem_mcp",
           "UNRECOGNIZED_OWNER_TRUST_PROFILE")
    demand(type(root["owner_uid"]) is int and
           type(root["executor_uid"]) is int and
           root["owner_uid"]!=root["executor_uid"] and
           root["executor_uid"]==os.geteuid(),
           "WRONG_EFFECTIVE_EXECUTOR_OS_IDENTITY")
    demand(type(root["resource_id"]) is str and
           root["resource_id"].startswith("urn:risu-b22:fixture:") and
           len(root["resource_id"])<=160,
           "UNVERIFIABLE_RESOURCE_ID")
    public=b64(root["ed25519_public_key_b64"],32)
    demand(root["key_id"]==digest(public),"WRONG_TRUSTED_OWNER_KEY_ID")
    demand(type(root["wheel_sha256"]) is str and
           HEXDIGEST.fullmatch(root["wheel_sha256"]),
           "MALFORMED_TRUSTED_ORIGINAL_ARTIFACT")
    safe_directory(root["resource_dir"],root["owner_uid"],os.geteuid())
    return root


def revoke_verify(path,sha_pin,root,now):
    demand(type(sha_pin) is str and HEXDIGEST.fullmatch(sha_pin),
           "NO_EXTERNALLY_PINNED_REVOCATION_EPOCH")
    record=read_document(path)
    demand(digest(Path(path).read_bytes())==sha_pin,
           "REVOCATION_LIST_NOT_PINNED")
    demand(type(record) is dict and set(record)=={
       "schema","revocations","signature_ed25519_b64"} and
       record["schema"]==REV_SCHEMA,
       "MALFORMED_OWNER_REVOCATION_RECORD")
    body=record["revocations"]
    demand(type(body) is dict and set(body)=={
       "issuer","key_id","published_at","revoked_nonces","sequence"},
       "UNVERIFIABLE_REVOCATION_BODY")
    demand(body["issuer"]==root["issuer"] and
           body["key_id"]==root["key_id"] and
           type(body["sequence"]) is int and body["sequence"]>=0,
           "WRONG_SIGNED_REVOCATION_ISSUER")
    revoked=body["revoked_nonces"]
    demand(type(revoked) is list and len(revoked)<=256 and
           all(type(x) is str and HEXDIGEST.fullmatch(x) for x in revoked)
           and len(set(revoked))==len(revoked),
           "INVALID_SIGNED_REVOKED_NONCES")
    demand(utc(body["published_at"])<=now+timedelta(seconds=2) and
           now-utc(body["published_at"])<=timedelta(minutes=15),
           "REVOCATION_EPOCH_TOO_OLD")
    signature(body,record["signature_ed25519_b64"],
              root["ed25519_public_key_b64"],REV_PREFIX)
    return set(revoked)


def verify_preflight(request_path,grant_path,trust_path,trust_sha,
                     rev_path,rev_sha,wheel_path,ledger_dir,actor):
    demand(os.name=="posix","UNSUPPORTED_HOST_OS")
    now=datetime.now(timezone.utc)
    root=trust_owner(trust_path,trust_sha)
    demand(actor==root["executor_uid"],"ACTOR_NOT_THE_OS_EXECUTOR")
    wheel=Path(wheel_path)
    demand(wheel.is_file() and wheel.stat().st_size<=2000000 and
           digest(wheel.read_bytes())==root["wheel_sha256"],
           "WRONG_PUBLISHED_ORIGINAL_SOFTWARE")
    revoked=revoke_verify(rev_path,rev_sha,root,now)
    request=read_document(request_path)
    demand(type(request) is dict and request.get("jsonrpc")=="2.0" and
           request.get("method")=="tools/call" and
           type(request.get("id")) is int and
           set(request)=={"jsonrpc","id","method","params"},
           "NOT_A_SINGLE_ORIGINAL_MCP_TOOL_CALL")
    params=request["params"]
    demand(type(params) is dict and set(params)=={"name","arguments"} and
           params["name"]==root["approved_tool"],
           "UNAPPROVED_ACTUAL_MCP_TOOL")
    args=params["arguments"]
    demand(type(args) is dict and set(args)=={"path","content","append"} and
           args["append"] is False and
           type(args["content"]) is str and
           0<len(args["content"].encode("utf-8"))<=MAX_TEXT,
           "UNBOUNDED_OR_UNSUPPORTED_MCP_ARGUMENTS")
    target=Path(args["path"])
    directory=Path(root["resource_dir"])
    demand(target.is_absolute() and len(str(target))<360 and
           target.parent==directory and
           target.name not in ("",".","..") and
           str(target)==str(directory/target.name),
           "UNAUTHORIZED_OUTSIDE_RESOURCE_PATH")
    demand(os.access(directory,os.W_OK|os.X_OK),
           "EXECUTOR_LACKS_REAL_OS_DAC_PERMISSION")
    initial=file_state(target)
    if initial["exists"]:
        demand(os.access(target,os.W_OK),
               "EXECUTOR_LACKS_REAL_TARGET_FILE_DAC_PERMISSION")
    grant=read_document(grant_path)
    demand(type(grant) is dict and set(grant)=={
        "schema","policy","signature_ed25519_b64"} and
        grant["schema"]==GRANT_SCHEMA,"MISSING_PREISSUED_OWNER_GRANT")
    policy=grant["policy"]
    demand(type(policy) is dict and set(policy)=={
      "audience","issuer","owner_uid","executor_uid",
      "resource_id","resource_dir","target_path","request_sha256",
      "original_tool","server_module","wheel_sha256","nonce",
      "issued_at","expires_at","pre_state_sha256",
      "allowed_operation","desired_post_sha256"},
      "INVALID_SIGNED_OWNER_GRANT_FIELDS")
    signature(policy,grant["signature_ed25519_b64"],
              root["ed25519_public_key_b64"],PREFIX)
    demand(policy["audience"]=="risu-b22-unmodified-mcp-gateway" and
           policy["issuer"]==root["issuer"] and
           policy["owner_uid"]==root["owner_uid"] and
           policy["executor_uid"]==root["executor_uid"] and
           policy["resource_id"]==root["resource_id"] and
           policy["resource_dir"]==root["resource_dir"] and
           policy["target_path"]==str(target) and
           policy["request_sha256"]==digest(canonical(request)) and
           policy["original_tool"]==root["approved_tool"] and
           policy["server_module"]==root["server_module"] and
           policy["wheel_sha256"]==root["wheel_sha256"],
           "SCOPE_NOT_BOUND_TO_ACTUAL_RESOURCE_ACTOR_AND_REQUEST")
    nonce=policy["nonce"]
    demand(type(nonce) is str and HEXDIGEST.fullmatch(nonce),
           "INVALID_GRANT_NONCE")
    demand(nonce not in revoked,"OWNER_REVOKED_THIS_GRANT")
    issued=utc(policy["issued_at"])
    expires=utc(policy["expires_at"])
    demand(issued<=now<=expires and
           expires-issued<=timedelta(minutes=10),
           "EXPIRED_OR_FUTURE_DATED_PERMISSION")
    expected_pre=policy["pre_state_sha256"]
    demand(expected_pre is None or
           (type(expected_pre) is str and HEXDIGEST.fullmatch(expected_pre)),
           "INVALID_PRECALL_STATE_CONSTRAINT")
    demand(expected_pre==initial["sha256"],
           "STALE_PRECALL_TARGET_STATE")
    desired=digest(args["content"].encode("utf-8"))
    demand(policy["desired_post_sha256"]==desired,
           "DESIRED_CONTENT_NOT_IN_SIGNED_SCOPE")
    intended=("CREATE" if not initial["exists"] else
              "NO_CHANGE" if initial["sha256"]==desired else "REPLACE")
    demand(policy["allowed_operation"]==intended,
           "REQUESTED_DIRECTION_NOT_APPROVED_BY_OWNER")
    led=Path(ledger_dir)
    demand(led.is_dir() and not led.is_symlink(),"MISSING_DURABLE_LEDGER")
    st=os.stat(led,follow_symlinks=False)
    demand(st.st_uid==os.geteuid() and (st.st_mode&0o077)==0,
           "REPLAY_LEDGER_NOT_PRIVATE_TO_EXECUTOR")
    # Atomic O_EXCL is the reservation point. A crashed process consumes
    # the nonce: fail closed rather than execute twice.
    fd=os.open(led/nonce,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        payload=canonical({"request_sha256":digest(canonical(request)),
                           "owner_issuer":root["issuer"],
                           "nonce":nonce,
                           "preflight_decision":"AUTHORIZED",
                           "original_mcp_server_not_yet_started":True})
        os.write(fd,payload)
        os.fsync(fd)
    finally:os.close(fd)
    return {"request":request,"root":root,"policy":policy,
            "pre_state":initial,"predicted_direction":intended,
            "grant_sha256":digest(Path(grant_path).read_bytes()),
            "request_sha256":digest(canonical(request)),
            "nonce":nonce}


async def run_original(check,server_python):
    # This function is called ONLY after verify_preflight succeeds and
    # reserves the unique signed nonce. No stdio MCP server is launched
    # in refusal branches.
    policy=check["policy"]
    root=check["root"]
    target=Path(policy["target_path"])
    demand(Path(server_python).is_file(),"MISSING_PINNED_ORIGINAL_SERVER_RUNTIME")
    env={"PATH":"/usr/bin:/bin","HOME":"/tmp","TMPDIR":"/tmp",
         "LANG":"C.UTF-8","LC_ALL":"C.UTF-8",
         "PYTHONDONTWRITEBYTECODE":"1","PYTHONNOUSERSITE":"1",
         "NO_COLOR":"1","CI":"true"}
    process=await asyncio.create_subprocess_exec(
        str(server_python),"-I","-m",root["server_module"],root["resource_dir"],
        cwd=root["resource_dir"],env=env,
        stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,limit=524290)
    wire=[]
    async def exchange(msg):
        raw=canonical(msg)+b"\n"
        process.stdin.write(raw)
        await asyncio.wait_for(process.stdin.drain(),12)
        wire.append(raw)
        if "id" not in msg:return None
        for _ in range(20):
            line=await asyncio.wait_for(process.stdout.readline(),35)
            if not line or not line.endswith(b"\n") or len(line)>524288:
                raise RuntimeError("Original MCP server returned no bounded protocol line")
            wire.append(line)
            value=json.loads(line)
            if type(value) is not dict or value.get("jsonrpc")!="2.0":
                raise RuntimeError("Original source emitted non-MCP response")
            if value.get("id")==msg["id"]:return value
            if "id" not in value:continue
            raise RuntimeError("Unexpected native server initiated call")
        raise RuntimeError("Unbounded native original server notifications")
    try:
        hello=await exchange({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
             "protocolVersion":"2025-11-25","capabilities":{},
             "clientInfo":{"name":"risu-b22-precall-owner-gateway","version":"1"}}})
        if type(hello.get("result")) is not dict:
            raise RuntimeError("Original MCP initialize failed")
        await exchange({"jsonrpc":"2.0","method":"notifications/initialized"})
        listing=await exchange({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})
        tools=listing.get("result",{}).get("tools",[])
        if not any(type(x) is dict and x.get("name")==check["request"]["params"]["name"]
                   for x in tools):
            raise RuntimeError("Original server does not advertise signed tool")
        response=await exchange(check["request"])
        if (type(response.get("result")) is not dict or
                response["result"].get("isError") is True or
                "error" in response):
            raise RuntimeError("Original MCP tool returned an error")
        after=file_state(target)
        desired=policy["desired_post_sha256"]
        if after["sha256"]!=desired:
            raise RuntimeError("Original server postcondition differs from signed allowed content")
        return {
           "server_started":True,"native_original_tool_calls":1,
           "original_mcp_process_pid":process.pid,
           "original_raw_jsonrpc_sha256":digest(b"".join(wire)),
           "original_raw_jsonrpc_b64":base64.b64encode(b"".join(wire)).decode(),
           "after_state":after,"postcondition_matched":True
        }
    finally:
        if process.returncode is None:
            process.terminate()
            try:await asyncio.wait_for(process.wait(),5)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()


def record(path,value):
    path=Path(path)
    with path.open("x",encoding="utf-8") as f:
        json.dump(value,f,sort_keys=True,indent=2)
        f.write("\n")


async def main_async(args):
    before={"schema":"risu-b22-precall-gate-result-v1",
            "gatekeeper_uid":os.geteuid() if hasattr(os,"geteuid") else None,
            "server_started":False,"native_original_tool_calls":0,
            "decision":"UNVERIFIED","reason":"INCOMPLETE"}
    # The outer evidence report is deliberately a separate, new file.
    # Refusal returns without ever invoking run_original.
    try:
        pre=verify_preflight(args.request,args.grant,args.trust_root,
            args.trusted_root_sha256,args.revocations,
            args.revocations_sha256,args.original_wheel,args.ledger,
            os.geteuid())
        before.update({"decision":"AUTHORIZED_PRECALL","reason":"VALID_OWNER_GRANT",
          "owner_uid":pre["root"]["owner_uid"],
          "owner_key_id":pre["root"]["key_id"],
          "resource_id":pre["root"]["resource_id"],
          "request_sha256":pre["request_sha256"],
          "signed_grant_sha256":pre["grant_sha256"],
          "consumed_nonce_sha256":digest(pre["nonce"].encode()),
          "preflight_predicted_direction":pre["predicted_direction"],
          "pre_state":pre["pre_state"]})
    except (Refused,FileExistsError,PermissionError,FileNotFoundError,
            IsADirectoryError,ValueError,TypeError,KeyError,OSError) as exc:
        before.update({"decision":"DENIED_BEFORE_SERVER_SPAWN",
                       "reason":exc.code if isinstance(exc,Refused) else
                         "REPLAY_OR_UNREADABLE_LOCAL_OS_RESOURCE"})
        record(args.out,before)
        print("B22_GATE_DENIED_BEFORE_MCP_PROCESS",before["reason"])
        return 3
    try:
        outcome=await run_original(pre,args.server_python)
        before.update(outcome)
        before.update({"decision":"AUTHORIZED_EXECUTED_AND_POSTCONDITION_MATCHED",
                       "reason":"SOURCE_NATIVE_WRITE_WITHIN_OWNER_SIGNED_SCOPE"})
        record(args.out,before)
        print("B22_ORIGINAL_MCP_PRECALL_AUTHORIZED_EXECUTED",before["preflight_predicted_direction"])
        return 0
    except Exception as exc:
        before.update({"decision":"AUTHORIZED_BUT_EXECUTION_OR_POSTCONDITION_FAILED",
            "reason":type(exc).__name__,
            "server_started":True})
        record(args.out,before)
        return 4


def cli(argv=None):
    p=argparse.ArgumentParser(prog="risu-probe enforce-mcp-preflight")
    for name in ("request","grant","trust-root","trusted-root-sha256",
                 "revocations","revocations-sha256","original-wheel",
                 "ledger","server-python","out"):
        p.add_argument("--"+name,required=True)
    return asyncio.run(main_async(p.parse_args(argv)))


if __name__=="__main__":
    raise SystemExit(cli())
