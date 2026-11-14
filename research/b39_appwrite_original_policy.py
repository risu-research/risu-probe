#!/usr/bin/env python3
"""B39 deliberate Appwrite secret redaction with exact pinned ORIGINAL source.

Only the independent maintainer's redaction.py module runs. Appwrite server,
real account, secret, API, database and remote network are not executed. The
MCP peer is controlled, uses all-synthetic explicitly FAKE values.
"""
from __future__ import annotations
import asyncio
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from pydantic import BaseModel, Field
from b38_native_contract_auditor import audit_record

HERE=Path(__file__).resolve().parent
ROOT=HERE.parent
UPSTREAM=ROOT/"original"
FILE="src/mcp_server_appwrite/redaction.py"
COMMIT="96d0278df4a2c0917c894d2b25138235e3963488"
BLOB="4c35901707211c917c8850e03026efb3280ed611"
PEER=HERE/"b39_appwrite_fake_secret_stdio.py"
OUT=HERE/"out"
FAKE="FAKE_B39_PASSWORD_SAMPLE_NOT_REAL"

def must(flag,code):
    if not flag:raise RuntimeError("B39_APPWRITE_"+code)
def git(*args):
    q=subprocess.run(["git","-C",str(UPSTREAM),*args],
                     capture_output=True,text=True,timeout=40,check=False)
    must(q.returncode==0,"GIT_"+str(args[0]))
    return q.stdout.strip()
def sha(b):return hashlib.sha256(b).hexdigest()

def load_original():
    must(git("rev-parse","HEAD")==COMMIT,"PINNED_COMMIT_MISMATCH")
    must(git("rev-parse","HEAD:"+FILE)==BLOB,"PINNED_BLOB_MISMATCH")
    q=subprocess.run(["git","-C",str(UPSTREAM),"cat-file","blob",BLOB],
                     capture_output=True,timeout=40,check=False)
    must(q.returncode==0 and 100<len(q.stdout)<100_000,
         "ORIGINAL_SOURCE_BLOB_MISSING")
    original=OUT/"source"/"appwrite_original_redaction.py"
    original.parent.mkdir(parents=True,exist_ok=True)
    original.write_bytes(q.stdout)
    spec=importlib.util.spec_from_file_location("b39_appwrite_exact_original_module",original)
    must(spec is not None and spec.loader is not None,"PYTHON_ORIGINAL_IMPORT_SPEC")
    module=importlib.util.module_from_spec(spec)
    sys.modules[spec.name]=module
    spec.loader.exec_module(module)
    must(callable(module.redact_payload) and callable(module.redact),
         "ORIGINAL_APPWRITE_REDACTOR_NOT_AVAILABLE")
    return module,sha(q.stdout)

async def main():
    OUT.mkdir(exist_ok=True)
    module,source_sha=load_original()
    # Appwrite Console SDK's public model-field annotations are used by the
    # actual original source: no fabricated schema or monkeypatching.
    model_secrets=module._secret_names()
    must("secret" in model_secrets,
         "ORIGINAL_APPWRITE_SDK_DID_NOT_MARK_SECRET_FIELD")
    class FakeTypedVault(BaseModel):
        secret: str=Field(json_schema_extra={"format":"password"})
        title: str
    typed,typed_fields=module.redact(FakeTypedVault(secret=FAKE,title="Visible summary"))
    must(typed["secret"]=="[redacted]" and typed["title"]=="Visible summary"
         and "secret" in typed_fields
         and typed["secretFingerprint"]==module.fingerprint(FAKE),
         "TYPED_SECRET_REDACTION_POLICY_NOT_PRESERVED")
    wire=OUT/"B39_APPWRITE_ORIGINAL_NATIVE_STDIO.jsonl"
    params=StdioServerParameters(command=sys.executable,args=[str(PEER)],
        env={"B39_APPWRITE_WIRE":str(wire.resolve())})
    async with stdio_client(params) as (read,write):
        async with ClientSession(read,write) as cli:
            await asyncio.wait_for(cli.initialize(),timeout=18)
            result=await asyncio.wait_for(cli.call_tool("read_dummy",{}),timeout=18)
            must(not result.is_error and result.structured_content is not None,
                 "NORMAL_ORIGINAL_MCP_RESULT_NOT_AVAILABLE")
            payload=result.structured_content
            masked,fields=module.redact_payload(payload)
    must(masked["secret"]=="[redacted]"
         and masked["nested"]["secret"]=="[redacted]"
         and masked["blank"]["secret"]==""
         and masked["title"]=="Visible summary"
         and sorted(fields)==["secret"],
         "ORIGINAL_EXTERNAL_PAYLOAD_REDACTION_FAILED")
    must(masked["secretFingerprint"]==module.fingerprint(FAKE),
         "ORIGINAL_SECRET_FINGERPRINT_NOT_PRESERVED")
    must(FAKE not in json.dumps(masked),
         "FAKE_TEST_SECRET_LEAKED_IN_REDACTED_OUTPUT")
    raw=[json.loads(line) for line in wire.read_text(encoding="utf-8").splitlines()]
    call=[x for x in raw if x.get("request",{}).get("method")=="tools/call"]
    must(len(call)==1,"MCP_NATIVE_WIRE_MISSING")
    native=call[0]
    obs={"request_id":native["request"]["id"],"tool":"read_dummy","outcome":"success"}
    base={
       "wire":native,"observed":obs,
       "contract":{"status":True},
       "execution_provenance":"CONTROLLED_FIRST_PARTY",
    }
    scoped=audit_record(base)
    must(not scoped["findings"] and scoped["channels_tested"]==["status"],
         "STATUS_SCOPE_UNEXPECTED_WARNING")
    invalid=audit_record({**base,
       "contract":{"status":True,"structured":"exact"},
       "observed":{**obs,"structured":masked}})
    must(invalid["findings"]==["MCP_STRUCTURED_CONTENT_LOST_OR_CHANGED"],
         "INCORRECT_EXACT_POLICY_CHALLENGE_NOT_DETECTED")
    summary={
      "case":"N4",
      "upstream":"appwrite/mcp",
      "original_independent_redaction_module_executed":True,
      "original_complete_appwrite_server_executed":False,
      "original_external_client_executed":False,
      "actual_MCP_SDK_stdio_result_used":True,
      "no_real_credentials_or_secrets":True,
      "appwrite_original_SDK_format_password_annotations_used":True,
      "typed_model_fields_redacted":True,
      "nested_untyped_payload_fields_redacted":True,
      "blank_secret_left_blank":True,
      "normal_public_fields_retained":True,
      "intentional_redaction_not_an_information_loss_bug":True,
      "wrong_exact_contract_alarm_not_a_detector_false_positive":True,
      "normal_primary_real_client_FPR_eligible":False,
      "population_FPR":"UNMEASURED",
      "frozen_checker_original_unchanged":True,
    }
    report={"schema":"p6b39-appwrite-original-intentional-secret-protection-v1",
      "summary":summary,
      "source_commit":COMMIT,"source_git_blob":BLOB,"source_sha256":source_sha,
      "raw_native_wire_sha256":sha(wire.read_bytes()),"raw_wire_file":wire.name,
      "observed_policy_output":{
          "masked_nested_value":masked["nested"]["secret"],
          "blank_secret":masked["blank"]["secret"],
          "public_title":masked["title"],
          "fingerprint_prefix":"sha256:..."},
      "frozen_verifier_scoped":scoped,"frozen_verifier_misconfigured":invalid,
    }
    out=OUT/"B39_APPWRITE_REDACTION_POLICY_AUDIT.json"
    out.write_text(json.dumps(report,sort_keys=True,indent=2,ensure_ascii=False)+"\n")
    print(json.dumps(summary,sort_keys=True))
    print("B39_APPWRITE_ORIGINAL_INTENTIONAL_REDACTION_POLICY_CONFIRMED")
    print("B39_APPWRITE_RESULT_SHA256="+sha(out.read_bytes()))

if __name__=="__main__":
    asyncio.run(main())
