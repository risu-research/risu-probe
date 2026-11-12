"""Independent B21 signed fixture-owner and ORIGINAL source-native effect audit.

This auditor imports neither the RISU B20 effect engine nor the B21 owner
policy product. It independently verifies exact public wheel bytes, Ed25519
signature envelopes, original 7 JSON-RPC lines, each safe real before/after
file payload, original observer JSON and pre-issued policy-to-request bindings.

Local fixture-owner signature is NOT a third-party user authorization proof.
"""
from __future__ import annotations
import argparse,base64,hashlib,json,zipfile
from datetime import datetime
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

WHEEL="94610f0b73df1d3ada4ef0353353eb93695645c7b82f71ca80ed13dc1022c235"
SOURCE_SHA="c754a7720d52d92eb49324649b19f58b07b20703fcc2c2c1b02ce1f20152fcc8"
ORIGINAL_GIT_BLOB="f886fcbc6e61f3be8e6fd76b6e5f3ad1f8cbb7b6"
PREFIX=b"RISU-MCP-SIGNED-RESOURCE-POLICY-V1\x00"
CELLS=("before_trigger","before_control","after_trigger","after_control")
SHORT=b"RISU B21 harmless local file\n"
LONG=b"RISU B21 harmless local file plus preexisting extra nonsecret text\n"
EXPECTED={
 "before_trigger":{"file-presence":"ACTIVATE","file-contents":"CREATE","file-size":"INCREASE"},
 "before_control":{"file-presence":"NO_CHANGE","file-contents":"NO_CHANGE","file-size":"NO_CHANGE"},
 "after_trigger":{"file-presence":"ACTIVATE","file-contents":"CREATE","file-size":"INCREASE"},
 "after_control":{"file-presence":"NO_CHANGE","file-contents":"REPLACE","file-size":"DECREASE"},
}


def must(x,explanation):
    if not x:raise ValueError(explanation)


def h(data):return hashlib.sha256(data).hexdigest()


def json_file(path):return json.loads(Path(path).read_text("utf-8"))


def canon(data):return json.dumps(data,ensure_ascii=False,sort_keys=True,
                   separators=(",",":"),allow_nan=False).encode()


def utc(text):
    assert text.endswith("Z")
    return datetime.fromisoformat(text.replace("Z","+00:00"))


def audit(evidence:Path,expected_report:Path|None=None):
    wheel=evidence/"original_unmodified_pypi_wheel.whl"
    actual_wheel=wheel.read_bytes()
    must(h(actual_wheel)==WHEEL,"Original upstream PyPI release hash wrong")
    with zipfile.ZipFile(wheel) as z:source=z.read("filesystem_mcp/server.py")
    must(h(source)==SOURCE_SHA,"Original installed server code hash not pinned")
    must(hashlib.sha1(b"blob "+str(len(source)).encode()+bytes([0])+source).hexdigest()==ORIGINAL_GIT_BLOB,
         "Original pinned Git source blob not equal published byte content")
    trust=evidence/"pretrusted_synthetic_owner_root.json"
    pin=(evidence/"PREISSUED_OWNER_ROOT_SHA256.txt").read_text().strip()
    must(h(trust.read_bytes())==pin and len(pin)==64,
         "Original preexecution fixture owner root pin mismatch")
    owner=json_file(trust)
    must(owner["trust_scope"]=="CI_LOCAL_FIXTURE_ONLY" and
         len(owner["principals"])==1,"Not a deliberately scoped synthetic local owner")
    principal=owner["principals"][0]
    key=base64.b64decode(principal["ed25519_public_key_b64"],validate=True)
    must(len(key)==32 and h(key)==principal["key_id"],
         "Original owner public key ID mismatch")
    verifier=Ed25519PublicKey.from_public_bytes(key)
    manifest=json_file(evidence/"SIGNED_OWNER_AUTHORITY_MANIFEST.json")
    plan=json_file(evidence/"ORIGINAL_FROZEN_PLAN.json")
    must(manifest["declared_dataset_role"]==plan["classification"]==
         "DEVELOPMENT_POSITIVE_CONTROL","Signed fixture incorrectly promoted to independent discovery")
    must(manifest["original_software_sha256"]==WHEEL,
         "Original owner grant claims different release")
    must(manifest["original_software_file"]==wheel.name,
         "Actual verified original wheel not target of owner grant")
    must(manifest["plan_sha256"]==h(canon(plan)),
         "Original run owner policy does not bind frozen direction plan")
    report=json_file(expected_report) if expected_report else None
    observations=[]
    seen_nonce=set()
    scope_violations=0
    authorized=0
    for cell in CELLS:
        folder=evidence/cell
        proof=manifest["cases"][cell]
        signed_path=evidence/proof["grant_file"]
        event_path=evidence/proof["event_file"]
        must(signed_path.is_file() and event_path.is_file(),
             "Source-native case lacks original signed grant and event")
        must(h(signed_path.read_bytes())==proof["grant_sha256"] and
             h(event_path.read_bytes())==proof["event_sha256"],
             "Original grant or event changed after case capture")
        signed=json_file(signed_path)
        policy=signed["policy"]
        must(signed["schema"]=="risu-mcp-owner-precall-grant-v1",
             "Original preissued owner policy schema malformed")
        try:
            verifier.verify(base64.b64decode(signed["signature_ed25519_b64"],validate=True),
                            PREFIX+canon(policy))
        except (InvalidSignature,ValueError) as e:
            raise ValueError("Independent Ed25519 original owner grant forgery") from e
        must(policy["issuer"]==principal["issuer"] and
             policy["key_id"]==principal["key_id"] and
             policy["case"]==cell and
             policy["resource_id"] in principal["resource_ids"] and
             policy["resource_id"]=="fixture://risu-b21/"+cell+"/payload",
             "Signed policy doesn't bind same original resource and trusted issuer")
        must(policy["wheel_sha256"]==WHEEL and
             policy["actor"]=="b21-harmless-mcp-client" and
             policy["tool"]=="write_file" and
             policy["resource_argument_pointer"]=="/path",
             "Original signed tool, actor, target or upstream package mismatch")
        must(policy["run_nonce"] not in seen_nonce and len(policy["run_nonce"])==64,
             "Nonce reuse between owner-signed original runs")
        seen_nonce.add(policy["run_nonce"])
        event=json_file(event_path)
        must(event["case"]==cell and
             event["resource_id"]==policy["resource_id"] and
             event["run_nonce"]==policy["run_nonce"] and
             event["grant_sha256"]==h(signed_path.read_bytes()) and
             event["wheel_sha256"]==WHEEL,
             "No original pre-call event binding to exact signed grant")
        must(utc(policy["issued_at"])<=utc(event["invoked_at"])<=
             utc(event["completed_at"])<=utc(policy["expires_at"]),
             "Signed policy not valid when original tool executed")
        record=json_file(folder/"SOURCE_ORIGINAL_EXECUTION_RECORD.json")
        must(record["status"]=="CAPTURED_ORIGINAL_NATIVE_WITH_PRECALL_OWNER_GRANT"
             and record["original_mcp_server_unmodified"] is True and
             record["tool_result_success"] is True and
             record["grant_sha256_after_tool"]==record["signed_owner_policy_file_sha256_before_tool"]
             ==h(signed_path.read_bytes()),
             "Original software or signed grant changed across source-native invocation")
        original=folder/"original_stdio.jsonl"
        wire=original.read_bytes()
        assert event["trace_sha256"]==record["original_trace_sha256"]==h(wire)
        messages=[json.loads(line) for line in wire.splitlines()]
        must(len(messages)==7 and
             all(x.get("jsonrpc")=="2.0" for x in messages),
             "Original raw MCP transport count/structure differs")
        requests=[x for x in messages if x.get("method")=="tools/call"]
        catalogs=[x["result"] for x in messages if x.get("id")==2 and
                   type(x.get("result")) is dict]
        results=[x["result"] for x in messages if x.get("id")==20 and
                  type(x.get("result")) is dict]
        must(len(requests)==len(catalogs)==len(results)==1 and
             any(tool.get("name")=="write_file" for tool in catalogs[0]["tools"])
             and results[0].get("isError") is not True,
             "No original normal write_file invocation correlated to source catalog")
        args=requests[0]["params"]["arguments"]
        must(requests[0]["params"]["name"]=="write_file"
             and args["content"]==SHORT.decode("utf-8")
             and args["append"] is False
             and args["path"].endswith("/allowed/payload.txt"),
             "The actual MCP tool wrote beyond synthetic fixture or used wrong bytes")
        must(policy["args_sha256"]==event["args_sha256"]==h(canon(args))
             and policy["resource_argument_sha256"]==
             event["resource_argument_sha256"]==h(canon(args["path"])),
             "Signed owner grant not bound to actual tool's resource argument")
        previous_path=folder/"actual_before_payload.bin"
        after_path=folder/"actual_after_payload.bin"
        before=previous_path.read_bytes() if previous_path.exists() else None
        after=after_path.read_bytes() if after_path.exists() else None
        expected_pre=(None if cell in ("before_trigger","after_trigger")
                      else SHORT if cell=="before_control" else LONG)
        must(before==expected_pre and after==SHORT,
             "Original before/after physical file content differs from predeclared fixture")
        witness=json_file(folder/"ORIGINAL_PARENT_FILE_OBSERVER.json")
        must(h(canon(args["path"]))==witness["target_resource_path_sha256"],
             "Original independent physical target not linked to signed resource")
        must(witness["before_exists"] is (before is not None) and
             witness["after_exists"] is True and
             witness["before_sha256"]==(h(before) if before is not None else None)
             and witness["after_sha256"]==h(after) and
             witness["before_bytes"]==(len(before) if before is not None else 0)
             and witness["after_bytes"]==len(after),
             "Original independent observer not backed by original file bytes")
        must(event["original_observer_sha256"]==h((folder/"ORIGINAL_PARENT_FILE_OBSERVER.json").read_bytes()),
             "Original signed-grant event no longer binds physical effect observer")
        episode=json_file(folder/"episode.json")
        must(episode["trace_sha256"]==h(wire) and
             episode["call"]["arguments_sha256"]==h(canon(args)) and
             episode["call"]["result_sha256"]==h(canon(results[0])),
             "Original B20 episode hash differs from actual source-native call")
        # Compute actual typed directional changes from original byte evidence,
        # independently of the generic product's transition implementation.
        before_exists=before is not None
        expect={
          "file-presence":"NO_CHANGE" if before_exists else "ACTIVATE",
          "file-contents":"CREATE" if not before_exists else
                          "NO_CHANGE" if before==after else "REPLACE",
          "file-size":"NO_CHANGE" if before is not None and len(before)==len(after) else
                      "DECREASE" if before is not None and len(before)>len(after) else "INCREASE"
        }
        must(expect==EXPECTED[cell],"Original physical fixture's direction differs from preregistration")
        for name,direction in expect.items():
            allowed=policy["allowed_directions"][name]
            permitted=direction in allowed
            if permitted:authorized+=1
            else:scope_violations+=1
            must((not permitted) is (cell=="after_trigger"),
                 "Signed owner policy scope differs from pre-registered deliberate denial")
        observations.append({
          "case":cell,"unmodified_original_native_mcp":True,
          "signed_authority_preissued_in_ci_observation":True,
          "preexisting_payload_sha256":h(before) if before is not None else None,
          "post_payload_sha256":h(after),
          "direction_by_typed_sensor":expect,
          "observed_outside_signed_scope":cell=="after_trigger",
          "signed_grant_sha256":h(signed_path.read_bytes()),
          "original_mcp_trace_sha256":h(wire)
        })
    must(authorized==9 and scope_violations==3,
         "Unexpected direction authorization count")
    if report:
        sum_=report["summary"]
        must(sum_["within_signed_scope"]==authorized and
             sum_["outside_signed_scope"]==scope_violations and
             sum_["cases_with_signed_scope_violations"]==1 and
             sum_["valid_pinned_owner_signatures"]==4,
             "Original generic RISU authority result disagrees with independent audit")
    return {
        "schema":"risu-b21-independent-original-public-publisher-and-signed-fixture-owner-audit-v1",
        "original_vendor":"kujirahand/mcp_server-filesystem",
        "original_unmodified_PyPI_release_sha256":WHEEL,
        "original_upstream_module_sha256":SOURCE_SHA,
        "owner_public_root_sha256":pin,
        "owner_authority_class":"CI_LOCAL_FIXTURE_ONLY",
        "original_native_MCP_calls_independently_audited":4,
        "independently_verified_owner_signatures":4,
        "original_file_before_after_bytes_rehashed":8,
        "preissued_policies_in_original_parent_execution_records":4,
        "typed_directional_assessments":12,
        "within_signed_owner_fixture_scope":authorized,
        "outside_signed_fixture_scope":scope_violations,
        "real_upstream_vulnerabilities_discovered":0,
        "original_per_case":observations,
        "limits":[
            "All signatures are produced by a real fresh in-memory private key controlled by our isolated fixture owner, not a third-party end-user.",
            "A signed fixture owner policy records a constraint and the checker audits it AFTER execution; it did not block the third-party write tool.",
            "Chronology is demonstrated by original CI capture code and records, not an independently signed secure timestamp source.",
            "The trust-root pin was created by the same CI fixture owner, so it is not evidence of real production user ownership.",
            "This repeats normal third-party file-write behavior under intentionally conflicting fixture policy and does not discover a novel external vulnerability."
        ]}


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--evidence",type=Path,required=True)
    p.add_argument("--product-report",type=Path)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    r=audit(a.evidence,a.product_report)
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(r,sort_keys=True,indent=2,ensure_ascii=False)+"\n")
    print("B21_INDEPENDENT_SIGNED_OWNER_AND_ACTUAL_ORIGINAL_EFFECT_VERIFIED",
          r["original_native_MCP_calls_independently_audited"],
          r["within_signed_owner_fixture_scope"],
          r["outside_signed_fixture_scope"])


if __name__=="__main__":main()
