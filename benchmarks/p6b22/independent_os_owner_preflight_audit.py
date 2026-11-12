"""P6-B22 auditor, independent of the RISU pre-call gateway.

Reparses the actual original JSON-RPC from 3 allowed original processes,
actual OS execve syscall traces of every accepted/denied case, literal
external file before/after bytes, original upstream wheel and signed owner
grants and revocation lists. NO imports of risu_mcp_preflight or B21/B20.

This proves repeatable Linux OS-principal fixture authorization only.
A pretrusted owner root captured by the same privileged CI runner is not
an independent natural person's consent.
"""
from __future__ import annotations
import argparse,base64,hashlib,json,zipfile,re
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

WHEEL="94610f0b73df1d3ada4ef0353353eb93695645c7b82f71ca80ed13dc1022c235"
SOURCE="c754a7720d52d92eb49324649b19f58b07b20703fcc2c2c1b02ce1f20152fcc8"
PREFIX=b"RISU-B22-OS-OWNER-PRECALL-V1\x00"
REVPREFIX=b"RISU-B22-OS-OWNER-REVOCATION-V1\x00"
ALLOWED={"allowed_create","allowed_noop","allowed_replace"}
DENIED={"denied_replay","denied_no_grant","denied_signed_scope",
        "denied_revoked","denied_os_dac","denied_stale_state",
        "denied_tampered_request"}


def ensure(x,reason):
    if not x:raise ValueError(reason)


def digest(b):return hashlib.sha256(b).hexdigest()
def canon(x):
    return json.dumps(x,sort_keys=True,separators=(",",":"),
                      ensure_ascii=False,allow_nan=False).encode()
def load(p):return json.loads(Path(p).read_text("utf-8"))


def state_bytes(root,label,phase):
    path=root/(label+"_"+phase+"_ORIGINAL_TARGET.bin")
    return path.read_bytes() if path.exists() else None


def claim_state(raw):
    return {"exists":raw is not None,
            "sha256":digest(raw) if raw is not None else None,
            "size":len(raw) if raw is not None else 0}


def validate(research:Path,pkg:Path):
    original_wheel=next(pkg.glob("filesystem_mcp-1.0.2-*.whl"))
    raw=original_wheel.read_bytes()
    ensure(digest(raw)==WHEEL,"Original external PyPI wheel byte mismatch")
    with zipfile.ZipFile(original_wheel) as z:
        module=z.read("filesystem_mcp/server.py")
    ensure(digest(module)==SOURCE,"Original upstream server module byte mismatch")
    info=load(research/"OS_INDEPENDENT_ACCOUNT_STATE.json")
    root=research/"PREISSUED_PUBLIC_OWNER_ROOT.json"
    signed_root=load(root)
    ensure(digest(root.read_bytes())==info["pretrusted_owner_root_sha256"],
           "Owner root pin changed from original pre-call")
    ensure(signed_root["owner_uid"]==info["owner_uid"] and
           signed_root["executor_uid"]==info["executor_uid"] and
           info["owner_uid"]!=info["executor_uid"] and
           info["owner_uid"]!=0 and info["executor_uid"]!=0,
           "Separate actual OS user identity evidence missing")
    ensure(info["executor_can_read_owner_private_key"] is False and
           info["private_key_mode"]=="0o600" and
           info["private_key_uid"]==info["owner_uid"],
           "Owner private key not restricted from executor")
    key=base64.b64decode(signed_root["ed25519_public_key_b64"],validate=True)
    ensure(len(key)==32 and digest(key)==signed_root["key_id"],
           "No valid pinned resource owner key")
    pub=Ed25519PublicKey.from_public_bytes(key)
    original=load(research/"FIRST_REAL_OS_PRINCIPAL_ENFORCEMENT_SUMMARY.json")
    cases=original["cases"]
    ensure(set(cases)==ALLOWED|DENIED and
           original["total_preflight_decisions"]==10 and
           original["authorized_native_original_MCP_calls"]==3 and
           original["genuinely_denied_before_original_MCP_server_spawn"]==7,
           "Missing precommitted ten OS principal observations")
    grants={digest(f.read_bytes()):load(f)
            for f in research.glob("grant_*.json")}
    signed_epochs={}
    for path in research.glob("revocations_epoch*.json"):
        document=load(path)
        ensure(document["schema"]=="risu-b22-owner-revocation-v1",
               "Invalid actual signed revocation schema")
        body=document["revocations"]
        ensure(body["issuer"]==signed_root["issuer"] and
               body["key_id"]==signed_root["key_id"],
               "Signed revoke issuer differs from actual owner")
        try:
            pub.verify(base64.b64decode(document["signature_ed25519_b64"],
                validate=True),REVPREFIX+canon(body))
        except (InvalidSignature,ValueError) as e:
            raise ValueError("Wrong original owner revocation signature") from e
        signed_epochs[digest(path.read_bytes())]=body
    ensure(len(signed_epochs)>=2,"Missing original owner initial and revoked epochs")
    all_reasons={}
    actual_calls=0
    unseen=0
    for label in sorted(cases):
        rec=cases[label]
        report=load(research/rec["source_report_file"])
        tracer=(research/(label+".execve.strace")).read_text(errors="replace")
        pre=state_bytes(research,label,"BEFORE")
        post=state_bytes(research,label,"AFTER")
        ensure(rec["file_before"]==claim_state(pre) and
               rec["file_after"]==claim_state(post),
               "External source physical file bytes not equal recorded original state")
        native_seen=('-m", "filesystem_mcp"' in tracer or
                     "'-m', 'filesystem_mcp'" in tracer)
        ensure(rec["actual_original_server_execve_seen"] is native_seen,
               "Original source execve verification differs from real tracer")
        ensure(native_seen is (label in ALLOWED),
               "Authorized/denied OS process semantics contradicted")
        ensure(report["server_started"] is native_seen and
               report["native_original_tool_calls"]==int(native_seen),
               "Original process state not bound to source-level policy decision")
        ensure(rec["real_owner_uid"]==info["owner_uid"] and
               rec["real_executor_uid"]==info["executor_uid"],
               "Actual gateway process UID witness mismatch")
        ensure(rec["resource_directory_owner_uid_at_invocation"]==
               info["owner_uid"],
               "Owner abandoned physical OS file directory before request")
        if label=="denied_os_dac":
            ensure(rec["resource_directory_mode_at_invocation"]=="0o700",
                   "No independent original OS DAC withdrawal witness")
        rev=rec["revocation_epoch_sha256"]
        ensure(rev in signed_epochs,"Unproven original signed revocation epoch")
        request_matches=[load(f) for f in research.glob("request_*.json")
            if digest(f.read_bytes())==rec["request_file_sha256"]]
        ensure(len(request_matches)==1,"Actual caller MCP request not preserved")
        actual_request=request_matches[0]
        gsha=rec["signed_grant_file_sha256"]
        if gsha is None:
            ensure(label=="denied_no_grant","Unexpected original request with no grant")
        else:
            ensure(gsha in grants,"Missing original Ed25519 grant bytes")
            g=grants[gsha]
            try:
                pub.verify(base64.b64decode(g["signature_ed25519_b64"],
                    validate=True),PREFIX+canon(g["policy"]))
            except (InvalidSignature,ValueError) as e:
                raise ValueError("Original resource owner pre-call signature forged") from e
            p=g["policy"]
            ensure(p["owner_uid"]==info["owner_uid"] and
                   p["executor_uid"]==info["executor_uid"] and
                   p["resource_id"]==signed_root["resource_id"] and
                   p["wheel_sha256"]==WHEEL and
                   p["server_module"]=="filesystem_mcp",
                   "Actual original grant not scoped to correct OS resource identity")
            if label!="denied_tampered_request":
                ensure(p["request_sha256"]==digest(canon(actual_request)),
                       "Signed policy not bound to actual MCP args")
            else:
                ensure(p["request_sha256"]!=digest(canon(actual_request)),
                       "Tampered request attack fixture not actually mutated")
            if label=="denied_revoked":
                ensure(p["nonce"] in signed_epochs[rev]["revoked_nonces"],
                       "Revoked grant not found in pinned owner-signed revocations")
            else:
                ensure(p["nonce"] not in signed_epochs[rev]["revoked_nonces"],
                       "Non-revoked proof accidentally used revoked grant")
        if native_seen:
            original_wire=(research/(label+"_ORIGINAL_NATIVE_STDIO.jsonl")).read_bytes()
            ensure(digest(original_wire)==report["original_raw_jsonrpc_sha256"] and
                   original_wire==base64.b64decode(report["original_raw_jsonrpc_b64"],
                       validate=True),
                   "Original native wire not physically captured as signed result")
            wire=[json.loads(line) for line in original_wire.splitlines()]
            ensure(len(wire)==7 and all(x.get("jsonrpc")=="2.0" for x in wire),
                   "Original upstream server response not 7-message MCP stdio")
            catalog=[x["result"] for x in wire if x.get("id")==2 and
                     type(x.get("result")) is dict]
            requests=[x for x in wire if x.get("method")=="tools/call"]
            results=[x["result"] for x in wire if x.get("id")==20 and
                     type(x.get("result")) is dict]
            ensure(len(catalog)==len(requests)==len(results)==1 and
                   any(x.get("name")=="write_file" for x in catalog[0]["tools"])
                   and results[0].get("isError") is not True
                   and requests[0]==actual_request,
                   "Unexpected source native MCP tool, catalog or result")
            ensure(rec["file_after"]["sha256"]==
                   digest(actual_request["params"]["arguments"]["content"].encode()),
                   "Verified native tool response not backed by target physical effect")
            actual_calls+=1
        else:
            ensure(pre==post and
                   not (research/(label+"_ORIGINAL_NATIVE_STDIO.jsonl")).exists(),
                   "Owner-denied actual file changed or original server ran")
            unseen+=1
        all_reasons[label]=report["reason"]
    ensure(actual_calls==3 and unseen==7,
           "Original OS observed spawn/denial denominator differs")
    ensure(all_reasons["denied_signed_scope"]=="REQUESTED_DIRECTION_NOT_APPROVED_BY_OWNER"
           and all_reasons["denied_revoked"]=="OWNER_REVOKED_THIS_GRANT"
           and all_reasons["denied_replay"]=="REPLAY_OR_UNREADABLE_LOCAL_OS_RESOURCE"
           and all_reasons["denied_stale_state"]=="STALE_PRECALL_TARGET_STATE",
           "Signed policy and replay refusal reasons differ from preregistration")
    return {
        "schema":"risu-b22-independent-original-os-owner-precall-audit-v1",
        "upstream_real_original_pypi_sha256":WHEEL,
        "upstream_real_original_python_module_sha256":SOURCE,
        "issuer_public_key_sha256":signed_root["key_id"],
        "two_real_distinct_os_uids_confirmed_from_original_ci":True,
        "owner_private_key_never_in_export":True,
        "owner_private_key_mode_from_original_owner_process":"0600",
        "owner_revocation_signatures_independently_verified":len(signed_epochs),
        "authorized_native_upstream_calls":actual_calls,
        "denied_before_original_server_execve":unseen,
        "all_denied_original_target_bytes_preserved":True,
        "original_owner_signed_grants_verified":len(grants),
        "new_external_upstream_vulnerabilities":0,
        "independent_natural_person_consent":"NOT_OBTAINED",
        "original_denial_reasons":all_reasons,
        "limitations":[
            "Original Linux OS UIDs are separate but CI privileged runner can sudo; this is not an independently consenting external person.",
            "execve witness is a CI-captured syscall trace, not hardware/remote attestation.",
            "The gateway pre-authorizes exact file-write tool requests, but not all possible hidden side effects.",
            "Initial trusted root and revocation sequence are pinned by the CI workflow, not by a production independent trust administrator.",
            "Owner revocation freshness can roll back if caller supplies an old but formerly valid pinned epoch digest; production needs trusted monotonic revocation reference.",
            "POSIX DAC and path checks are runtime preconditions, not a race-free openat2 sandbox or SELinux policy.",
            "This same upstream filesystem server was used in B20/B21. The independent evaluation here concerns pre-call enforcement behavior, not fresh defect discovery."
        ]
    }


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--evidence-root",type=Path,required=True)
    p.add_argument("--original-package",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    report=validate(a.evidence_root,a.original_package)
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
    print("B22_INDEPENDENT_OS_OWNER_SOURCE_NATIVE_PRECALL_EXECVE",report[
        "authorized_native_upstream_calls"],report["denied_before_original_server_execve"])


if __name__=="__main__":
    main()
