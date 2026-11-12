"""P6-B21 directed effects + resource-owner signed *scoped* authority.

Offline evidence verifier. It never runs user code, calls an MCP server,
issues signatures, infers grants from readOnlyHint, or assumes the published
software author owns a user's resource. A signature is meaningful only after
a separate caller pins the trust root and verifies its actual ownership of
the named resource. The CI fixture issuer owns only synthetic temp fixtures.
"""
from __future__ import annotations
import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import sys

from risu_mcp_effects import (
    judge, load_json, canonical, pointer, relative, sha, EffectError, CELLS
)
from risu_mcp_trace import _read_trace
from risu_mcp_authority import correlate

REPORT="risu-mcp-directed-effect-authority-report-v1"
MANIFEST="risu-mcp-directed-authority-evaluation-v1"
ROOTS="risu-mcp-external-owner-root-v1"
GRANT="risu-mcp-owner-precall-grant-v1"
EVENT="risu-mcp-owner-precall-execution-event-v1"
DOMAIN=b"RISU-MCP-SIGNED-RESOURCE-POLICY-V1\x00"
HEX=re.compile(r"[0-9a-f]{64}\Z")
TOKEN=re.compile(r"[A-Za-z0-9_.:-]{1,200}\Z")
KIND_OPS={
    "boolean":frozenset(("NO_CHANGE","ACTIVATE","DEACTIVATE")),
    "counter":frozenset(("NO_CHANGE","INCREASE","DECREASE")),
    "digest":frozenset(("NO_CHANGE","CREATE","DELETE","REPLACE")),
}


class AuthorityError(ValueError):pass


def demand(condition,why):
    if not condition:raise AuthorityError(why)


def parse_time(text):
    demand(type(text) is str and text.endswith("Z") and
           len(text)<=32,"INVALID_UTC_GRANT_TIMESTAMP")
    try:value=datetime.fromisoformat(text[:-1]+"+00:00")
    except (ValueError,TypeError) as e:raise AuthorityError("INVALID_UTC_GRANT_TIMESTAMP") from e
    demand(value.tzinfo is not None,"INVALID_UTC_GRANT_TIMESTAMP")
    return value


def get_directions(before,after,kind):
    demand(kind in KIND_OPS,"UNSUPPORTED_DIRECTION_SENSOR")
    if before==after:return "NO_CHANGE",None
    if kind=="boolean":
        demand(type(before) is type(after) is bool,"INVALID_BOOL_DIRECTION")
        return ("ACTIVATE" if not before else "DEACTIVATE"),None
    if kind=="counter":
        demand(type(before) is type(after) is int and
               0<=before<=2**53 and 0<=after<=2**53,"INVALID_COUNTER_DIRECTION")
        delta=after-before
        return ("INCREASE" if delta>0 else "DECREASE"),delta
    demand((before is None or type(before) is str) and
           (after is None or type(after) is str),"INVALID_DIGEST_DIRECTION")
    return ("CREATE" if before is None else
            "DELETE" if after is None else "REPLACE"),None


def decode64(text,size,why):
    demand(type(text) is str and len(text)<200,why)
    try:blob=base64.b64decode(text,validate=True)
    except Exception as e:raise AuthorityError(why) from e
    demand(len(blob)==size,why)
    return blob


def verify_signature(body,signature,pub):
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
    except ImportError as e:raise AuthorityError("CRYPTOGRAPHIC_VERIFIER_DEPENDENCY_MISSING") from e
    sig=decode64(signature,64,"INVALID_ED25519_SIGNATURE_ENCODING")
    key=decode64(pub,32,"INVALID_ED25519_ROOT_PUBLIC_KEY")
    try:Ed25519PublicKey.from_public_bytes(key).verify(
            sig,DOMAIN+canonical(body))
    except (InvalidSignature,ValueError) as e:
        raise AuthorityError("OWNER_SIGNATURE_INVALID") from e


def check_roots(path,expected_sha):
    demand(type(expected_sha) is str and HEX.fullmatch(expected_sha),
           "ROOT_HASH_MUST_BE_PROVIDED_OUT_OF_BAND")
    demand(not path.is_symlink() and path.is_file() and path.stat().st_size<=131072,
           "UNSAFE_OWNER_TRUST_ROOT_FILE")
    demand(sha(path.read_bytes())==expected_sha,
           "OUT_OF_BAND_TRUST_ROOT_HASH_MISMATCH")
    roots=load_json(path)
    demand(type(roots) is dict and roots.get("schema")==ROOTS and
           set(roots)=={"schema","principals","trust_scope"},
           "INVALID_OWNER_TRUST_ROOT_DOCUMENT")
    demand(roots["trust_scope"] in
           ("CI_LOCAL_FIXTURE_ONLY","OWNER_ATTESTED_OUT_OF_BAND"),
           "UNSUPPORTED_ROOT_TRUST_SCOPE")
    principals=roots["principals"]
    demand(type(principals) is list and 1<=len(principals)<=24,
           "MISSING_OR_OVERSIZED_OWNER_KEYS")
    trusted={}
    for row in principals:
        demand(type(row) is dict and set(row)=={
           "issuer","key_id","ed25519_public_key_b64","resource_ids"},
           "INVALID_OWNER_KEY_ENTRY")
        issuer=row["issuer"]
        demand(type(issuer) is str and TOKEN.fullmatch(issuer) and issuer not in trusted,
               "DUPLICATE_OR_INVALID_OWNER_PRINCIPAL")
        key=decode64(row["ed25519_public_key_b64"],32,"INVALID_OWNER_PUBLIC_KEY")
        demand(sha(key)==row["key_id"],"ROOT_PUBLIC_KEY_ID_NOT_HASHED_KEY")
        resources=row["resource_ids"]
        demand(type(resources) is list and 1<=len(resources)<=256 and
               all(type(x) is str and 1<=len(x)<=200 and
                   (x.startswith("fixture://") or x.startswith("urn:risu-owner:"))
                   for x in resources) and len(set(resources))==len(resources),
               "INVALID_TRUSTED_RESOURCE_IDENTITIES")
        trusted[issuer]=row
    return trusted,roots["trust_scope"]


def verify(plan, evidence, manifest, roots_file, expected_root_hash):
    evidence=Path(evidence).resolve(strict=True)
    prior=judge(evidence,plan)
    demand(prior["summary"]["all_predeclared_patterns_met"],
           "UNDERLYING_GENERIC_EFFECT_PATTERN_NOT_QUALIFIED")
    demand(type(manifest) is dict and manifest.get("schema")==MANIFEST and
           set(manifest)=={"schema","plan_sha256","cases","declared_dataset_role",
                           "original_software_file","original_software_sha256"},
           "INVALID_DIRECTION_AUTHORITY_MANIFEST")
    demand(manifest["plan_sha256"]==sha(canonical(plan)),
           "SIGNED_AUTHORITY_NOT_BOUND_TO_FROZEN_EFFECT_PLAN")
    demand(manifest["declared_dataset_role"]==plan["classification"],
           "EVALUATION_ROLE_CONFLICT")
    software=relative(evidence,manifest["original_software_file"])
    software_digest=sha(software.read_bytes())
    demand(type(manifest["original_software_sha256"]) is str and
           bool(HEX.fullmatch(manifest["original_software_sha256"])) and
           software_digest==manifest["original_software_sha256"],
           "ORIGINAL_EXECUTED_SOFTWARE_ARTIFACT_NOT_BOUND")
    cases=manifest["cases"]
    demand(type(cases) is dict and set(cases)==set(CELLS),
           "INCOMPLETE_OWNER_PRECALL_AUTHORITY_MATRIX")
    trusted,scope=check_roots(roots_file,expected_root_hash)
    used_nonce=set()
    used_grants=set()
    all_cases={}
    accepted=0
    violations=0
    transitions=0
    for cell in CELLS:
        refs=cases[cell]
        demand(type(refs) is dict and set(refs)=={
           "grant_file","grant_sha256","event_file","event_sha256"},
           "MISSING_PRECALL_GRANT_OR_EXECUTION_EVENT")
        gfile=relative(evidence,refs["grant_file"])
        efile=relative(evidence,refs["event_file"])
        demand(sha(gfile.read_bytes())==refs["grant_sha256"] and
               sha(efile.read_bytes())==refs["event_sha256"] and
               refs["grant_file"] not in used_grants,
               "OWNER_POLICY_OR_EVENT_CONTENT_MISMATCH")
        used_grants.add(refs["grant_file"])
        grant=load_json(gfile)
        event=load_json(efile)
        demand(type(grant) is dict and grant.get("schema")==GRANT and
               set(grant)=={"schema","policy","signature_ed25519_b64"},
               "INVALID_OWNER_SIGNED_POLICY_ENVELOPE")
        policy=grant["policy"]
        demand(type(policy) is dict and set(policy)=={
           "audience","issuer","key_id","case","actor","resource_id",
           "run_nonce","tool","args_sha256","resource_argument_pointer",
           "resource_argument_sha256","wheel_sha256","issued_at",
           "expires_at","allowed_directions"},
           "INVALID_OWNER_SIGNED_POLICY_BODY")
        demand(policy["audience"]=="risu-mcp-effect-authority-b21" and
               policy["case"]==cell and policy["tool"]==plan["tool"],
               "WRONG_SIGNED_GRANT_AUDIENCE_CASE_OR_TOOL")
        issuer=policy["issuer"]
        demand(issuer in trusted,"UNTRUSTED_GRANT_ISSUER")
        owner=trusted[issuer]
        demand(policy["key_id"]==owner["key_id"] and
               policy["resource_id"] in owner["resource_ids"],
               "SIGNED_GRANT_RESOURCE_OUTSIDE_TRUSTED_OWNER_SCOPE")
        demand(type(policy["actor"]) is str and
               bool(TOKEN.fullmatch(policy["actor"])),
               "INVALID_AUTHORIZED_ACTOR")
        demand(type(policy["run_nonce"]) is str and
               bool(HEX.fullmatch(policy["run_nonce"])) and
               policy["run_nonce"] not in used_nonce,
               "DUPLICATE_OR_INVALID_OWNER_SESSION_NONCE")
        used_nonce.add(policy["run_nonce"])
        demand(type(policy["wheel_sha256"]) is str and
               bool(HEX.fullmatch(policy["wheel_sha256"])) and
               policy["wheel_sha256"]==software_digest,
               "ORIGINAL_SOFTWARE_RELEASE_NOT_BOUND_TO_POLICY")
        issued=parse_time(policy["issued_at"])
        expires=parse_time(policy["expires_at"])
        demand(issued<expires and expires-issued<=timedelta(hours=1),
               "EXPIRED_OR_OVERSIZED_OWNER_POLICY_WINDOW")
        allowed=policy["allowed_directions"]
        demand(type(allowed) is dict and
               set(allowed)=={x["id"] for x in plan["sensors"]},
               "MISSING_SIGNED_SENSOR_SCOPES")
        kind_by_id={x["id"]:x["kind"] for x in plan["sensors"]}
        for sensor_id,operations in allowed.items():
            demand(type(operations) is list and 1<=len(operations)<=4 and
                   len(set(operations))==len(operations) and
                   all(type(op) is str and op in KIND_OPS[kind_by_id[sensor_id]]
                       for op in operations),
                   "INVALID_OR_TOO_BROAD_SIGNED_OPERATION_SCOPE")
        # Explicit signed resource mapping must be grounded in original
        # native MCP arguments; no string-prefix / file-name inference.
        traced,trace_hash=_read_trace(relative(evidence,plan["cells"][cell]["trace"]))
        matched,anomalies=correlate(traced)
        demand(not anomalies and len(matched)==1 and
               matched[0]["name"]==policy["tool"] and
               type(matched[0]["args"]) is dict,
               "CANNOT_BIND_OWNER_RESOURCE_TO_ORIGINAL_TOOL_ARGUMENTS")
        selected=pointer(matched[0]["args"],policy["resource_argument_pointer"])
        demand(policy["resource_argument_sha256"]==sha(canonical(selected)),
               "RESOURCE_OWNER_GRANT_NOT_BOUND_TO_ACTUAL_ARGUMENT_TARGET")
        verify_signature(policy,grant["signature_ed25519_b64"],
                         owner["ed25519_public_key_b64"])
        demand(type(event) is dict and event.get("schema")==EVENT and
               set(event)=={"schema","case","actor","resource_id","run_nonce",
                            "grant_sha256","tool","args_sha256",
                            "resource_argument_sha256","wheel_sha256",
                            "invoked_at","completed_at","trace_sha256",
                            "original_observer_sha256"},
               "INVALID_PRECALL_EXECUTION_EVENT")
        demand(event["case"]==cell and
               event["actor"]==policy["actor"] and
               event["resource_id"]==policy["resource_id"] and
               event["run_nonce"]==policy["run_nonce"] and
               event["grant_sha256"]==sha(gfile.read_bytes()) and
               event["tool"]==policy["tool"] and
               event["args_sha256"]==policy["args_sha256"] and
               event["resource_argument_sha256"]==policy["resource_argument_sha256"] and
               event["wheel_sha256"]==policy["wheel_sha256"],
               "EXECUTION_NOT_BOUND_TO_PREISSUED_OWNER_POLICY")
        invoked=parse_time(event["invoked_at"])
        completed=parse_time(event["completed_at"])
        demand(issued<=invoked<=completed<=expires and
               completed-invoked<=timedelta(minutes=15),
               "OWNER_GRANT_NOT_VALID_DURING_CAPTURED_EXECUTION")
        episode=load_json(relative(evidence,plan["cells"][cell]["episode"]))
        demand(event["trace_sha256"]==episode["trace_sha256"]==
               prior["episodes"][cell]["trace_sha256"] and
               event["args_sha256"]==episode["call"]["arguments_sha256"],
               "ACTUAL_MCP_CALL_NOT_BOUND_TO_SIGNED_GRANT")
        witness=episode["sensors"]
        demand(type(witness) is list and len(witness)==len(plan["sensors"]),
               "DIRECTION_SENSOR_WITNESS_MISSING")
        # The independent observer SHA binds to B20 verified original data.
        # B20 accepts one original JSON per cell used by several sensor fields.
        raw_hashes={w["original_observer"]["sha256"] for w in witness}
        demand(len(raw_hashes)==1 and
               event["original_observer_sha256"] in raw_hashes,
               "EXECUTION_NOT_BOUND_TO_INDEPENDENT_ORIGINAL_EFFECT_SENSOR")
        direction_items={}
        for w in witness:
            sensor_id=w["id"]
            op,delta=get_directions(w["before"],w["after"],w["kind"])
            authorized=op in allowed[sensor_id]
            direction_items[sensor_id]={
              "transition":op,
              "signed_allowed_transitions":sorted(allowed[sensor_id]),
              "permitted_by_pinned_fixture_owner":authorized,
              "delta":delta,
              "pre_value_sha256":sha(canonical(w["before"])),
              "post_value_sha256":sha(canonical(w["after"])),
            }
            if op!="NO_CHANGE":transitions+=1
            if authorized:accepted+=1
            else:violations+=1
        all_cases[cell]={
          "signed_owner_issuer":issuer,
          "signer_key_sha256":owner["key_id"],
          "owner_resource_id":policy["resource_id"],
          "actor_claim":policy["actor"],
          "policy_sha256":sha(canonical(policy)),
          "grant_envelope_sha256":sha(gfile.read_bytes()),
          "execution_nonce_sha256":sha(policy["run_nonce"].encode()),
          "original_tool_result_sha256":prior["episodes"][cell]["tool_result_sha256"],
          "directions":direction_items,
          "policy_local_verdict":(
              "SIGNED_SCOPE_OBSERVED_VIOLATION" if any(
                  not x["permitted_by_pinned_fixture_owner"]
                  for x in direction_items.values()) else
              "SIGNED_SCOPE_OBSERVED_COMPLIANCE"
          )
        }
    return {
      "schema":REPORT,
      "plan_hash":sha(canonical(plan)),
      "authority_root_file_sha256":expected_root_hash,
      "trusted_root_mode":scope,
      "dataset_role":plan["classification"],
      "original_software_artifact_sha256":software_digest,
      "status":"DIRECTIONAL_OBSERVATION_WITH_SIGNED_SCOPE_VERIFIED",
      "summary":{
          "source_bound_original_mcp_calls":4,
          "valid_pinned_owner_signatures":4,
          "typed_directional_sensor_assessments":accepted+violations,
          "sensor_changes_observed":transitions,
          "within_signed_scope":accepted,
          "outside_signed_scope":violations,
          "cases_with_signed_scope_violations":sum(
               x["policy_local_verdict"]=="SIGNED_SCOPE_OBSERVED_VIOLATION"
               for x in all_cases.values()),
          "new_external_vulnerabilities_discovered":0
      },
      "cases":all_cases,
      "limitations":[
        "The principal's control over each resource must be established OUT OF BAND. A pinned key signature alone cannot prove legal or operating-system ownership.",
        "In CI_LOCAL_FIXTURE_ONLY mode, authorization means only a synthetic resource owner's signed fixture policy, not an upstream developer or production user's consent.",
        "An observed policy-scope violation does not mean the MCP server enforced or bypassed an access-control check. This verifier is POST-HOC, not a runtime prevention layer.",
        "Original observation chronology and nonce are CI records; fully coherent replay of a captured signed bundle still requires an external durable nonce ledger and trusted event attestation to exclude.",
        "The underlying B20 observer JSON is not cryptographically signed by an independent measuring device; copied bytes and JSON pointers only prove internal consistency.",
        "The owner policy binds a claimed actor and original MCP tool arguments. Actor authentication is outside scope and must be supplied separately for production authorization.",
        "Result applies to the named sensors and resources, not all possible side effects. MCP annotations are not policy authority."
      ]
    }


def cli(argv=None):
    parser=argparse.ArgumentParser(prog="risu-probe verify-mcp-effect-authority")
    parser.add_argument("--plan",required=True,type=Path)
    parser.add_argument("--evidence-root",required=True,type=Path)
    parser.add_argument("--authority-manifest",required=True,type=Path)
    parser.add_argument("--trust-root",required=True,type=Path)
    parser.add_argument("--trusted-root-sha256",required=True)
    parser.add_argument("--format",choices=("text","json"),default="text")
    parser.add_argument("--out",type=Path)
    parser.add_argument("--fail-on-violation",action="store_true")
    args=parser.parse_args(argv)
    try:
        result=verify(load_json(args.plan),args.evidence_root.resolve(strict=True),
            load_json(args.authority_manifest),args.trust_root,args.trusted_root_sha256)
        output=(json.dumps(result,indent=2,sort_keys=True,ensure_ascii=False)+"\n"
                if args.format=="json" else "RISU directed/authority | "+
                    str(result["summary"]["outside_signed_scope"])+" scope violations\n")
        if args.out:
            with args.out.resolve().open("x",encoding="utf-8") as f:f.write(output)
        else:print(output,end="")
        if args.fail_on_violation and result["summary"]["outside_signed_scope"]:
            return 1
        return 0
    except (AuthorityError,EffectError,ValueError,TypeError,KeyError,OSError,
            UnicodeError,RecursionError) as e:
        print("RMA921 UNVERIFIED_DIRECTION_OR_OWNER_AUTHORITY: "+type(e).__name__,
              file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(cli())
