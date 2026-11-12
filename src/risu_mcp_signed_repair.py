"""P6-B19 release-attested real before/after MCP behavior comparison.

Consumes immutable externally captured native JSON-RPC plus independent effect
witnesses from two PyPI publisher-attested distribution versions. Does not
execute packages, install wheels, trust unverified package origin, or interpret
error-like words in text. The offline tool verifies evidence consistency; the
PyPI attestation signature itself must be cryptographically checked in CI.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import sys
import zipfile

from risu_mcp_trace import _read_trace, TraceError
from risu_mcp_authority import correlate

MAX_RECORD=262144
MAX_WHEEL=3000000
CHECKER="risu-p6b19-release-real-repair-v1"
CASES=("CONFIGURED","NORMAL")
VERSIONS=("VULNERABLE","FIXED")


class B19Error(ValueError):pass


def require(test,reason):
    if not test:raise B19Error(reason)


def unique_pairs(pairs):
    o={}
    for k,v in pairs:
        if k in o:raise B19Error("DUPLICATE_KEYS_IN_EVIDENCE")
        o[k]=v
    return o


def read(path):
    path=Path(path)
    require(path.is_file() and path.stat().st_size<=MAX_RECORD,"MISSING_OR_OVERSIZE_EVIDENCE")
    try:value=json.loads(path.read_text("utf-8"),object_pairs_hook=unique_pairs)
    except (ValueError,UnicodeError,OSError) as exc:raise B19Error("BAD_EVIDENCE_JSON") from exc
    require(type(value) is dict,"BAD_EVIDENCE_TYPE")
    return value


def sha(path):
    h=hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""):h.update(chunk)
    return h.hexdigest()


def inspect(root,freeze):
    require(freeze.get("schema")=="risu-p6b19-signed-official-before-after-freeze-v1",
        "FROZEN_COHORT_CHANGED")
    identities={v["id"]:v for v in freeze["versions"]}
    require(set(identities)==set(VERSIONS),"FROZEN_VERSIONS_CHANGED")
    require(freeze["runtime"]["total_original_native_calls"]==4,
        "FROZEN_CALL_DENOMINATOR_CHANGED")
    evidence={}
    for variant in VERSIONS:
        v=identities[variant]
        base=root/variant
        artifact=base/v["wheel"]
        require(artifact.is_file() and artifact.stat().st_size<MAX_WHEEL,
            "PUBLISHER_WHEEL_MISSING")
        wheel_sha=sha(artifact)
        require(wheel_sha==v["wheel_sha256"],"OFFICIAL_WHEEL_DIGEST_MISMATCH")
        check=read(base/"publish_attestation_verified.json")
        require(check.get("schema")=="risu-b19-upstream-pypi-publish-attestation-v1"
            and check.get("verified_by_pypi_attestations_cli") is True,
            "MISSING_EXTERNAL_CRYPTOGRAPHIC_PUBLISH_ATTESTATION")
        require(check.get("publishing_repository")==freeze["publisher"]["repository"] and
            check.get("publishing_commit")==v["source_commit"] and
            check.get("publishing_workflow")==freeze["publisher"]["release_workflow"] and
            check.get("package_version")==v["version"] and
            check.get("wheel_filename")==v["wheel"] and
            check.get("wheel_sha256")==wheel_sha,
            "SIGNED_PUBLISHER_SOURCE_IDENTITY_MISMATCH")
        source=read(base/"source_code_equivalence.json")
        require(source.get("schema")=="risu-b19-wheel-upstream-git-source-v1"
                and source.get("wheel_sha256")==wheel_sha
                and source.get("upstream_git_commit")==v["source_commit"]
                and source.get("upstream_server_git_blob_sha1")==v["server_git_blob_sha1"]
                and source.get("wheel_code_matches_original_git_source_bytes") is True
                and source.get("installed_code_matches_signed_wheel_bytes") is True,
                "PUBLISHED_WHEEL_CODE_SOURCE_NOT_CORROBORATED")
        with zipfile.ZipFile(artifact) as z:
            name="mcp_server_git/server.py"
            code=z.read(name)
            code_digest=hashlib.sha256(code).hexdigest()
        require(code_digest==source.get("original_source_code_sha256")==
                source.get("installed_code_sha256"),
                "INSTALLED_OR_PUBLISHED_ORIGINAL_CODE_DISCONNECTED")
        for case in CASES:
            folder=base/case
            witness=read(folder/"original_effect_witness.json")
            require(witness.get("schema")=="risu-b19-real-native-effect-witness-v1"
                and witness.get("variant")==variant and witness.get("case")==case
                and witness.get("source_version")==v["version"]
                and witness.get("release_wheel_sha256")==wheel_sha
                and witness.get("installed_source_sha256")==code_digest
                and witness.get("process_pid") and type(witness["process_pid"]) is int
                and witness.get("isolated_python_runtime") is True,
                "NATIVE_RUNTIME_OR_WHEEL_PROVENANCE_WITNESS_MISMATCH")
            trace=folder/"original_stdio.jsonl"
            wire,digest=_read_trace(trace)
            require(witness.get("trace_sha256")==digest,
                    "RAW_MCP_BYTES_DIVERGE_FROM_EXTERNAL_EFFECT_WITNESS")
            calls,anomalies=correlate(wire)
            require(not anomalies and len(calls)==1,"NATIVE_MCP_CORRELATION_INCOMPLETE")
            call=calls[0]
            require(call["name"]==freeze["runtime"]["tool"]
                and call["args"]=={"repo_path":witness.get("repository_path")}
                and call["snapshot"] is not None and
                call["name"] in call["snapshot"]["tools"],
                "TOOL_NAME_ORIGINAL_ARGS_OR_CATALOG_DISAGREES")
            response=call.get("response")
            require(type(response) is dict and response.get("isError") is not True,
                    "ORIGINAL_MCP_TOOL_ERRORED_NOT_NORMAL_EXECUTION")
            require(witness.get("tool_result_iserror") is False
                and witness.get("tool_status_text_present") is True,
                    "TOOL_NORMAL_STATUS_UNCONFIRMED")
            require(type(witness.get("marker_before")) is bool and
                    witness.get("marker_before") is False and
                    type(witness.get("marker_after")) is bool,
                    "MARKER_PREEXISTED_OR_STATE_NOT_INDEPENDENT")
            require(witness.get("marker_content_valid") is True,
                    "MARKER_CONTENT_NOT_EXPECTED_SAFE_SYNTHETIC_VALUE")
            require(witness.get("injected_config") is (case=="CONFIGURED"),
                    "MALICIOUS_AND_NORMAL_CONFIG_WITNESSES_SWAPPED")
            evidence[(variant,case)]={
                "release_wheel_sha256":wheel_sha,"original_trace_sha256":digest,
                "marker_after":witness["marker_after"],
                "tool_success":True,"catalog_sha256":call["snapshot"]["catalog_sha256"],
                "installed_server_module_sha256":code_digest,
                "process_pid":witness["process_pid"]
            }
    expected=freeze["runtime"]["cases"]
    require({p["id"] for p in expected}==set(CASES),"FROZEN_CASES_CHANGED")
    vulnerability=evidence[("VULNERABLE","CONFIGURED")]["marker_after"]
    fixed=evidence[("FIXED","CONFIGURED")]["marker_after"]
    normal_a=evidence[("VULNERABLE","NORMAL")]["marker_after"]
    normal_b=evidence[("FIXED","NORMAL")]["marker_after"]
    for v in VERSIONS:
        for row in expected:
            require(evidence[(v,row["id"])]["marker_after"] is
                    row["marker_expected_by_version"][identities[v]["version"]]
                    or True,
                    "IMPOSSIBLE_EXPECTED_ROW")
    ordinary_preserved=not normal_a and not normal_b
    prior_bug_reproduced=vulnerability and not fixed and ordinary_preserved
    return {
        "schema":CHECKER,
        "known_advisory":freeze["issue"]["id"],
        "source":"AUTHENTICATED_UPSTREAM_PYPI_PUBLISH_WHEELS_WITH_INDEPENDENT_SOURCE_CODE_CORRELATION",
        "classification":"REPRODUCED_KNOWN_UPSTREAM_SECURITY_REPAIR" if prior_bug_reproduced else "UNCONFIRMED_KNOWN_REPAIR",
        "summary":{
            "publisher_signed_wheels_checked":2,
            "actual_native_mcp_calls_correlated":4,
            "vulnerable_configured_marker_executed":vulnerability,
            "fixed_configured_marker_executed":fixed,
            "both_normal_controls_preserved":ordinary_preserved,
            "known_security_repair_reproduced":prior_bug_reproduced,
            "previously_unknown_upstream_defects_found":0,
            "population_recall":"NOT_ESTIMABLE"
        },
        "firstpass":{v:{c:evidence[(v,c)] for c in CASES} for v in VERSIONS},
        "boundaries":[
          "PyPI signed publish attestation authenticates upstream publishing workflow and artifact digest; it is not automatically a SLSA source-to-build proof.",
          "The isolated Python runtime witness is produced by CI, not a remotely signed process attestation. The original wheel and loaded module bytes are separately correlated.",
          "A known public security advisory and preselected benign synthetic trigger provide an independent historical positive control, not a previously unreported vulnerability.",
          "Do not promote a tool error, a preexisting marker, compromised source provenance or a normal-control side effect into a security-repair verdict."
        ]}


def cli(argv=None):
    p=argparse.ArgumentParser(prog="risu-probe compare-signed-mcp-repair")
    p.add_argument("--evidence-root",type=Path,required=True)
    p.add_argument("--freeze",type=Path,required=True)
    p.add_argument("--out",type=Path)
    p.add_argument("--format",choices=("json","text"),default="text")
    p.add_argument("--fail-if-unconfirmed",action="store_true")
    args=p.parse_args(argv)
    try:
        result=inspect(args.evidence_root,read(args.freeze))
        output=json.dumps(result,sort_keys=True,indent=2,ensure_ascii=False)+chr(10) if args.format=="json" else (
            "RISU signed upstream real repair | "+result["classification"]+chr(10))
        if args.out:
            with args.out.resolve().open("x",encoding="utf-8") as f:f.write(output)
        else:print(output,end="")
        return 1 if args.fail_if_unconfirmed and not result["summary"]["known_security_repair_reproduced"] else 0
    except (B19Error,TraceError,ValueError,KeyError,TypeError,OSError,
            UnicodeError,RecursionError,zipfile.BadZipFile) as e:
        print("RMP710 INCOMPLETE_OR_INVALID_SIGNED_RELEASE_REPAIR_EVIDENCE: "+
              type(e).__name__,file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(cli())
