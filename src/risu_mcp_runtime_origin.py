"""P6-B18 offline source/build/live-process evidence correlation.

Limits:
- JSON witness integrity checks are not themselves cryptographic attestation.
- A signed GitHub Actions attestation is independently verified by CI's
  gh attestation verify step; this tool only correlates the exported result.
- This does NOT authenticate the external publisher's deployed software.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys

from risu_mcp_origin import pinned_sources, validate_manifest, OriginError
from risu_mcp_trace import _read_trace, TraceError
from risu_mcp_authority import correlate

B18 = "risu-p6b18-executed-binary-predeclared-v1"
BUILDER = "risu-b18-builder-evidence-v1"
RUNTIME = "risu-b18-runtime-procfs-evidence-v1"
MAX_RECORD = 262144
MAX_BINARY = 90000000
HASH = re.compile(r"[0-9a-f]{64}\Z")


class RuntimeOriginError(ValueError):
    pass


def require(test: bool, reason: str) -> None:
    if not test:
        raise RuntimeOriginError(reason)


def json_file(path: Path) -> dict:
    try:
        p=path.resolve(strict=True)
        if not p.is_file() or p.stat().st_size>MAX_RECORD:
            raise RuntimeOriginError("OVERSIZED_OR_MISSING_EVIDENCE_RECORD")
        raw=p.read_text(encoding="utf-8")
        value=json.loads(raw,object_pairs_hook=_unique)
    except (OSError,UnicodeError,ValueError,TypeError) as e:
        if isinstance(e,RuntimeOriginError):raise
        raise RuntimeOriginError("INVALID_JSON_EVIDENCE") from e
    require(type(value) is dict,"EVIDENCE_NOT_AN_OBJECT")
    return value


def _unique(pairs: list) -> dict:
    result={}
    for key,val in pairs:
        if key in result:raise RuntimeOriginError("DUPLICATE_JSON_KEYS")
        result[key]=val
    return result


def sha_file(path:Path) -> str:
    path=path.resolve(strict=True)
    require(path.is_file() and path.stat().st_size <= MAX_BINARY,
            "BINARY_MISSING_OR_TOO_LARGE")
    h=hashlib.sha256()
    with path.open("rb") as f:
        while True:
            buf=f.read(1024*1024)
            if not buf:break
            h.update(buf)
    return h.hexdigest()


def is_hash(value) -> bool:
    return type(value) is str and bool(HASH.fullmatch(value))


def inspect(trace: Path, source_checkout: Path, binary: Path,
            frozen:dict, source_manifest:dict, a:dict,b:dict,
            runtime:dict,attestation:dict) -> dict:
    require(frozen.get("schema")==B18,"FROZEN_COHORT_SCHEMA_MISMATCH")
    source=frozen.get("source",{})
    build=frozen.get("build",{})
    expected=frozen.get("runtime",{})
    require(source_manifest.get("revision")==source.get("revision") and
            source_manifest.get("repository")==source.get("repository"),
            "PINNED_SOURCE_REPOSITORY_REVISION_CONFLICT")
    listed={x.get("path"):x.get("blob") for x in source.get("files",[])}
    listed2={x.get("path"):x.get("git_blob_sha1") for x in
             source_manifest.get("sources",[])}
    require(listed==listed2 and len(listed)==3,
            "ORIGINAL_SOURCE_OBJECT_LIST_DIFFERS_FROM_FREEZE")
    verified=pinned_sources(source_checkout,validate_manifest(source_manifest))
    require(len(verified)==3,"GIT_OBJECTS_NOT_COVERED")
    actual_binary=sha_file(binary)
    require(is_hash(actual_binary),"INVALID_ARTIFACT_SHA256")
    records=[]
    for item,identity in ((a,"A"),(b,"B")):
        require(item.get("schema")==BUILDER and item.get("builder")==identity,
                "BUILDER_IDENTITY_INVALID")
        require(item.get("source_revision")==source["revision"] and
                item.get("source_repository")==source["repository"],
                "BUILD_SOURCE_REVISION_CONFLICT")
        require(item.get("source_blobs")==listed,
                "BUILD_USED_DIFFERENT_SOURCE_FILE_OBJECTS")
        require(item.get("go_version") == "go version "+build["toolchain"]+" linux/amd64",
                "GO_TOOLCHAIN_VERSION_MISMATCH")
        require(item.get("goos")==build["goos"] and
                item.get("goarch")==build["goarch"] and
                item.get("cgo_enabled")==build["cgo_enabled"] and
                item.get("target")==build["target"] and
                item.get("flags")==build["flags"],
                "BUILD_FLAGS_DIFFER_FROM_FREEZE")
        require(is_hash(item.get("binary_sha256")) and
                item["binary_sha256"]==actual_binary,
                "BUILD_BINARY_SHA256_DISAGREES_WITH_ARTIFACT")
        require(type(item.get("binary_bytes")) is int and
                item["binary_bytes"]==binary.stat().st_size,
                "BUILD_ARTIFACT_BYTE_COUNT_MISMATCH")
        require(type(item.get("github_run_id")) is int and item["github_run_id"]>0,
                "BUILD_RUN_ID_MISSING")
        require(type(item.get("github_job")) is str and item["github_job"],
                "BUILD_JOB_ID_MISSING")
        records.append(item)
    require(a["github_job"]!=b["github_job"],
            "TWO_BUILDERS_ARE_SAME_JOB")
    require(a["binary_sha256"]==b["binary_sha256"],
            "NON_REPRODUCIBLE_INDEPENDENT_BUILD")
    require(runtime.get("schema")==RUNTIME,"RUNTIME_WITNESS_SCHEMA_MISMATCH")
    require(runtime.get("source_revision")==source["revision"],
            "RUNTIME_DECLARED_SOURCE_WRONG")
    require(runtime.get("binary_sha256")==actual_binary,
            "RUNTIME_BINARY_NOT_BUILDER_ARTIFACT")
    require(runtime.get("selected_calls")==len(expected["expected_original_calls"]),
            "RUNTIME_CALL_DENOMINATOR_CHANGED")
    require(runtime.get("captured_calls")==runtime["selected_calls"],
            "RUNTIME_CAPTURE_INCOMPLETE")
    require(runtime.get("proc_pid") and type(runtime["proc_pid"]) is int,
            "MISSING_REAL_PROCESS_PID")
    require(runtime.get("proc_exe_sha256_before")==actual_binary and
            runtime.get("proc_exe_sha256_after")==actual_binary and
            runtime.get("disk_sha256_before")==actual_binary and
            runtime.get("disk_sha256_after")==actual_binary,
            "LIVE_PROCESS_IMAGE_NOT_BUILD_ARTIFACT")
    require(runtime.get("proc_device_inode_before")==
            runtime.get("proc_device_inode_after") and
            type(runtime.get("proc_device_inode_before")) is list and
            len(runtime["proc_device_inode_before"])==2,
            "LIVE_EXECUTABLE_IDENTITY_CHANGED")
    require(runtime.get("proc_exe_target") and type(runtime["proc_exe_target"]) is str,
            "MISSING_PROCESS_EXE_TARGET")
    require(runtime.get("attested_subject_sha256")==actual_binary,
            "RUNTIME_ATTESTED_SUBJECT_DIGEST_MISMATCH")
    require(runtime.get("binary_command_verified") is True,
            "ACTUAL_EXEC_ARGV_NOT_CHECKED")
    wire,trace_sha=_read_trace(trace)
    require(is_hash(runtime.get("trace_sha256")) and
            runtime["trace_sha256"]==trace_sha,
            "WIRE_RECORD_DISCONNECTED_FROM_PROCESS_WITNESS")
    calls,anomalies=correlate(wire)
    matched=[]
    for i,locked in enumerate(expected["expected_original_calls"]):
        call=[c for c in calls if c["name"]==locked["tool"] and
              c["args"]==locked["arguments"]]
        require(len(call)==1,"ORIGINAL_FIXED_CALL_MISSING_OR_REPLAYED")
        c=call[0]
        require(c["snapshot"] is not None and
                c["snapshot"]["complete_line"] < c["request_line"],
                "MISSING_CONTEMPORANEOUS_SOURCE_TOOL_CATALOG")
        require(type(c["response"]) is dict and
                c["response"].get("isError") in (False,None,True),
                "INVALID_TOOL_RESPONSE")
        matched.append({"call_index":i,"tool_hash":hashlib.sha256(
            locked["tool"].encode()).hexdigest()[:16],
            "request_line":c["request_line"],"response_line":c["response_line"],
            "catalog_sha256":c["snapshot"]["catalog_sha256"],
            "tool_error_reported":c["response"].get("isError",False)})
    require(len(calls)==len(matched),"UNDECLARED_EXTRA_TOOL_CALL")
    require(not anomalies,"UNMATCHED_OR_INCOMPLETE_MCP_MESSAGES")
    # A verification record produced by 'gh attestation verify' is an input
    # reported by CI; offline checker is NOT a Sigstore signature verifier.
    require(attestation.get("schema")=="risu-b18-gh-attestation-cli-result-v1",
            "EXTERNAL_ATTESTATION_RECORD_SCHEMA")
    require(attestation.get("verified") is True and
            attestation.get("subject_sha256")==actual_binary and
            attestation.get("attestation_repository")==frozen["signature"]["attesting_repository"] and
            attestation.get("signer_workflow")==frozen["signature"]["flow"],
            "ATTESTATION_CLI_RESULT_OR_SUBJECT_MISMATCH")
    require(attestation.get("verification_run_id")==runtime.get("verification_run_id") and
            type(runtime.get("verification_run_id")) is int,
            "ATTESTATION_VERIFICATION_RUN_DISCONNECTED")
    return {
        "schema":"risu-mcp-executed-runtime-corroboration-report-v1",
        "original_source_repository":source["repository"],
        "original_source_revision":source["revision"],
        "original_source_blobs_verified":len(verified),
        "binary_sha256":actual_binary,
        "original_trace_sha256":trace_sha,
        "summary":{
            "independent_builders":2,
            "identical_reproducible_binary":True,
            "live_proc_executable_matches_attested_artifact":True,
            "source_pinned_file_objects":3,
            "matched_original_native_calls":len(matched),
            "reported_verified_attestation_subject_matches":True,
            "source_to_binary_gap":"CI controlled build from checked-out publisher source; this product itself has no verified cryptographic remote builder attestation",
            "publisher_release_signed":"NOT_ESTABLISHED",
        },
        "calls":matched,
        "trust_boundary":"This offline tool checks consistency of CI-supplied witness data, source Git objects, original JSON-RPC bytes and artifact SHA256. It cannot independently sign or verify Sigstore certificates, authenticate /proc readings made in a separate process, attest against compromised CI, or prove the external publisher released/deployed this binary. Only the independently executed GitHub Actions attestation and verification workflow supply that external CI-builder assertion.",
    }


def cli(argv=None) -> int:
    p=argparse.ArgumentParser(prog="risu-probe verify-mcp-runtime")
    p.add_argument("trace",type=Path)
    p.add_argument("--source-checkout",required=True,type=Path)
    p.add_argument("--frozen-cohort",required=True,type=Path)
    p.add_argument("--source-manifest",required=True,type=Path)
    p.add_argument("--binary",required=True,type=Path)
    p.add_argument("--builder-a",required=True,type=Path)
    p.add_argument("--builder-b",required=True,type=Path)
    p.add_argument("--runtime-witness",required=True,type=Path)
    p.add_argument("--attestation-result",required=True,type=Path)
    p.add_argument("--out",type=Path)
    p.add_argument("--format",choices=("json","text"),default="text")
    try:
        a=p.parse_args(argv)
        result=inspect(a.trace,a.source_checkout,a.binary,json_file(a.frozen_cohort),
               json_file(a.source_manifest),json_file(a.builder_a),
               json_file(a.builder_b),json_file(a.runtime_witness),
               json_file(a.attestation_result))
        if a.format=="json":
            output=json.dumps(result,indent=2,sort_keys=True,ensure_ascii=False)+chr(10)
        else:
            output=("RISU B18 source/build/runtime: two independent build digests"
                    " + checked live process + original MCP trace corroborated"+chr(10))
        if a.out:
            with a.out.resolve().open("x",encoding="utf-8") as f:f.write(output)
        else:print(output,end="")
        return 0
    except (RuntimeOriginError,OriginError,TraceError,ValueError,TypeError,
            KeyError,UnicodeError,OSError,RecursionError) as e:
        print("RMR810 INCONSISTENT_OR_UNVERIFIED_BUILD_RUNTIME_EVIDENCE: "+
              type(e).__name__,file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(cli())
