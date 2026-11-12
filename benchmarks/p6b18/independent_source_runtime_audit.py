"""B18 independent source/build/attestation/live-process audit.

This auditor intentionally DOES NOT import RISU's runtime verifier. Original
external binary must be rebuilt on two distinct CI runners. This auditor
checks independent SHA, Git object, raw native MCP, signed workflow identity.
No user-provided witness can prove live process identity without its trusted
CI execution record. No claim of publisher-signed release is made.
"""
from __future__ import annotations
import argparse,hashlib,json,subprocess
from pathlib import Path

GIT_REV="328036ea2090c83f28c41a42ee4c9e5ec7393a4f"
SOURCE_REPO="modelcontextprotocol/go-sdk"
DIGEST="c11061e35013c28f273e92ed44ff8f76eb21f8d547a76c93c7b2840c8cc5ef8f"
SOURCE_FILES={
 "examples/server/toolschemas/main.go":"0a2cfbd214798cd094fbe63162e78e7cc5bcab33",
 "go.mod":"3287a95780c8160bdbb4554fb2f509ca369197a4",
 "go.sum":"c13454aad50d66edfca523be20fd9c230ff100c7"}
SIGNER="https://github.com/risu-research/risu-probe/.github/workflows/p6b18-source-build-runtime.yml"


def enforce(p,explanation):
    if not p:raise ValueError(explanation)


def sha(p):
    h=hashlib.sha256()
    with Path(p).open("rb") as f:
        for data in iter(lambda:f.read(1024*1024),b""):h.update(data)
    return h.hexdigest()


def read(p):return json.loads(Path(p).read_text("utf-8"))


def git(repo,*args):
    return subprocess.check_output(["git","-C",str(repo),*args],stderr=subprocess.DEVNULL).decode().strip()


def audit(original,binary_a,binary_b,checkout,attestation_path,independent_replay=None):
    frozen=read(original/"benchmarks/p6b18/FROZEN_SOURCE_BUILD_RUNTIME.json")
    runtime=read(original/".b18-live/runtime_witness.json")
    result=read(original/".b18-evidence/runtime_firstpass.json")
    tree=read(original/".b18-evidence/provider_tree.json")
    a=read(original/".b18-a/builder.json")
    b=read(original/".b18-b/builder.json")
    attest=read(attestation_path)
    wire_path=original/".b18-live/original_stdio.jsonl"
    real_sha=sha(wire_path)
    assert frozen["schema"]=="risu-p6b18-executed-binary-predeclared-v1"
    enforce(frozen["source"]["repository"]==SOURCE_REPO and
        frozen["source"]["revision"]==GIT_REV,"Source revision or publisher changed")
    enforce({x["path"]:x["blob"] for x in frozen["source"]["files"]}==SOURCE_FILES,
            "Original source file pins changed")
    enforce(git(checkout,"rev-parse","HEAD")==GIT_REV,
            "Independent checkout at wrong original source commit")
    source_digests={}
    for path,expected in SOURCE_FILES.items():
        oid=git(checkout,"rev-parse",GIT_REV+":"+path)
        enforce(oid==expected,"Pinned Git tree differs from source")
        raw=subprocess.check_output(["git","-C",str(checkout),"cat-file","blob",oid])
        computed=hashlib.sha1(b"blob "+str(len(raw)).encode()+bytes([0])+raw).hexdigest()
        enforce(computed==expected,"Git blob contents do not match")
        source_digests[path]=hashlib.sha256(raw).hexdigest()
    enforce(tree["verified_against_publisher_remote_tree"] is True
        and tree["full_revision"]==GIT_REV,"No remote original publisher tree evidence")
    enforce({x["path"]:x["file_sha256"] for x in tree["source_blobs"]}==source_digests,
            "Recomputed original source digests differ from firstpass provider lookup")
    enforce(sha(binary_a)==sha(binary_b)==DIGEST,
            "Independent compiled bytes differ from original signed image")
    enforce(a["builder"]=="A" and b["builder"]=="B" and
            a["github_job"]!=b["github_job"] and
            a["github_run_id"]==b["github_run_id"]==43304077747 and
            a["binary_sha256"]==b["binary_sha256"]==DIGEST,
            "Original two independent source-build records disagree")
    enforce(a["go_version"]==b["go_version"]=="go version go1.25.0 linux/amd64"
            and a["flags"]==b["flags"]==frozen["build"]["flags"],
            "Original toolchain or build flags differ")
    enforce(type(attest) is list and len(attest)>0,
            "No independently verified Sigstore statement")
    certificate=attest[0]["verificationResult"]["signature"]["certificate"]
    statement=attest[0]["verificationResult"]["statement"]
    enforce(statement["_type"]=="https://in-toto.io/Statement/v1" and
            statement["predicateType"]=="https://slsa.dev/provenance/v1",
            "Original signer statement type changed")
    subjects=statement["subject"]
    enforce(any(x.get("name")=="mcp-toolschemas" and
            x.get("digest",{}).get("sha256")==DIGEST for x in subjects),
            "Attestation subject not exact original executed binary")
    enforce(certificate["githubWorkflowRepository"]=="risu-research/risu-probe"
            and certificate["buildSignerURI"].startswith(SIGNER+"@refs/heads/qualification/p6b18-")
            and certificate["runnerEnvironment"]=="github-hosted",
            "Sigstore verified signer is not frozen RISU qualification workflow")
    enforce("/runs/43304077747/" in certificate["runInvocationURI"],
            "Signature does not link to original GitHub build run")
    enforce(certificate["sourceRepositoryURI"]=="https://github.com/risu-research/risu-probe",
            "Attestation falsely claims upstream source as signing repo")
    enforce(attest[0]["verificationResult"]["verifiedTimestamps"][0]["type"]=="Tlog",
            "No Sigstore transparency-log verified time")
    enforce(runtime["status"]=="CAPTURED_ORIGINAL_GO_BINARY" and
            runtime["trace_sha256"]==real_sha==result["original_trace_sha256"],
            "Original captured wire does not match signed build witness")
    for name in ("binary_sha256","attested_subject_sha256","proc_exe_sha256_before",
            "proc_exe_sha256_after","disk_sha256_before","disk_sha256_after"):
        enforce(runtime[name]==DIGEST,"Original live executable differs: "+name)
    enforce(runtime["proc_device_inode_before"]==
            runtime["proc_device_inode_after"] and runtime["proc_pid"]>1,
            "Live process image identity changed")
    enforce(runtime["start_cmdline"]==runtime["end_cmdline"]==
            [runtime["proc_exe_target"]],
            "Executed program command line changed or differs from /proc/exe target")
    lines=[json.loads(l) for l in wire_path.read_text().splitlines()]
    requests={v["id"]:(i,v) for i,v in enumerate(lines,1) if
              v.get("method")=="tools/call" and "id" in v}
    replies={v["id"]:(i,v) for i,v in enumerate(lines,1) if
             "id" in v and v.get("method") is None}
    expected=frozen["runtime"]["expected_original_calls"]
    enforce(len(requests)==len(expected)==4,"Original frozen call denominator changed")
    truth=[
      ("simple greeting",{"name":"RISU"},"Hi RISU",False),
      ("manual greeting",{"name":"B18"},"Hi B18",False),
      ("manual greeting",{"name":"NAME_TOO_LONG_FOR_ORIGINAL_TOOL"},None,True),
      ("unvalidated greeting",{"user":"B18"},"Hi B18",False)
    ]
    for i,(tool,args,answer,error) in enumerate(truth):
        req,resp=requests[20+i],replies[20+i]
        enforce(req[0]<resp[0] and req[1]["params"]=={"name":tool,"arguments":args},
                "Original submitted MCP tool call not prelocked")
        data=resp[1]["result"]
        enforce(bool(data.get("isError",False)) is error,
                "Original server changed success/failure behavior")
        if error:
            enforce("invalid input:" in data["content"][0]["text"] and
                    "maxLength" in data["content"][0]["text"],
                    "Original invalid input refusal missing")
        elif i<2:
            enforce(data.get("structuredContent")=={"greeting":answer},
                    "Original structured greeting changed")
            enforce(json.loads(data["content"][0]["text"])=={"greeting":answer},
                    "Original text/structured dual content inconsistency")
        else:
            enforce(data["content"][0]["text"]==answer,
                    "Original permissive text greeting changed")
    enforce(result["summary"]["identical_reproducible_binary"] is True and
        result["summary"]["live_proc_executable_matches_attested_artifact"] is True and
        result["summary"]["matched_original_native_calls"]==4,
        "Original B18 product report no longer matches independently read wire")
    result2=None
    if independent_replay is not None:
        witness=read(independent_replay/"runtime_witness.json")
        enforce(witness["status"]=="CAPTURED_ORIGINAL_GO_BINARY" and
                witness["captured_calls"]==4 and
                witness["binary_sha256"]==DIGEST and
                witness["proc_exe_sha256_before"]==DIGEST and
                witness["proc_exe_sha256_after"]==DIGEST,
                "Second independently launched server not original compiled binary")
        w2=independent_replay/"original_stdio.jsonl"
        rows2=[json.loads(l) for l in w2.read_text().splitlines()]
        # JSON-RPC source results for this deterministic fixture must match
        # across original builder-A and independent builder-B binaries.
        tool_replies={v["id"]:v for v in rows2
                      if "id" in v and v.get("method") is None and v["id"]>=20}
        enforce(len(tool_replies)==4,"Independent replay lost tool responses")
        for rid in range(20,24):
            enforce(tool_replies[rid]==replies[rid][1],
                    "Replayed externally built Go MCP output changed")
        result2={"original_builder_B_executed_separately":True,
                 "replay_live_binary_sha256":DIGEST,
                 "second_original_trace_sha256":sha(w2),
                 "four_semantically_identical_original_response_objects":True}
    return {
      "schema":"risu-b18-independent-source-build-live-image-audit-v1",
      "upstream_source_commit":GIT_REV,
      "remote_provider_source_objects_checked":len(source_digests),
      "recomputed_original_binary_sha256":DIGEST,
      "independent_build_runner_hashes_equal":True,
      "github_actions_signer_cryptographically_verified_externally":True,
      "original_sigstore_transparency_log_timestamp_checked":True,
      "source_to_binary_provenance":"RISU signed CI build from pinned external source",
      "live_elf_procfs_image_witness_consistent":True,
      "actual_original_native_mcp_calls_checked":4,
      "actual_original_mcp_defects_found":0,
      "second_independent_process_execution":result2,
      "limitations":[
        "GitHub Actions attestation authenticates RISU's CI build, not an official external publisher release.",
        "The offline JSON witness does not cryptographically attest the process PID; trust depends on independently audited CI process measurement.",
        "A compromised runner, dependency cache, Go compiler or GitHub infrastructure is outside the test threat model.",
        "The source code and its dependencies may still contain flaws, and one source-informed normal server cannot establish bug discovery recall."
      ]
    }


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--original",required=True,type=Path)
    p.add_argument("--builder-a-binary",required=True,type=Path)
    p.add_argument("--builder-b-binary",required=True,type=Path)
    p.add_argument("--source",required=True,type=Path)
    p.add_argument("--signed-proof",required=True,type=Path)
    p.add_argument("--replay",type=Path)
    p.add_argument("--out",required=True,type=Path)
    args=p.parse_args()
    data=audit(args.original,args.builder_a_binary,args.builder_b_binary,
               args.source,args.signed_proof,args.replay)
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(data,indent=2,sort_keys=True,ensure_ascii=False)+chr(10))
    print("B18_SECONDARY_INDEPENDENT_ORIGINAL_BINARY_AUDIT",json.dumps({
      "source_files":data["remote_provider_source_objects_checked"],
      "original_calls":data["actual_original_native_mcp_calls_checked"],
      "replayed":bool(data["second_independent_process_execution"]),
      "upstream_bugs":data["actual_original_mcp_defects_found"]},sort_keys=True))


if __name__=="__main__":
    main()
