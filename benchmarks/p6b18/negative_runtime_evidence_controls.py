"""B18 adversarial replay against frozen executable-origin inspector.

Mutations are LOCAL SYNTHETIC COUNTERFACTUALS applied to immutable firstpass
evidence. Never count a mutation as a newly detected third-party defect.
"""
from __future__ import annotations
import argparse,copy,hashlib,json,tempfile
from pathlib import Path

from risu_mcp_runtime_origin import inspect,RuntimeOriginError
from risu_mcp_origin import OriginError
from risu_mcp_trace import TraceError

def read(path):return json.loads(path.read_text("utf-8"))

def run(original,checkout,binary_a,binary_b,attestation,out):
    root=original
    frozen=read(root/"benchmarks/p6b18/FROZEN_SOURCE_BUILD_RUNTIME.json")
    source=read(root/"benchmarks/p6b18/SOURCE_GIT_OBJECT_MANIFEST.json")
    build_a=read(root/".b18-a/builder.json")
    build_b=read(root/".b18-b/builder.json")
    witness=read(root/".b18-live/runtime_witness.json")
    signed=read(attestation)
    trace=root/".b18-live/original_stdio.jsonl"
    result=inspect(trace,checkout,binary_a,frozen,source,
                   build_a,build_b,witness,signed)
    assert result["summary"]["matched_original_native_calls"]==4

    negatives=[]
    def candidate(label,modifier,custom_binary=None,custom_trace=None,change_source=False):
        f=copy.deepcopy(frozen);p=copy.deepcopy(source);a=copy.deepcopy(build_a)
        b=copy.deepcopy(build_b);w=copy.deepcopy(witness);s=copy.deepcopy(signed)
        modifier(f,p,a,b,w,s)
        testfile=custom_binary if custom_binary else binary_a
        testtrace=custom_trace if custom_trace else trace
        preserved=None
        target=None
        if change_source:
            target=checkout/"examples/server/toolschemas/main.go"
            preserved=target.read_bytes()
            target.write_bytes(preserved+b"\n// SYNTHETIC_UNCOMMITTED_TAMPER\n")
        try:
            try:
                inspect(testtrace,checkout,testfile,f,p,a,b,w,s)
            except (RuntimeOriginError,OriginError,TraceError,ValueError,
                    TypeError,KeyError,UnicodeError,OSError,RecursionError) as e:
                negatives.append({"case":label,"result":"REJECTED",
                    "exception":type(e).__name__,
                    "synthetic_not_real_upstream_bug":True})
            else:
                raise AssertionError("INVALID_EVIDENCE_ACCEPTED: "+label)
        finally:
            if preserved is not None:
                target.write_bytes(preserved)
    with tempfile.TemporaryDirectory(prefix="b18-counterfacts-") as d:
        scratch=Path(d)
        fake_binary=scratch/"mutated_mcp_toolschemas"
        fake_binary.write_bytes(binary_a.read_bytes()+b"synthetic-edit")
        trace_file=scratch/"mutated_original_stdio.jsonl"
        trace_file.write_bytes(trace.read_bytes()+b"\n")
        candidate("changed_executable_binary",lambda *x:None,custom_binary=fake_binary)
        candidate("changed_binary_digest_in_builder_B",
                  lambda f,p,a,b,w,s:b.update(binary_sha256="0"*64))
        candidate("duplicated_builder_identity",
                  lambda f,p,a,b,w,s:b.update(github_job=a["github_job"]))
        candidate("wrong_compilation_toolchain",
                  lambda f,p,a,b,w,s:b.update(go_version="go version go1.26.0 linux/amd64"))
        candidate("wrong_upstream_commit_claim",
                  lambda f,p,a,b,w,s:p.update(revision="0"*40))
        candidate("wrong_go_source_blob_claim",
                  lambda f,p,a,b,w,s:p["sources"][0].update(git_blob_sha1="0"*40))
        candidate("source_worktree_content_tamper",
                  lambda *x:None,change_source=True)
        candidate("different_live_proc_image_before",
                  lambda f,p,a,b,w,s:w.update(proc_exe_sha256_before="0"*64))
        candidate("different_live_proc_image_after",
                  lambda f,p,a,b,w,s:w.update(proc_exe_sha256_after="0"*64))
        candidate("replaced_proc_inode",
                  lambda f,p,a,b,w,s:w.update(proc_device_inode_after=[0,0]))
        candidate("unverified_claimed_attestation",
                  lambda f,p,a,b,w,s:s.update(verified=False))
        candidate("different_signed_artifact_subject",
                  lambda f,p,a,b,w,s:s.update(subject_sha256="0"*64))
        candidate("wrong_attested_signer_workflow",
                  lambda f,p,a,b,w,s:s.update(signer_workflow=".github/workflows/evil.yml"))
        candidate("wrong_attested_signer_repository",
                  lambda f,p,a,b,w,s:s.update(attestation_repository="unknown/foreign"))
        candidate("different_attestation_verification_run",
                  lambda f,p,a,b,w,s:s.update(verification_run_id=w["verification_run_id"]+1))
        candidate("rewritten_original_mcp_stdout",
                  lambda *x:None,custom_trace=trace_file)
        assert len(negatives)==16
        assert all(v["result"]=="REJECTED" for v in negatives)
        assert hashlib.sha256(trace.read_bytes()).hexdigest()==witness["trace_sha256"]
        assert hashlib.sha256(binary_a.read_bytes()).hexdigest()==build_a["binary_sha256"]
        assert binary_a.read_bytes()==binary_b.read_bytes()

    record={
       "schema":"risu-b18-original-evidence-mutation-audit-v1",
       "original_external_server":"modelcontextprotocol/go-sdk original toolschemas example",
       "original_source_revision":frozen["source"]["revision"],
       "original_original_trace_sha256":witness["trace_sha256"],
       "original_binary_sha256":build_a["binary_sha256"],
       "original_real_upstream_defects":0,
       "synthetic_mutation_denominator":len(negatives),
       "synthetic_mutations_rejected":sum(x["result"]=="REJECTED" for x in negatives),
       "original_evidence_preserved":True,
       "counterfactuals":negatives,
       "disclaimer":"All negative cases are deliberate postfreeze evidence edits, not actual upstream defects. This local inspector trusts a separately produced attestation-verification record; actual cryptographic verification was performed by gh CLI in independent GitHub Actions."
    }
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(record,indent=2,sort_keys=True,ensure_ascii=False)+chr(10))
    print("B18_SYNTHETIC_RUNTIME_PROVENANCE_MUTATIONS",record["synthetic_mutations_rejected"],
          "/",record["synthetic_mutation_denominator"])

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--original",required=True,type=Path)
    p.add_argument("--checkout",required=True,type=Path)
    p.add_argument("--binary-a",required=True,type=Path)
    p.add_argument("--binary-b",required=True,type=Path)
    p.add_argument("--attestation",required=True,type=Path)
    p.add_argument("--out",required=True,type=Path)
    a=p.parse_args()
    run(a.original,a.checkout,a.binary_a,a.binary_b,a.attestation,a.out)

if __name__=="__main__":main()
