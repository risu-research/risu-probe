"""P6-B18: synthetic adversarial controls for executed build provenance checker.

No mocked control is counted as an external observed bug or an authentic
Sigstore verification. External runtime/attestation are checked in native CI.
"""
from __future__ import annotations
import copy, hashlib, json, subprocess, tempfile, unittest
from pathlib import Path

from risu_mcp_runtime_origin import (
    RuntimeOriginError, inspect, cli, sha_file, json_file
)
from risu_mcp_origin import OriginError

def encode(value):
    return json.dumps(value,separators=(",",":"),ensure_ascii=False)+chr(10)

class B18SyntheticProvenance(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.repo=self.root/"source"
        self.repo.mkdir()
        names=["examples/server/toolschemas/main.go","go.mod","go.sum"]
        for i,name in enumerate(names):
            p=self.repo/name
            p.parent.mkdir(parents=True,exist_ok=True)
            p.write_text("SYNTHETIC RISU B18 source artifact "+str(i)+chr(10),encoding="utf-8")
        def git(*args):
            return subprocess.check_output(["git","-C",str(self.repo),*args],
                stderr=subprocess.DEVNULL,text=True).strip()
        git("init","-q")
        git("add",".")
        git("-c","user.name=RISU Synthetic","-c","user.email=synthetic@invalid.example",
            "commit","-qm","synthetic local fixture")
        rev=git("rev-parse","HEAD")
        files=[{"path":path,"blob":git("rev-parse","HEAD:"+path)} for path in names]
        self.manifest={"schema":"risu-mcp-upstream-source-manifest-v1",
            "repository":"synthetic/local-go-server","revision":rev,
            "sources":[{"tool":"source-"+str(i),"path":f["path"],
                        "git_blob_sha1":f["blob"]} for i,f in enumerate(files)]}
        flags=["-trimpath","-buildvcs=false","-mod=readonly","-ldflags=-buildid="]
        tools=[("simple greeting",{"name":"RISU"}),
               ("manual greeting",{"name":"B18"}),
               ("manual greeting",{"name":"NAME_TOO_LONG_FOR_ORIGINAL_TOOL"}),
               ("unvalidated greeting",{"user":"B18"})]
        self.frozen={"schema":"risu-p6b18-executed-binary-predeclared-v1",
            "source":{"repository":self.manifest["repository"],
                      "revision":rev,"files":files},
            "build":{"toolchain":"go1.25.0","goos":"linux","goarch":"amd64",
                     "cgo_enabled":"0","target":"./examples/server/toolschemas",
                     "flags":flags},
            "runtime":{"expected_original_calls":[{"tool":name,"arguments":args}
                      for name,args in tools],"selected_count":4},
            "signature":{"attesting_repository":"risu-research/risu-probe",
             "flow":".github/workflows/p6b18-source-build-runtime.yml"}}
        self.binary=self.root/"built_binary"
        self.binary.write_bytes(b"Synthetic! Not actual executable.\x00")
        digest=sha_file(self.binary)
        base={"schema":"risu-b18-builder-evidence-v1",
              "github_run_id":111111,"source_repository":self.manifest["repository"],
              "source_revision":rev,
              "source_blobs":{f["path"]:f["blob"] for f in files},
              "go_version":"go version go1.25.0 linux/amd64",
              "goos":"linux","goarch":"amd64","cgo_enabled":"0",
              "target":"./examples/server/toolschemas","flags":flags,
              "binary_sha256":digest,"binary_bytes":self.binary.stat().st_size}
        self.a={**base,"builder":"A","github_job":"build-A"}
        self.b={**base,"builder":"B","github_job":"build-B"}
        lines=[]
        lines.extend([
         {"jsonrpc":"2.0","id":1,"method":"initialize","params":{}},
         {"jsonrpc":"2.0","id":1,"result":{"capabilities":{},"protocolVersion":"2025-11-25"}},
         {"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}},
         {"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":name,
             "inputSchema":{"type":"object"}} for name in sorted(set(x[0] for x in tools))]}}
        ])
        for i,(name,args) in enumerate(tools):
            lines.extend([
                {"jsonrpc":"2.0","id":20+i,"method":"tools/call",
                 "params":{"name":name,"arguments":args}},
                {"jsonrpc":"2.0","id":20+i,"result":{
                 "isError":i==2,
                 "content":[{"type":"text","text":"real-looking synthetic output"}]}}
            ])
        self.trace=self.root/"original_stdio.jsonl"
        self.trace.write_text("".join(encode(x) for x in lines),encoding="utf-8")
        self.witness={
            "schema":"risu-b18-runtime-procfs-evidence-v1",
            "source_revision":rev,"binary_sha256":digest,
            "selected_calls":4,"captured_calls":4,
            "proc_pid":31415,"proc_exe_target":str(self.binary.resolve()),
            "proc_exe_sha256_before":digest,"proc_exe_sha256_after":digest,
            "disk_sha256_before":digest,"disk_sha256_after":digest,
            "proc_device_inode_before":[1,2],"proc_device_inode_after":[1,2],
            "binary_command_verified":True,"attested_subject_sha256":digest,
            "verification_run_id":100001,
            "trace_sha256":hashlib.sha256(self.trace.read_bytes()).hexdigest()}
        self.attestation={
            "schema":"risu-b18-gh-attestation-cli-result-v1",
            "verified":True,"subject_sha256":digest,
            "attestation_repository":"risu-research/risu-probe",
            "signer_workflow":".github/workflows/p6b18-source-build-runtime.yml",
            "verification_run_id":100001}

    def run_check(self):
        return inspect(self.trace,self.repo,self.binary,self.frozen,self.manifest,
                       self.a,self.b,self.witness,self.attestation)

    def expect_rejected(self):
        with self.assertRaises((RuntimeOriginError,OriginError,ValueError)):
            self.run_check()

    def test_all_evidence_consistent_offline_not_authentic(self):
        r=self.run_check()
        self.assertEqual(r["summary"]["matched_original_native_calls"],4)
        self.assertEqual(r["summary"]["publisher_release_signed"],"NOT_ESTABLISHED")
        self.assertIn("not",r["trust_boundary"].lower())

    def test_actual_binary_byte_tamper_rejected(self):
        with self.binary.open("ab") as f:f.write(bytes([17]))
        self.expect_rejected()

    def test_builder_B_digest_mismatch_rejected(self):
        self.b["binary_sha256"]="a"*64
        self.expect_rejected()

    def test_builder_B_identity_not_independent(self):
        self.b["github_job"]=self.a["github_job"]
        self.expect_rejected()

    def test_unpinned_different_source_commit(self):
        self.manifest["revision"]="f"*40
        self.expect_rejected()

    def test_different_source_worktree_rejected(self):
        with (self.repo/"go.mod").open("a") as f:f.write("malicious")
        self.expect_rejected()

    def test_missing_source_blob_pin_rejected(self):
        self.manifest["sources"][0]["git_blob_sha1"]="0"*40
        self.expect_rejected()

    def test_runtime_wrong_image_pre(self):
        self.witness["proc_exe_sha256_before"]="0"*64
        self.expect_rejected()

    def test_runtime_wrong_image_post(self):
        self.witness["proc_exe_sha256_after"]="0"*64
        self.expect_rejected()

    def test_runtime_wrong_disk_after(self):
        self.witness["disk_sha256_after"]="0"*64
        self.expect_rejected()

    def test_runtime_pid_or_inode_change(self):
        self.witness["proc_device_inode_after"]=[1,3]
        self.expect_rejected()

    def test_attestation_false(self):
        self.attestation["verified"]=False
        self.expect_rejected()

    def test_wrong_attested_subject(self):
        self.attestation["subject_sha256"]="0"*64
        self.expect_rejected()

    def test_wrong_signer_repository(self):
        self.attestation["attestation_repository"]="malicious/wrong"
        self.expect_rejected()

    def test_wrong_signer_workflow(self):
        self.attestation["signer_workflow"]=".github/workflows/evil.yml"
        self.expect_rejected()

    def test_runtime_mismatched_attestation_run(self):
        self.attestation["verification_run_id"]+=1
        self.expect_rejected()

    def test_trace_rewrite_with_unchanged_digest(self):
        with self.trace.open("ab") as f:f.write(b" ")
        self.expect_rejected()

    def test_missing_predeclared_tool_call_response(self):
        rows=self.trace.read_text().splitlines(keepends=True)
        self.trace.write_text("".join(rows[:-1]))
        self.witness["trace_sha256"]=hashlib.sha256(self.trace.read_bytes()).hexdigest()
        self.expect_rejected()

    def test_no_continuous_catalog_before_calls(self):
        rows=[json.loads(x) for x in self.trace.read_text().splitlines()]
        rows=[x for x in rows if x.get("id")!=2]
        self.trace.write_text("".join(encode(x) for x in rows))
        self.witness["trace_sha256"]=hashlib.sha256(self.trace.read_bytes()).hexdigest()
        self.expect_rejected()

    def test_extra_undeclared_tool_call_not_silently_ignored(self):
        with self.trace.open("a") as f:
            f.write(encode({"jsonrpc":"2.0","id":87,"method":"tools/call",
                   "params":{"name":"unvalidated greeting","arguments":{"user":"EXTRA"}}}))
            f.write(encode({"jsonrpc":"2.0","id":87,"result":{"content":[]}}))
        self.witness["trace_sha256"]=hashlib.sha256(self.trace.read_bytes()).hexdigest()
        self.expect_rejected()

    def test_duplicate_json_evidence_keys_rejected(self):
        target=self.root/"invalid.json"
        target.write_text('{"verified":true,"verified":false}')
        with self.assertRaises(RuntimeOriginError):
            json_file(target)

if __name__=="__main__":
    unittest.main()
