"""B19 synthetic signed-release/effect-witness checks.

All fixture attestations are FAKE TEST DATA and never credited as actual
external publisher attestations. Real signatures are verified by the PyPI
official attestation client in separate CI before real comparison.
"""
from __future__ import annotations
import copy,hashlib,json,tempfile,unittest,zipfile
from pathlib import Path

from risu_mcp_signed_repair import inspect,B19Error,sha


def dump(value):
    return json.dumps(value,separators=(",",":"),ensure_ascii=False)+chr(10)


def meta():
    return {"schema":"risu-p6b19-signed-official-before-after-freeze-v1",
        "issue":{"id":"GHSA-6hqx-gqrx-c5r2"},
        "publisher":{"repository":"modelcontextprotocol/servers",
                     "release_workflow":".github/workflows/release.yml"},
        "versions":[
            {"id":"VULNERABLE","version":"2026.11.4","source_commit":"f"*40,
             "wheel":"mcp_server_git-2026.11.4-py3-none-any.whl",
             "wheel_sha256":"0"*64,"server_git_blob_sha1":"a"*40},
            {"id":"FIXED","version":"2026.11.11","source_commit":"e"*40,
             "wheel":"mcp_server_git-2026.11.11-py3-none-any.whl",
             "wheel_sha256":"0"*64,"server_git_blob_sha1":"b"*40}],
        "runtime":{"tool":"git_status","total_original_native_calls":4,
          "cases":[{"id":"CONFIGURED","marker_expected_by_version":{
            "2026.11.4":True,"2026.11.11":False}},
            {"id":"NORMAL","marker_expected_by_version":{
            "2026.11.4":False,"2026.11.11":False}}]}}


class B19SyntheticReview(unittest.TestCase):
    def setUp(self):
        d=tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.root=Path(d.name)
        self.freeze=meta()
        self.code=b"synthetic upstream module, no real PyPI code"
        self.csha=hashlib.sha256(self.code).hexdigest()
        for v in self.freeze["versions"]:
            base=self.root/v["id"]
            base.mkdir()
            whl=base/v["wheel"]
            with zipfile.ZipFile(whl,"w") as z:
                z.writestr("mcp_server_git/server.py",self.code)
            digest=sha(whl)
            v["wheel_sha256"]=digest
            pub={"schema":"risu-b19-upstream-pypi-publish-attestation-v1",
                "verified_by_pypi_attestations_cli":True,
                "publishing_repository":self.freeze["publisher"]["repository"],
                "publishing_commit":v["source_commit"],
                "publishing_workflow":self.freeze["publisher"]["release_workflow"],
                "package_version":v["version"],"wheel_filename":v["wheel"],
                "wheel_sha256":digest}
            (base/"publish_attestation_verified.json").write_text(dump(pub))
            source={"schema":"risu-b19-wheel-upstream-git-source-v1",
                "wheel_sha256":digest,"upstream_git_commit":v["source_commit"],
                "upstream_server_git_blob_sha1":v["server_git_blob_sha1"],
                "wheel_code_matches_original_git_source_bytes":True,
                "installed_code_matches_signed_wheel_bytes":True,
                "installed_code_sha256":self.csha,
                "original_source_code_sha256":self.csha}
            (base/"source_code_equivalence.json").write_text(dump(source))
            for case in ("CONFIGURED","NORMAL"):
                root=base/case
                root.mkdir()
                rp="/tmp/risu-b19-fixture/"+v["id"]+"/"+case
                wire=[
                {"jsonrpc":"2.0","id":1,"method":"initialize","params":{}},
                {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25"}},
                {"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}},
                {"jsonrpc":"2.0","id":2,"result":{"tools":[{
                    "name":"git_status","inputSchema":{"type":"object"}}]}},
                {"jsonrpc":"2.0","id":20,"method":"tools/call",
                 "params":{"name":"git_status","arguments":{"repo_path":rp}}},
                {"jsonrpc":"2.0","id":20,"result":{"isError":False,
                  "content":[{"type":"text","text":"Repository status: On branch main"}]}}]
                trace=root/"original_stdio.jsonl"
                trace.write_text("".join(dump(x) for x in wire))
                after=v["id"]=="VULNERABLE" and case=="CONFIGURED"
                witness={"schema":"risu-b19-real-native-effect-witness-v1",
                  "variant":v["id"],"case":case,
                  "source_version":v["version"],
                  "release_wheel_sha256":digest,
                  "installed_source_sha256":self.csha,
                  "isolated_python_runtime":True,"process_pid":10101,
                  "injected_config":case=="CONFIGURED",
                  "repository_path":rp,
                  "marker_before":False,"marker_after":after,
                  "marker_content_valid":True,
                  "trace_sha256":hashlib.sha256(trace.read_bytes()).hexdigest(),
                  "tool_result_iserror":False,"tool_status_text_present":True}
                (root/"original_effect_witness.json").write_text(dump(witness))

    def test_source_signed_behavior_pairing(self):
        r=inspect(self.root,self.freeze)
        self.assertTrue(r["summary"]["known_security_repair_reproduced"])
        self.assertEqual(r["summary"]["actual_native_mcp_calls_correlated"],4)
        self.assertEqual(r["summary"]["previously_unknown_upstream_defects_found"],0)

    def test_pre_attestation_missing_rejected(self):
        f=self.root/"VULNERABLE/publish_attestation_verified.json"
        f.unlink()
        with self.assertRaises(B19Error):inspect(self.root,self.freeze)

    def test_publisher_identity_mismatch_rejected(self):
        self.change("VULNERABLE/publish_attestation_verified.json","publishing_repository","stranger/unrelated")
        with self.assertRaises(B19Error):inspect(self.root,self.freeze)

    def test_publishing_commit_mismatch_rejected(self):
        self.change("FIXED/publish_attestation_verified.json","publishing_commit","0"*40)
        with self.assertRaises(B19Error):inspect(self.root,self.freeze)

    def test_unsigned_attestation_cannot_be_promoted(self):
        self.change("FIXED/publish_attestation_verified.json","verified_by_pypi_attestations_cli",False)
        with self.assertRaises(B19Error):inspect(self.root,self.freeze)

    def test_wheel_tamper_rejected(self):
        path=self.root/self.freeze["versions"][0]["id"]/self.freeze["versions"][0]["wheel"]
        with path.open("ab") as f:f.write(b"SYNTHETIC_TAMPER")
        with self.assertRaises(B19Error):inspect(self.root,self.freeze)

    def test_install_code_changed_rejected(self):
        self.change("FIXED/source_code_equivalence.json","installed_code_sha256","f"*64)
        with self.assertRaises(B19Error):inspect(self.root,self.freeze)

    def test_source_git_blob_changed_rejected(self):
        self.change("VULNERABLE/source_code_equivalence.json","upstream_server_git_blob_sha1","0"*40)
        with self.assertRaises(B19Error):inspect(self.root,self.freeze)

    def test_marker_before_mcp_call_rejected(self):
        self.change("VULNERABLE/CONFIGURED/original_effect_witness.json","marker_before",True)
        with self.assertRaises(B19Error):inspect(self.root,self.freeze)

    def test_changed_native_trace_hash_rejected(self):
        t=self.root/"VULNERABLE/CONFIGURED/original_stdio.jsonl"
        with t.open("a") as f:f.write(" ")
        with self.assertRaises((B19Error,ValueError)):inspect(self.root,self.freeze)

    def test_tool_failure_not_mistaken_for_fix(self):
        self.change("FIXED/CONFIGURED/original_effect_witness.json","tool_result_iserror",True)
        with self.assertRaises(B19Error):inspect(self.root,self.freeze)

    def test_clean_control_contamination_not_repair(self):
        self.change("FIXED/NORMAL/original_effect_witness.json","marker_after",True)
        r=inspect(self.root,self.freeze)
        self.assertFalse(r["summary"]["known_security_repair_reproduced"])

    def test_not_fixed_external_marker_no_success(self):
        self.change("FIXED/CONFIGURED/original_effect_witness.json","marker_after",True)
        r=inspect(self.root,self.freeze)
        self.assertFalse(r["summary"]["known_security_repair_reproduced"])

    def test_older_bug_absent_not_positive(self):
        self.change("VULNERABLE/CONFIGURED/original_effect_witness.json","marker_after",False)
        r=inspect(self.root,self.freeze)
        self.assertFalse(r["summary"]["known_security_repair_reproduced"])

    def test_missing_original_call_not_silent(self):
        t=self.root/"VULNERABLE/NORMAL/original_stdio.jsonl"
        raw=t.read_text().splitlines(keepends=True)
        t.write_text("".join(raw[:-2]))
        h=hashlib.sha256(t.read_bytes()).hexdigest()
        self.change("VULNERABLE/NORMAL/original_effect_witness.json","trace_sha256",h)
        with self.assertRaises(B19Error):inspect(self.root,self.freeze)

    def test_malicious_config_swapped_rejected(self):
        self.change("FIXED/CONFIGURED/original_effect_witness.json","injected_config",False)
        with self.assertRaises(B19Error):inspect(self.root,self.freeze)

    def test_duplicate_json_fields_rejected(self):
        t=self.root/"FIXED/publish_attestation_verified.json"
        t.write_text('{"schema":"bad","schema":"duplicate"}')
        with self.assertRaises(B19Error):inspect(self.root,self.freeze)

    def test_unknown_version_cannot_replace_heldout(self):
        self.freeze["versions"][1]["version"]="2026.11.12"
        with self.assertRaises(B19Error):inspect(self.root,self.freeze)

    def change(self,p,key,value):
        path=self.root/p
        d=json.loads(path.read_text())
        d[key]=value
        path.write_text(dump(d))


if __name__=="__main__":unittest.main()
