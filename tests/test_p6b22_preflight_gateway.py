"""B22 synthetic adversarial gateway tests.

These use mocked OS-resource-owner *identity checks* to exercise crypto,
scope, prestate and nonce logic under the same interpreter UID. They are
NOT the two-account OS integration; GitHub Actions separately runs that
with actually different Linux UIDs and genuine original MCP processes.
"""
from __future__ import annotations
import argparse,asyncio,base64,copy,hashlib,json,os,tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from datetime import datetime,timezone,timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from risu_mcp_preflight import (
  verify_preflight,main_async,signature,canonical,digest,PREFIX,REV_PREFIX,
  ROOT_SCHEMA,GRANT_SCHEMA,REV_SCHEMA,Refused,file_state
)


def write(path,data):
    path.write_text(json.dumps(data,sort_keys=True,indent=2)+"\n")


def ztime(dt):
    return dt.isoformat(timespec="seconds").replace("+00:00","Z")


@unittest.skipUnless(os.name=="posix","P6B22 real resource guard supports POSIX only")
class TestB22Precall(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.dir=Path(t.name).resolve()
        self.owner=self.dir/"allowed"
        self.owner.mkdir()
        self.target=self.owner/"file.txt"
        self.key=Ed25519PrivateKey.generate()
        pub=self.key.public_key().public_bytes(
          serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        self.root={
          "schema":ROOT_SCHEMA,"issuer":"synthetic-os-fixture-owner",
          "owner_uid":os.geteuid()+10000,"executor_uid":os.geteuid(),
          "resource_dir":str(self.owner),"resource_id":"urn:risu-b22:fixture:file1",
          "key_id":digest(pub),"ed25519_public_key_b64":base64.b64encode(pub).decode(),
          "approved_tool":"write_file","server_module":"filesystem_mcp",
          "wheel_sha256":digest(b"synthetic wheel bytes"),
          "trust_level":"OS_UID_ISOLATED_FIXTURE_ONLY"}
        self.root_path=self.dir/"root.json"
        write(self.root_path,self.root)
        self.root_sha=digest(self.root_path.read_bytes())
        self.wheel=self.dir/"original_stub.whl"
        self.wheel.write_bytes(b"synthetic wheel bytes")
        self.request={
          "jsonrpc":"2.0","id":20,"method":"tools/call",
          "params":{"name":"write_file","arguments":{
            "path":str(self.target),"content":"synthetic safe payload\n","append":False}}}
        self.request_file=self.dir/"request.json"
        write(self.request_file,self.request)
        self.now=datetime.now(timezone.utc)
        self.policy={
          "audience":"risu-b22-unmodified-mcp-gateway",
          "issuer":self.root["issuer"],"owner_uid":self.root["owner_uid"],
          "executor_uid":self.root["executor_uid"],
          "resource_id":self.root["resource_id"],
          "resource_dir":str(self.owner),"target_path":str(self.target),
          "request_sha256":digest(canonical(self.request)),
          "original_tool":"write_file","server_module":"filesystem_mcp",
          "wheel_sha256":self.root["wheel_sha256"],
          "nonce":"a"*64,"issued_at":ztime(self.now-timedelta(seconds=3)),
          "expires_at":ztime(self.now+timedelta(minutes=3)),
          "pre_state_sha256":None,"allowed_operation":"CREATE",
          "desired_post_sha256":digest(b"synthetic safe payload\n")}
        self.grant_path=self.dir/"signed_grant.json"
        self.save_grant()
        self.rev_path=self.dir/"revocations.json"
        self.rev_body={"issuer":self.root["issuer"],"key_id":self.root["key_id"],
          "sequence":0,"published_at":ztime(self.now),"revoked_nonces":[]}
        self.save_rev()
        self.ledger=self.dir/"ledger"
        self.ledger.mkdir()
        self.ledger.chmod(0o700)

    def save_grant(self):
        data={"schema":GRANT_SCHEMA,"policy":self.policy,
            "signature_ed25519_b64":base64.b64encode(
                self.key.sign(PREFIX+canonical(self.policy))).decode()}
        write(self.grant_path,data)

    def save_rev(self):
        data={"schema":REV_SCHEMA,"revocations":self.rev_body,
              "signature_ed25519_b64":base64.b64encode(
                self.key.sign(REV_PREFIX+canonical(self.rev_body))).decode()}
        write(self.rev_path,data)
        self.rev_sha=digest(self.rev_path.read_bytes())

    def execute(self):
        with patch("risu_mcp_preflight.safe_directory",return_value=self.owner):
            return verify_preflight(
                self.request_file,self.grant_path,self.root_path,
                self.root_sha,self.rev_path,self.rev_sha,self.wheel,
                self.ledger,os.geteuid())

    def rejects(self):
        with self.assertRaises((Refused,FileExistsError,PermissionError,ValueError)):
            self.execute()

    def test_real_ed25519_signature_and_valid_exact_grant_allow(self):
        item=self.execute()
        self.assertEqual(item["predicted_direction"],"CREATE")
        self.assertTrue((self.ledger/("a"*64)).is_file())

    def test_missing_grant_denied(self):
        self.grant_path.unlink()
        self.rejects()

    def test_tampered_signature_denied(self):
        d=json.loads(self.grant_path.read_text())
        d["policy"]["allowed_operation"]="NO_CHANGE"
        write(self.grant_path,d)
        self.rejects()

    def test_forged_key_denied(self):
        other=Ed25519PrivateKey.generate()
        d=json.loads(self.grant_path.read_text())
        d["signature_ed25519_b64"]=base64.b64encode(
            other.sign(PREFIX+canonical(self.policy))).decode()
        write(self.grant_path,d)
        self.rejects()

    def test_revoked_signed_grant_denied(self):
        self.rev_body["revoked_nonces"]=["a"*64]
        self.rev_body["sequence"]=1
        self.save_rev()
        self.rejects()

    def test_stale_revocation_epoch_denied(self):
        self.rev_body["published_at"]=ztime(self.now-timedelta(days=1))
        self.save_rev()
        self.rejects()

    def test_wrong_out_of_band_root_sha_denied(self):
        self.root_sha="b"*64
        self.rejects()

    def test_grant_modified_signer_ownership_forgery_denied(self):
        self.policy["owner_uid"]+=5
        self.save_grant()
        self.rejects()

    def test_wrong_signed_actor_uid_denied(self):
        self.policy["executor_uid"]+=1
        self.save_grant()
        self.rejects()

    def test_unapproved_content_against_signed_request_denied(self):
        self.request["params"]["arguments"]["content"]="other payload"
        write(self.request_file,self.request)
        self.rejects()

    def test_unapproved_target_path_denied(self):
        self.request["params"]["arguments"]["path"]=str(self.owner/"other.txt")
        write(self.request_file,self.request)
        self.rejects()

    def test_path_traversal_refused(self):
        self.request["params"]["arguments"]["path"]=str(self.owner/".."/"other.txt")
        write(self.request_file,self.request)
        self.rejects()

    def test_wrong_tool_denied(self):
        self.request["params"]["name"]="read_file"
        write(self.request_file,self.request)
        self.rejects()

    def test_wrong_release_digest_denied(self):
        self.wheel.write_bytes(b"modified published archive")
        self.rejects()

    def test_intended_direction_not_signed_denied(self):
        self.policy["allowed_operation"]="NO_CHANGE"
        self.save_grant()
        self.rejects()

    def test_before_state_stale_denied(self):
        self.target.write_text("unexpected other writer")
        self.rejects()

    def test_expired_grant_denied(self):
        self.policy["expires_at"]=ztime(self.now-timedelta(seconds=1))
        self.save_grant()
        self.rejects()

    def test_postdated_grant_denied(self):
        self.policy["issued_at"]=ztime(self.now+timedelta(minutes=1))
        self.save_grant()
        self.rejects()

    def test_wrong_execution_software_module_denied(self):
        self.policy["server_module"]="untrusted_module"
        self.save_grant()
        self.rejects()

    def test_nonce_reuse_is_atomic_and_denied(self):
        self.execute()
        self.rejects()

    def test_unsafe_world_writable_replay_ledger_denied(self):
        self.ledger.chmod(0o777)
        self.rejects()

    def test_actual_os_dac_denial_checked_before_reserving_nonce(self):
        with patch("risu_mcp_preflight.os.access",return_value=False):
            self.rejects()
        self.assertFalse((self.ledger/("a"*64)).exists())

    def test_negative_preflight_does_not_spawn_any_original_server(self):
        self.policy["allowed_operation"]="NO_CHANGE"
        self.save_grant()
        output=self.dir/"denied_report.json"
        args=argparse.Namespace(request=str(self.request_file),grant=str(self.grant_path),
          trust_root=str(self.root_path),trusted_root_sha256=self.root_sha,
          revocations=str(self.rev_path),revocations_sha256=self.rev_sha,
          original_wheel=str(self.wheel),ledger=str(self.ledger),
          server_python="/does/not/exist",out=str(output))
        with patch("risu_mcp_preflight.safe_directory",return_value=self.owner),\
             patch("risu_mcp_preflight.run_original",side_effect=AssertionError("NOT CALLED")):
            result=asyncio.run(main_async(args))
        self.assertEqual(result,3)
        self.assertEqual(json.loads(output.read_text())["server_started"],False)
        self.assertFalse((self.ledger/("a"*64)).exists())

    def test_existing_target_exact_identical_is_normal_no_change(self):
        self.target.write_bytes(b"synthetic safe payload\n")
        self.policy["pre_state_sha256"]=digest(self.target.read_bytes())
        self.policy["allowed_operation"]="NO_CHANGE"
        self.save_grant()
        self.assertEqual(self.execute()["predicted_direction"],"NO_CHANGE")

    def test_existing_target_changed_means_replace_only(self):
        self.target.write_bytes(b"old contents")
        self.policy["pre_state_sha256"]=digest(self.target.read_bytes())
        self.policy["allowed_operation"]="REPLACE"
        self.save_grant()
        self.assertEqual(self.execute()["predicted_direction"],"REPLACE")

    def test_symlink_to_outside_directory_file_rejected(self):
        outside=self.dir/"other_person.txt"
        outside.write_text("not ours")
        self.target.symlink_to(outside)
        self.rejects()


if __name__=="__main__":unittest.main()
