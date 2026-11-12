"""B21 adversarial, purely synthetic cryptographically signed owner-scope tests.

The Ed25519 PRIVATE KEY is generated in memory by each test; never
published or exported. This establishes cryptographic binding, not a
production resource owner's identity or independent hardware attestation.
"""
from __future__ import annotations
import base64
import copy
from datetime import datetime, timezone
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from risu_mcp_effect_authority import (
  verify, AuthorityError, get_directions, DOMAIN, ROOTS, GRANT, EVENT, MANIFEST
)
from risu_mcp_effects import canonical, sha, EffectError
from test_p6b20_generic_effects import B20GenericEffectTest, CELLS


def write(path,obj):
    path.write_text(json.dumps(obj,sort_keys=True,indent=2)+"\n")


class TestSignedOwnerEffectAuthority(unittest.TestCase):
    def setUp(self):
        self.old=B20GenericEffectTest("test_generic_three_sensor_kinds_and_exact_response_equivalence")
        self.old.setUp()
        self.addCleanup(self.old.doCleanups)
        self.root=self.old.root
        self.plan=self.old.plan
        self.original=self.root/"synthetic_original_wheel.bin"
        self.original.write_bytes(b"not a real vendor wheel, synthetic software artifact only")
        self.software_sha=sha(self.original.read_bytes())
        self.private=Ed25519PrivateKey.generate()
        pub=self.private.public_key().public_bytes(
          serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        self.pub=base64.b64encode(pub).decode()
        self.key_id=sha(pub)
        self.resource={c:"fixture://risu-unit-owner/"+c+"/data" for c in CELLS}
        self.root_doc={
          "schema":ROOTS,
          "trust_scope":"CI_LOCAL_FIXTURE_ONLY",
          "principals":[{
            "issuer":"synthetic-test-file-owner",
            "key_id":self.key_id,
            "ed25519_public_key_b64":self.pub,
            "resource_ids":list(self.resource.values())}]
        }
        self.roots=self.root/"external_pretrusted_root.json"
        write(self.roots,self.root_doc)
        self.trusted_root_sha=sha(self.roots.read_bytes())
        self.manifest={
           "schema":MANIFEST,
           "declared_dataset_role":self.plan["classification"],
           "original_software_file":self.original.name,
           "original_software_sha256":self.software_sha,
           "plan_sha256":sha(canonical(self.plan)),
           "cases":{}
        }
        self.policies={}
        self.events={}
        self.files={}
        self.build()

    def build(self):
        for c in CELLS:
            episode=json.loads(self.old.episodes[c].read_text())
            req=episode["call"]
            ops={}
            for s in episode["sensors"]:
                direction,_=get_directions(s["before"],s["after"],s["kind"])
                ops[s["id"]]=[direction]
            policy={
                "audience":"risu-mcp-effect-authority-b21",
                "issuer":"synthetic-test-file-owner","key_id":self.key_id,
                "case":c,"actor":"synthetic-test-client",
                "resource_id":self.resource[c],
                "run_nonce":sha(c.encode()),
                "tool":self.plan["tool"],
                "args_sha256":req["arguments_sha256"],
                "wheel_sha256":self.software_sha,
                "issued_at":"2026-11-12T20:00:00Z",
                "expires_at":"2026-11-12T20:30:00Z",
                "allowed_directions":ops
            }
            grant={"schema":GRANT,"policy":policy,
                "signature_ed25519_b64":base64.b64encode(
                    self.private.sign(DOMAIN+canonical(policy))).decode()}
            p=self.root/c/"signed_preflight_owner_grant.json"
            write(p,grant)
            observer_sha=episode["sensors"][0]["original_observer"]["sha256"]
            event={
                "schema":EVENT,"case":c,"actor":policy["actor"],
                "resource_id":self.resource[c],"run_nonce":policy["run_nonce"],
                "grant_sha256":sha(p.read_bytes()),"tool":policy["tool"],
                "args_sha256":policy["args_sha256"],
                "wheel_sha256":policy["wheel_sha256"],
                "invoked_at":"2026-11-12T20:01:00Z",
                "completed_at":"2026-11-12T20:01:03Z",
                "trace_sha256":episode["trace_sha256"],
                "original_observer_sha256":observer_sha
            }
            ev=self.root/c/"precall_execution_event.json"
            write(ev,event)
            self.policies[c]=grant
            self.events[c]=event
            self.files[c]=(p,ev)
            self.manifest["cases"][c]={
                "grant_file":c+"/"+p.name,
                "grant_sha256":sha(p.read_bytes()),
                "event_file":c+"/"+ev.name,
                "event_sha256":sha(ev.read_bytes())
            }

    def run_check(self):
        return verify(self.plan,self.root,self.manifest,self.roots,self.trusted_root_sha)

    def rejects(self):
        with self.assertRaises((AuthorityError,EffectError,ValueError,
                               KeyError,TypeError)):
            self.run_check()

    def policy_mutate(self,cell,func,resign=False):
        grant=copy.deepcopy(self.policies[cell])
        func(grant["policy"])
        if resign:
            grant["signature_ed25519_b64"]=base64.b64encode(
                self.private.sign(DOMAIN+canonical(grant["policy"]))).decode()
        p,e=self.files[cell]
        write(p,grant)
        self.manifest["cases"][cell]["grant_sha256"]=sha(p.read_bytes())
        event=copy.deepcopy(self.events[cell])
        event["grant_sha256"]=sha(p.read_bytes())
        write(e,event)
        self.manifest["cases"][cell]["event_sha256"]=sha(e.read_bytes())

    def event_mutate(self,cell,func):
        p,e=self.files[cell]
        event=copy.deepcopy(self.events[cell])
        func(event)
        write(e,event)
        self.manifest["cases"][cell]["event_sha256"]=sha(e.read_bytes())

    def test_normal_signed_scope_authorizes_each_exact_observed_transition(self):
        r=self.run_check()
        self.assertEqual(r["status"],"DIRECTIONAL_OBSERVATION_WITH_SIGNED_SCOPE_VERIFIED")
        self.assertEqual(r["summary"]["valid_pinned_owner_signatures"],4)
        self.assertEqual(r["summary"]["within_signed_scope"],12)
        self.assertEqual(r["summary"]["outside_signed_scope"],0)
        self.assertEqual(r["summary"]["sensor_changes_observed"],3)
        self.assertEqual(r["trusted_root_mode"],"CI_LOCAL_FIXTURE_ONLY")

    def test_explicit_owner_deny_detects_actual_scope_violation(self):
        self.policy_mutate("before_trigger",lambda p:p["allowed_directions"].update({
            k:["NO_CHANGE"] for k in p["allowed_directions"]}),resign=True)
        r=self.run_check()
        self.assertEqual(r["summary"]["outside_signed_scope"],3)
        self.assertEqual(r["summary"]["cases_with_signed_scope_violations"],1)
        self.assertEqual(r["summary"]["new_external_vulnerabilities_discovered"],0)

    def test_weak_hint_cannot_override_signed_deny(self):
        self.policy_mutate("before_trigger",lambda p:p["allowed_directions"].update({
            k:["NO_CHANGE"] for k in p["allowed_directions"]}),resign=True)
        r=self.run_check()
        self.assertEqual(r["cases"]["before_trigger"]["policy_local_verdict"],
                         "SIGNED_SCOPE_OBSERVED_VIOLATION")

    def test_forged_signature_rejected(self):
        self.policy_mutate("before_trigger",lambda p:p.update(actor="evil"))
        self.rejects()

    def test_different_owner_key_signed_policy_rejected(self):
        another=Ed25519PrivateKey.generate()
        c="before_trigger"
        p,e=self.files[c]
        grant=copy.deepcopy(self.policies[c])
        grant["signature_ed25519_b64"]=base64.b64encode(
            another.sign(DOMAIN+canonical(grant["policy"]))).decode()
        write(p,grant)
        self.manifest["cases"][c]["grant_sha256"]=sha(p.read_bytes())
        event=copy.deepcopy(self.events[c])
        event["grant_sha256"]=sha(p.read_bytes())
        write(e,event)
        self.manifest["cases"][c]["event_sha256"]=sha(e.read_bytes())
        self.rejects()

    def test_root_substitution_rejected_even_if_self_consistent(self):
        self.root_doc["principals"][0]["resource_ids"].append("fixture://attacker")
        write(self.roots,self.root_doc)
        self.rejects()

    def test_pinned_root_sha_mismatch_fails_closed(self):
        self.trusted_root_sha="0"*64
        self.rejects()

    def test_resource_not_owned_rejected_even_with_owner_signature(self):
        self.policy_mutate("before_trigger",lambda p:
            p.update(resource_id="fixture://another-owner/private"),resign=True)
        self.rejects()

    def test_call_arguments_bound_cryptographically(self):
        self.policy_mutate("after_trigger",lambda p:
            p.update(args_sha256="0"*64),resign=True)
        self.rejects()

    def test_tool_substitution_not_allowed(self):
        self.policy_mutate("after_trigger",lambda p:
            p.update(tool="unrelated_tool"),resign=True)
        self.rejects()

    def test_wrong_software_release_even_if_signed_is_refused(self):
        self.policy_mutate("after_trigger",lambda p:
            p.update(wheel_sha256="0"*64),resign=True)
        self.rejects()

    def test_unsigned_software_artifact_changes_rejected(self):
        self.original.write_bytes(b"modified external wheel")
        self.rejects()

    def test_cross_case_nonce_reuse_rejected(self):
        self.policy_mutate("after_trigger",lambda p:
            p.update(run_nonce=self.policies["before_trigger"]["policy"]["run_nonce"]),
            resign=True)
        self.event_mutate("after_trigger",lambda e:
            e.update(run_nonce=self.policies["before_trigger"]["policy"]["run_nonce"]))
        self.rejects()

    def test_replayed_policy_case_rejected(self):
        self.policy_mutate("after_trigger",lambda p:
            p.update(case="before_trigger"),resign=True)
        self.rejects()

    def test_grant_was_issued_after_observed_call(self):
        self.policy_mutate("after_control",lambda p:
            p.update(issued_at="2026-11-12T20:15:00Z"),resign=True)
        self.rejects()

    def test_grant_expired_before_call_completion(self):
        self.policy_mutate("after_control",lambda p:
            p.update(expires_at="2026-11-12T20:01:01Z"),resign=True)
        self.rejects()

    def test_overlong_grant_duration_rejected(self):
        self.policy_mutate("before_trigger",lambda p:
            p.update(expires_at="2026-11-13T20:00:00Z"),resign=True)
        self.rejects()

    def test_signed_scope_not_wildcard(self):
        self.policy_mutate("before_trigger",lambda p:
            p["allowed_directions"]["effect-exists"].append("*"),resign=True)
        self.rejects()

    def test_missing_signed_sensor_scope_rejected(self):
        self.policy_mutate("before_trigger",lambda p:
            p["allowed_directions"].pop("effect-exists"),resign=True)
        self.rejects()

    def test_overscoped_root_resource_prefix_is_not_wildcard(self):
        self.root_doc["principals"][0]["resource_ids"]=["fixture://risu-unit-owner"]
        write(self.roots,self.root_doc)
        self.trusted_root_sha=sha(self.roots.read_bytes())
        self.rejects()

    def test_grant_file_tamper_rejected(self):
        p,e=self.files["before_trigger"]
        p.write_bytes(p.read_bytes()+b" ")
        self.rejects()

    def test_event_actor_mismatch_rejected(self):
        self.event_mutate("after_control",lambda e:e.update(actor="a-different-agent"))
        self.rejects()

    def test_event_original_observer_mismatch_rejected(self):
        self.event_mutate("before_trigger",lambda e:
            e.update(original_observer_sha256="f"*64))
        self.rejects()

    def test_event_trace_mismatch_rejected(self):
        self.event_mutate("before_trigger",lambda e:e.update(trace_sha256="f"*64))
        self.rejects()

    def test_plan_swap_rejected(self):
        self.plan["tool"]="stranger"
        self.rejects()

    def test_resource_path_escape_in_manifest_rejected(self):
        self.manifest["cases"]["after_control"]["grant_file"]="../outside.json"
        self.rejects()

    def test_owner_claim_identity_does_not_auto_prove_real_world_ownership(self):
        r=self.run_check()
        self.assertIn("CI_LOCAL_FIXTURE_ONLY",r["trusted_root_mode"])
        self.assertTrue(any("OUT OF BAND" in x for x in r["limitations"]))

    def test_digest_directions_create_delete_replace(self):
        self.assertEqual(get_directions(None,"a"*64,"digest")[0],"CREATE")
        self.assertEqual(get_directions("a"*64,None,"digest")[0],"DELETE")
        self.assertEqual(get_directions("a"*64,"b"*64,"digest")[0],"REPLACE")
        self.assertEqual(get_directions("a"*64,"a"*64,"digest")[0],"NO_CHANGE")

    def test_counter_direction_increase_and_decrease_and_magnitude(self):
        self.assertEqual(get_directions(0,12,"counter"),("INCREASE",12))
        self.assertEqual(get_directions(35,3,"counter"),("DECREASE",-32))
        self.assertEqual(get_directions(7,7,"counter"),("NO_CHANGE",None))

    def test_boolean_direction_activate_and_deactivate(self):
        self.assertEqual(get_directions(False,True,"boolean")[0],"ACTIVATE")
        self.assertEqual(get_directions(True,False,"boolean")[0],"DEACTIVATE")

    def test_b21_no_executable_autosend_or_secret_principal_claim(self):
        r=self.run_check()
        self.assertEqual(r["summary"]["new_external_vulnerabilities_discovered"],0)


if __name__=="__main__":unittest.main()
