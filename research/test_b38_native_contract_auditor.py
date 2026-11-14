"""B38 native contract source-independent development controls. No B38 upstream."""
from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parent))
from b38_native_contract_auditor import (evaluate,audit_record,IncompleteEvidence,
                                          digest)


def case(*,is_error=False,content=None,structured=None,media=False,
         outcome="success",text=None,reported_structured=None,reported_media=None):
    parts=content if content is not None else [{"type":"text","text":"hello"}]
    if media:
        parts=[{"type":"image","data":"YQ==","mimeType":"image/png"}]
    result={"content":parts,"isError":is_error}
    if structured is not None:
        result["structuredContent"]=structured
    wire={"request":{"jsonrpc":"2.0","id":17,"method":"tools/call",
                     "params":{"name":"retrieve","arguments":{}}},
          "response":{"jsonrpc":"2.0","id":17,"result":result}}
    observed={"tool":"retrieve","request_id":17,"outcome":outcome}
    if text is not None:observed["text"]=text
    if reported_structured is not ...:observed["structured"]=reported_structured
    if reported_media is not ...:observed["media"]=reported_media
    return wire,observed


class NativeContractTests(unittest.TestCase):
    def test_b37_controlled_original_error_as_success_detected(self):
        wire,obs=case(is_error=True,outcome="success")
        x=evaluate(wire,obs,{"status":True})
        self.assertEqual(x["findings"],["APPLICATION_ERROR_AS_SUCCESS"])

    def test_b37_fixed_original_error_propagated(self):
        wire,obs=case(is_error=True,outcome="tool_error")
        x=evaluate(wire,obs,{"status":True})
        self.assertEqual(x["classification"],"OBSERVED_CONTRACT_PRESERVED")

    def test_normal_success_not_flagged(self):
        wire,obs=case(is_error=False,outcome="success")
        x=evaluate(wire,obs,{"status":True})
        self.assertEqual(x["findings"],[])

    def test_normal_misclassified_error_caught(self):
        wire,obs=case(is_error=False,outcome="tool_error")
        self.assertIn("MCP_STATUS_MISCLASSIFIED",
                      evaluate(wire,obs,{"status":True})["findings"])

    def test_text_preserved(self):
        wire,obs=case(text="hello")
        self.assertEqual(evaluate(wire,obs,{"status":True,"text":"exact"})["findings"],[])

    def test_text_explicitly_missing(self):
        wire,obs=case(text="")
        self.assertIn("MCP_TEXT_CHANGED",
                      evaluate(wire,obs,{"status":True,"text":"exact"})["findings"])

    def test_text_unobserved_must_be_incomplete_not_lost(self):
        wire,obs=case()
        with self.assertRaises(IncompleteEvidence):
            evaluate(wire,obs,{"status":True,"text":"exact"})

    def test_structured_only_is_lost_when_explicitly_absent(self):
        wire,obs=case(content=[],structured={"answer":3},reported_structured=None)
        out=evaluate(wire,obs,{"status":True,"structured":"exact"})
        self.assertIn("MCP_STRUCTURED_CONTENT_LOST_OR_CHANGED",out["findings"])

    def test_structured_only_is_preserved(self):
        wire,obs=case(content=[],structured={"answer":3},reported_structured={"answer":3})
        self.assertEqual(evaluate(wire,obs,{"status":True,"structured":"exact"})["findings"],[])

    def test_structured_unobserved_is_incomplete_not_missing(self):
        wire,obs=case(content=[],structured={"answer":3},reported_structured=...)
        with self.assertRaises(IncompleteEvidence):
            evaluate(wire,obs,{"status":True,"structured":"exact"})

    def test_do_not_infer_loss_when_channel_outside_contract(self):
        wire,obs=case(content=[],structured={"answer":3},reported_structured=None)
        x=evaluate(wire,obs,{"status":True,"structured":"none"})
        self.assertEqual(x["findings"],[])
        self.assertEqual(x["channels_tested"],["status"])

    def test_media_lost_with_preobserved_media_contract(self):
        wire,obs=case(media=True,reported_media=[])
        out=evaluate(wire,obs,{"status":True,"media":"exact"})
        self.assertEqual(out["findings"],["MCP_MEDIA_LOST_OR_CHANGED"])

    def test_media_preserved_by_exact_original_base64_digest(self):
        wire,obs=case(media=True,reported_media=[
          {"type":"image","base64_sha256":digest(b"YQ==")}
        ])
        out=evaluate(wire,obs,{"status":True,"media":"exact"})
        self.assertEqual(out["findings"],[])

    def test_media_not_measured_is_incomplete(self):
        wire,obs=case(media=True,reported_media=...)
        with self.assertRaises(IncompleteEvidence):
            evaluate(wire,obs,{"status":True,"media":"exact"})

    def test_protocol_id_collision_rejected(self):
        wire,obs=case()
        wire["response"]["id"]=999
        with self.assertRaisesRegex(IncompleteEvidence,"ID_MISMATCH"):
            evaluate(wire,obs,{"status":True})

    def test_observed_tool_mismatch_rejected(self):
        wire,obs=case()
        obs["tool"]="other"
        with self.assertRaisesRegex(IncompleteEvidence,"TOOL_IDENTITY"):
            evaluate(wire,obs,{"status":True})

    def test_observed_request_id_mismatch_rejected(self):
        wire,obs=case()
        obs["request_id"]=18
        with self.assertRaisesRegex(IncompleteEvidence,"REQUEST_IDENTITY"):
            evaluate(wire,obs,{"status":True})

    def test_native_error_flag_must_be_real_boolean(self):
        wire,obs=case()
        wire["response"]["result"]["isError"]="true"
        with self.assertRaises(IncompleteEvidence):
            evaluate(wire,obs,{"status":True})

    def test_explicit_contract_required(self):
        wire,obs=case()
        with self.assertRaises(IncompleteEvidence):
            evaluate(wire,obs,{})

    def test_unknown_channel_contract_refused(self):
        wire,obs=case()
        with self.assertRaises(IncompleteEvidence):
            evaluate(wire,obs,{"status":True,"text":"summarize"})

    def test_unknown_consumer_outcome_refused(self):
        wire,obs=case()
        obs["outcome"]="uncertain"
        with self.assertRaises(IncompleteEvidence):
            evaluate(wire,obs,{"status":True})

    def test_original_source_provenance_declared_not_assumed(self):
        wire,obs=case()
        rec={"wire":wire,"observed":obs,"contract":{"status":True},
             "execution_provenance":"ORIGINAL_EXTERNAL_CLIENT_CONTROLLED_SERVER"}
        with self.assertRaisesRegex(IncompleteEvidence,"SOURCE_GIT_BLOB"):
            audit_record(rec)
        rec["original_source_git_blob"]="a"*40
        with self.assertRaisesRegex(IncompleteEvidence,"COMMIT_NOT_VERIFIED"):
            audit_record(rec)
        rec["original_commit_verified"]=True
        x=audit_record(rec)
        self.assertEqual(x["execution_provenance"],
                         "ORIGINAL_EXTERNAL_CLIENT_CONTROLLED_SERVER")

    def test_first_party_control_is_not_external_original(self):
        wire,obs=case()
        x=audit_record({"wire":wire,"observed":obs,"contract":{"status":True},
                        "execution_provenance":"CONTROLLED_FIRST_PARTY"})
        self.assertFalse(x["third_party_original_runtime_claim"])

    def test_jsonrpc_error_status_kept_separate_from_tool_error(self):
        wire,obs=case()
        wire["response"]={"jsonrpc":"2.0","id":17,
                          "error":{"code":-32603,"message":"transport refused"}}
        obs["outcome"]="jsonrpc_error"
        obs["error_text"]="transport refused (code=-32603)"
        x=evaluate(wire,obs,{"status":True})
        self.assertEqual(x["classification"],"OBSERVED_CONTRACT_PRESERVED")
        self.assertEqual(x["channels_tested"],["status"])

    def test_jsonrpc_error_cannot_claim_unchanged_contents(self):
        wire,obs=case()
        wire["response"]={"jsonrpc":"2.0","id":17,
                          "error":{"code":-32603,"message":"failure"}}
        obs["outcome"]="success"
        self.assertIn("JSONRPC_ERROR_MISCLASSIFIED",
                      evaluate(wire,obs,{"status":True,"text":"exact"})["findings"])

    def test_unmeasured_media_and_structured_never_guessed_clean(self):
        wire,obs=case(media=True,structured={"a":1})
        x=evaluate(wire,obs,{"status":True})
        self.assertEqual(x["channels_tested"],["status"])
        self.assertEqual(x["findings"],[])


if __name__=="__main__":
    unittest.main()
