"""Adversarial and legitimate controls for B37 native JSON-RPC error effect auditor."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parent))
from b37_protocol_error_effect_auditor import (
    EvidenceIncomplete, classify_tool_wire, audit_collected_execution,
    sha,
)


def wire(name="refusal",error=True,msg="VALIDATION_FAILED"):
    return {
      "request":{"jsonrpc":"2.0","id":3,
                 "method":"tools/call","params":{"name":name,"arguments":{}}},
      "response":{"jsonrpc":"2.0","id":3,
                  "result":{"content":[{"type":"text","text":msg}],
                            "isError":error}},
    }


class B37NativeEffectControls(unittest.TestCase):
    def test_error_as_success_detected_only_from_matching_original_native_pair(self):
        x=classify_tool_wire(wire(),"refusal",
                             {"outcome":"success","value":"VALIDATION_FAILED"})
        self.assertEqual(x,"APPLICATION_ERROR_AS_SUCCESS_CONFIRMED_IN_CONTROLLED_RUN")

    def test_error_as_error_is_preserved(self):
        x=classify_tool_wire(wire(),"refusal",
                             {"outcome":"mcp_tool_error","message":"VALIDATION_FAILED"})
        self.assertEqual(x,"APPLICATION_ERROR_PROPAGATED")

    def test_normal_tool_result_not_misclassified(self):
        x=classify_tool_wire(wire(name="normal",error=False,msg="OK"),
                             "normal",{"outcome":"success","value":"OK"})
        self.assertEqual(x,"NORMAL_SUCCESS_PRESERVED_STATUS")

    def test_genuine_jsonrpc_error_is_separate_from_application_error(self):
        entry=wire()
        entry["response"]={"jsonrpc":"2.0","id":3,
                           "error":{"code":-32603,"message":"downstream failure"}}
        x=classify_tool_wire(entry,"refusal",{
            "outcome":"mcp_tool_error","message":"downstream failure (code=-32603)"})
        self.assertEqual(x,"JSONRPC_ERROR_PRESERVED")

    def test_wrong_tool_identity_is_refused(self):
        with self.assertRaises(EvidenceIncomplete):
            classify_tool_wire(wire("refusal"),"another",{
                "outcome":"success","value":"VALIDATION_FAILED"})

    def test_wrong_request_and_response_id_is_refused(self):
        entry=wire()
        entry["response"]["id"]=100
        with self.assertRaises(EvidenceIncomplete):
            classify_tool_wire(entry,"refusal",{
                "outcome":"success","value":"VALIDATION_FAILED"})

    def test_error_projection_must_match_original_text(self):
        with self.assertRaises(EvidenceIncomplete):
            classify_tool_wire(wire(),"refusal",{
                "outcome":"success","value":"all good"})

    def test_mcp_error_status_must_be_boolean(self):
        entry=wire()
        entry["response"]["result"]["isError"]="true"
        with self.assertRaises(EvidenceIncomplete):
            classify_tool_wire(entry,"refusal",{
                "outcome":"success","value":"VALIDATION_FAILED"})

    def test_missing_result_is_not_counted_as_normal(self):
        entry=wire()
        entry["response"]={"jsonrpc":"2.0","id":3}
        with self.assertRaises(EvidenceIncomplete):
            classify_tool_wire(entry,"refusal",{
                "outcome":"success","value":"VALIDATION_FAILED"})

    def test_structured_only_channel_preservation_is_out_of_scope(self):
        entry=wire(name="normal",error=False,msg="irrelevant")
        entry["response"]["result"]={
           "content":[],"isError":False,
           "structuredContent":{"critical":"value"}
        }
        x=classify_tool_wire(entry,"normal",{
            "outcome":"success","value":""})
        self.assertEqual(x,"SUCCESS_STATUS_PRESERVED_OTHER_CHANNELS_UNASSESSED")

    def test_hash_bound_evidence_rejects_modified_wire(self):
        events=[
          {"request":{"jsonrpc":"2.0","id":1,"method":"tools/call",
                      "params":{"name":"normal"}},
           "response":{"jsonrpc":"2.0","id":1,
                       "result":{"content":[{"type":"text","text":"OK"}],
                                 "isError":False}}}
        ]*6
        data=("\n".join(json.dumps(x) for x in events)+"\n").encode()
        record={"before":{
             "original_raw_native_wire_sha256":sha(data),
             "original_client_imported_and_executed":True,
             "upstream_original_source_git_blob":"a"*40,
             "scenario_observations":{
                "normal":{"outcome":"success","value":"OK"},
                "refusal":{"outcome":"success","value":"OK"},
                "empty_refusal":{"outcome":"success","value":"OK"},
                "multi":{"outcome":"success","value":"OK"},
                "rpc_error":{"outcome":"success","value":"OK"},
                "normal_again":{"outcome":"success","value":"OK"},
             }},"after":{}}
        with self.assertRaisesRegex(EvidenceIncomplete,"HASH"):
            audit_collected_execution(record,{"before":data+b"x","after":b""})


if __name__=="__main__":
    unittest.main()
