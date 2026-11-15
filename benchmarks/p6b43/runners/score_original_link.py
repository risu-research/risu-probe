#!/usr/bin/env python3
"""P6-B43 research-only original agent MCP native-to-terminal link rule.

Predeclared LINK-1: do not invent cross-protocol identity, terminal persistence,
or actual business effects. This evaluator is independent of original source.
It can also run unchanged frozen B38 on explicitly observed native+consumer
status in a controlled unique-tool run, but this is NOT an original stable-ID
proof. First-party historical fix was selected from metadata.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

BLOBS={"before":"eb153d44c9d0cf9c2dafefe36e046c1d17812454",
       "after":"1e3a3fd5ba1cbab962f69883789dc725c1a26a0a"}
OUTCOME={"failed":"tool_error","completed":"success"}
TARGET_COMMIT={"before":"39d8fa2a8cf0a710d192720daf966fd68b6eaf26",
               "after":"2c87d801ef4779f7e4344c287f3feb9f4b0be054"}
VALID_KINDS={"success","tool_error"}
def link_one(rec):
    req=rec.get("original_native_request")
    resp=rec.get("original_native_reply")
    if not isinstance(req,dict) or not isinstance(resp,dict):
        return {"classification":"INCOMPLETE","reason":"NATIVE_REQUEST_RESPONSE_NOT_OBSERVED"}
    if req.get("method")!="tools/call" or req.get("jsonrpc")!="2.0" or resp.get("id")!=req.get("id"):
        return {"classification":"INCOMPLETE","reason":"NATIVE_REQUEST_ID_NOT_MATCHED"}
    result=resp.get("result")
    if not isinstance(result,dict) or type(result.get("isError",False)) is not bool:
        return {"classification":"INCOMPLETE","reason":"NATIVE_INBAND_TOOL_STATUS_ABSENT"}
    if not rec.get("original_agent_tool_call_id"):
        return {"classification":"INCOMPLETE","reason":"AGENT_TOOL_CALL_ID_MISSING"}
    if rec.get("original_agent_terminal_count")!=1:
        return {"classification":"INCOMPLETE","reason":"EXACTLY_ONE_ORIGINAL_TERMINAL_UNPROVEN"}
    status=rec.get("original_agent_terminal_status")
    if status not in ("failed","completed"):
        return {"classification":"INCOMPLETE","reason":"ORIGINAL_TERMINAL_STATUS_UNEXPOSED"}
    original_link=rec.get("original_wire_to_model_tool_id_in_band_link") is True
    persistent=rec.get("original_persistent_receipt") is True
    source_matches=req.get("params",{}).get("name")==rec.get("tool")
    if not source_matches:
        return {"classification":"INCOMPLETE","reason":"NATIVE_TOOL_NAME_MISMATCH"}
    native_kind="tool_error" if result.get("isError",False) else "success"
    app_kind=OUTCOME[status]
    functional="FUNCTIONAL_STATUS_CONTRADICTION" if native_kind!=app_kind else "FUNCTIONAL_STATUS_PRESERVED"
    return {"classification": "STRONG_LINK_PRESERVED" if original_link and persistent and functional=="FUNCTIONAL_STATUS_PRESERVED" else
             "STRONG_LINK_DISCREPANCY" if original_link and persistent and functional!="FUNCTIONAL_STATUS_PRESERVED" else
             "LINK_INCOMPLETE",
            "functional_status_test_under_unique_tool_scenario":functional,
            "wire_request_id":req["id"],
            "original_agent_tool_call_id":rec["original_agent_tool_call_id"],
            "native_kind":native_kind,
            "original_agent_terminal":status,
            "original_emitted_wire_to_agent_id_mapping":original_link,
            "original_persistent_terminal_receipt":persistent,
            "original_app_terminal_count":1,
            "original_native_tool_name":rec["tool"],
            "identity_strength":"ORIGINAL_PERSISTENT_LINK" if original_link and persistent else "FUNCTIONAL_CAUSAL_UNIQUE_TOOL_ONLY",
            "no_business_effect_proof":True,
            "no_deployed_agent_claim":True}

def selftest():
    req={"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"single"}}
    resp={"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"denied"}],"isError":True}}
    base={"tool":"single","original_native_request":req,"original_native_reply":resp,
          "original_agent_tool_call_id":"agent-9","original_agent_terminal_count":1,
          "original_agent_terminal_status":"failed","original_wire_to_model_tool_id_in_band_link":False,
          "original_persistent_receipt":False}
    preserved=link_one(base)
    assert preserved["classification"]=="LINK_INCOMPLETE"
    assert preserved["functional_status_test_under_unique_tool_scenario"]=="FUNCTIONAL_STATUS_PRESERVED"
    wrong=link_one({**base,"original_agent_terminal_status":"completed"})
    assert wrong["classification"]=="LINK_INCOMPLETE"
    assert wrong["functional_status_test_under_unique_tool_scenario"]=="FUNCTIONAL_STATUS_CONTRADICTION"
    assert link_one({**base,"original_agent_terminal_count":0})["classification"]=="INCOMPLETE"
    assert link_one({**base,"original_native_reply":{**resp,"id":4}})["classification"]=="INCOMPLETE"
    assert link_one({**base,"original_agent_terminal_count":2})["classification"]=="INCOMPLETE"
    strong=link_one({**base,"original_wire_to_model_tool_id_in_band_link":True,"original_persistent_receipt":True})
    assert strong["classification"]=="STRONG_LINK_PRESERVED"
    assert link_one({**base,"original_wire_to_model_tool_id_in_band_link":True,"original_persistent_receipt":True,"original_agent_terminal_status":"completed"})["classification"]=="STRONG_LINK_DISCREPANCY"
    print("B43_LINK_PRESPEC_NEGATIVE_POSITIVE_SELFTESTS_PASSED_7")

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--before",type=Path)
    p.add_argument("--after",type=Path)
    p.add_argument("--b38",type=Path)
    p.add_argument("--output",type=Path)
    p.add_argument("--selftest",action="store_true")
    args=p.parse_args()
    if args.selftest:
        selftest()
        if not args.before:return
    for k in ("before","after","b38","output"):
        if getattr(args,k) is None:p.error("missing --"+k)
    spec=importlib.util.spec_from_file_location("b38",args.b38)
    b38=importlib.util.module_from_spec(spec);spec.loader.exec_module(b38)
    results=[]
    for phase in ("before","after"):
        orig=json.loads(getattr(args,phase).read_text())
        assert orig["phase"]==phase
        assert orig["original_commit"]==TARGET_COMMIT[phase]
        assert orig["original_source_unmodified"] is True
        assert orig["original_MCPClient_native_sdk_and_acp_all_executed"] is True
        assert orig["native_stdIO_serialized_transport"] is True
        assert orig["original_cross_boundary_id_link_available"] is False
        assert orig["durable_completion_record_available"] is False
        rows=orig["records"]
        assert len(rows)==2 and {r["tool"] for r in rows}=={"b43_denied","b43_success"}
        for item in rows:
            req=item["original_native_request"]
            resp=item["original_native_reply"]
            assert sum(r["tool"]==item["tool"] for r in rows)==1
            l=link_one(item)
            assert l["classification"]=="LINK_INCOMPLETE",l
            if item["tool"]=="b43_denied":
                assert l["functional_status_test_under_unique_tool_scenario"]==("FUNCTIONAL_STATUS_CONTRADICTION" if phase=="before" else "FUNCTIONAL_STATUS_PRESERVED")
            else:
                assert l["functional_status_test_under_unique_tool_scenario"]=="FUNCTIONAL_STATUS_PRESERVED"
            # Only status was preregistered as B38 primary. Not a post-hoc text
            # contract. Observation excludes native request ID because original
            # agent ACP event NEVER contained it; copying it would be fabrication.
            b38_record={
                "wire":{"request":req,"response":resp},
                "observed":{"tool":item["tool"],"outcome":OUTCOME[item["original_agent_terminal_status"]]},
                "contract":{"status":True,"text":"none","structured":"none","media":"none"},
                "execution_provenance":"ORIGINAL_EXTERNAL_CLIENT_CONTROLLED_SERVER",
                "original_source_git_blob":BLOBS[phase],
                "original_commit_verified":True}
            score=b38.audit_record(b38_record)
            expected="DISCREPANCY" if phase=="before" and item["tool"]=="b43_denied" else "OBSERVED_CONTRACT_PRESERVED"
            assert score["classification"]==expected,score
            if expected=="DISCREPANCY":
                assert "APPLICATION_ERROR_AS_SUCCESS" in score["findings"]
            results.append({"phase":phase,"tool":item["tool"],
              "link_rule":l,"frozen_B38_on_evaluator_verified_unique_tool":score,
              "original_agent_native_request_id_propagation":False,
              "strong_b43_link_eligible":False})
    result={
      "schema":"risu-p6b43-original-nano-link-audit-v1",
      "selected_from_official_owner_fix_not_blind_positive":True,
      "source_implementation_original_unchanged":True,
      "original_native_mcp_to_original_agent_Acp_executed":True,
      "b43_strong_source_id_link_sample_eligible":0,
      "b43_strong_link_sample_incomplete":4,
      "b43_durable_receipts_observed":0,
      "functional_unique_tool_status_pairs":4,
      "functional_unique_tool_before_discrepancy":1,
      "functional_unique_tool_after_discrepancy":0,
      "b38_original_blob":"67bbb607d277dda3a1ead60a2ccd9ba807afd7ae",
      "b38_original_modified":False,
      "no_generic_out_of_sample_sensitivity_claim":True,
      "cases":results,
    }
    raw=json.dumps(result,indent=2,sort_keys=True)+"\n"
    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(raw)
    print("B43_NANO_ORIGINAL_FUNCTIONAL_RED_GREEN_WITH_STRICT_ID_GAP")
    print("B43_NANO_AUDIT_SHA256",hashlib.sha256(raw.encode()).hexdigest())

if __name__=="__main__":main()
