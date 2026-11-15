#!/usr/bin/env python3
"""B44 prospective first-look original-evidence verifier. No target imports.

Independent score of observed actual MELRA native stdio JSON-RPC frames,
original durable SQLite task/receipt/certificate summaries, independently read
real filesystem bytes. Distinguishes task-scoped original receipt times from
original per-native-request start/end. Never fabricate model tool call IDs.
Created after cohort/source seal; this is a transparent evaluation extractor,
NOT a blind novel detector, not a public product change.
"""
import argparse
import hashlib
import json
from pathlib import Path

def incomplete(reason):
    return {"verdict":"INCOMPLETE","reason":reason,"original_full_chain_proven":False}
def sha(s):return hashlib.sha256(s).hexdigest()
def has_hex(x):return isinstance(x,str) and len(x)==64 and all(c in "0123456789abcdef" for c in x)

def score(o):
    if o.get("original_repo")!="XAGI-Lab/melra" or o.get("upstream_implementation_patched") is not False:
        return incomplete("ORIGINAL_REPO_UNCHANGED_PROOF_MISSING")
    if o.get("original_commit")!="ab59ffa134decd9613a378c7bd8a0e8d495c7e89":
        return incomplete("ORIGINAL_COMMIT_MISMATCH")
    ev=o.get("native_stdio_raw_frame_redacted_witnesses")
    if not isinstance(ev,list) or len(ev)<12:
        return incomplete("ACTUAL_ORIGINAL_NATIVE_WIRE_ABSENT")
    native={}; replies={}; wire_frame_hashes=[]
    for e in ev:
        if not e.get("raw_verified_utf8_newline") or not has_hex(e.get("exact_bytes_sha256")):
            return incomplete("ACTUAL_STDIN_STDOUT_BYTE_FRAME_DIGEST_MISSING")
        wire_frame_hashes.append(e["exact_bytes_sha256"])
        msg=e.get("parsed_redacted")
        if not isinstance(msg,dict):return incomplete("WIRE_FRAME_NOT_PARSED_JSON")
        if e.get("direction")=="evaluator_native_client_to_original_external_MELRA_stdio_server" and msg.get("method")=="tools/call":
            if msg.get("id") in native:return {"verdict":"DUPLICATE_NATIVE_REQUEST_ID","original_full_chain_proven":False}
            native[msg["id"]]=msg
        if e.get("direction")=="original_external_MELRA_stdio_server_to_evaluator_native_client" and "id" in msg:
            if msg.get("id") in replies:return {"verdict":"DUPLICATE_NATIVE_RESPONSE_ID","original_full_chain_proven":False}
            replies[msg["id"]]=msg
    roles={i:r["params"]["name"] for i,r in native.items()}
    expect={
      "b44-plan-101":"melra_plan",
      "b44-denied-102":"melra_execute",
      "b44-execute-103":"melra_execute",
      "b44-receipt-104":"melra_receipt",
      "b44-status-105":"melra_task_status"
    }
    if roles!=expect:return incomplete("FIVE_REAL_NATIVE_TOOL_CALL_IDS_OR_NAMES_NOT_OBSERVED")
    for i in expect:
        if i not in replies or replies[i].get("jsonrpc")!="2.0" or not isinstance(replies[i].get("result"),dict):
            return incomplete("ORIGINAL_NATIVE_RESPONSE_ID_MISSING_OR_NONRESULT_"+i)
        if replies[i]["id"]!=native[i]["id"]:
            return incomplete("WRONG_NATIVE_REPLY_ID")
    if replies["b44-denied-102"]["result"].get("isError") is not True:
        return {"verdict":"ORIGINAL_DENIAL_STATUS_MISCLASSIFIED","original_full_chain_proven":False}
    if replies["b44-execute-103"]["result"].get("isError",False) is not False:
        return {"verdict":"ORIGINAL_APPROVED_EXECUTION_IS_ERROR","original_full_chain_proven":False}
    effect=o.get("effect",{})
    if not (
      effect.get("before_exists") is False and effect.get("after_exists") is True and
      effect.get("authorized_effect_content_exact") is True and
      effect.get("wrong_approval_did_not_mutate") is True and
      has_hex(effect.get("after_bytes_sha256")) and
      effect.get("after_bytes_sha256")==effect.get("expected_bytes_sha256")
    ):
        return {"verdict":"EFFECT_UNPROVEN","original_full_chain_proven":False}
    db=o.get("persisted_original_sqlite",{})
    if not (
      db.get("independently_reopened_after_original_process_exit") is True and
      db.get("original_task_row_count_for_id")==1 and
      db.get("original_receipt_row_count_for_id")==1 and
      db.get("original_certificate_row_count_for_id")==1 and
      db.get("task_status")=="verified_success" and
      db.get("stored_receipt_ids")==[o.get("original_melra_receipt_id")] and
      all(has_hex(db.get(k)) for k in ("task_json_sha256","receipt_json_sha256","certificate_json_sha256"))
    ):return incomplete("ORIGINAL_TASK_SCOPED_DURABLE_RECEIPT_OR_CERTIFICATE_NOT_PROVEN")
    receipt_keys=db.get("original_sqlite_receipt_record_keys",[])
    task_scoped_receipt_has_orig_start_end="startedAt" in receipt_keys and "endedAt" in receipt_keys
    if not task_scoped_receipt_has_orig_start_end:
        return incomplete("ORIGINAL_TASK_RECEIPT_START_END_FIELDS_MISSING")
    # Key distinction. Native tool request and model IDs must be original,
    # persisted and connected by ORIGINAL source. A test-owned 5-tool script
    # is not an independent original model.
    original_model=o.get("original_model_agent_tool_call_id_observed") is True
    original_native_agent=o.get("original_native_request_id_to_model_agent_tool_call_id_mapping_present") is True
    original_per_wire_s=o.get("original_per_native_request_matched_persistent_start_and_terminal") is True
    strong_model_chain=original_model and original_native_agent and original_per_wire_s
    if strong_model_chain:
        # Even with flags, require independently observed actual mapping records
        mapping=o.get("original_persisted_native_model_start_terminal_pairs")
        if not isinstance(mapping,list) or not mapping:
            return incomplete("ORIGINAL_PERSISTED_NATIVE_MODEL_START_TERMINAL_EVIDENCE_NOT_PRESENT")
    chain={
       "W_original_native_jsonrpc_stdio_request_response":True,
       "A_original_model_tool_call_id_to_native_request_id":original_model and original_native_agent,
       "S_original_persisted_start_per_native_request":original_per_wire_s,
       "T_original_persisted_terminal_per_native_request":original_per_wire_s,
       "E_independently_observed_disposable_file_mutation":True,
    }
    complete=all(chain.values()) and strong_model_chain
    return {
      "verdict":"FULL_CHAIN_VERIFIED" if complete else "LINK_INCOMPLETE",
      "original_full_chain_proven":complete,
      "chain":chain,
      "original_task_level_receipt_has_start_end_fields":task_scoped_receipt_has_orig_start_end,
      "original_sqlite_task_receipt_certificate_all_proven":True,
      "native_wire_responses_id_paired":len(expect),
      "native_wire_ids":list(expect),
      "original_effect_sha256":effect["after_bytes_sha256"],
      "original_receipt_id":o["original_melra_receipt_id"],
      "original_certificate_digest":o["original_certificate_digest"],
      "source_tier":"ACTUAL_ORIGINAL_NATIVE_MCP_STDIO_SERVER_TO_DURABLE_TASK_RECEIPT_INDEPENDENT_REAL_EFFECT",
      "original_app_has_no_external_model_agent_id_in_evaluated_path":not original_model,
      "native_request_ids_generated_by_evaluator":True,
      "native_request_id_not_original_task_or_agent_id":True,
      "no_generalized_detection_performance_claim":True,
      "no_inferred_external_effect_from_receipt":True,
      "do_not_promote_to_public_main":True,
    }

def selftests(original):
    score0=score(original);assert score0["verdict"]=="LINK_INCOMPLETE",score0
    def mutated(fn):
        v=json.loads(json.dumps(original));fn(v);return score(v)
    cases=[
      ("db_missing",lambda v:v["persisted_original_sqlite"].update(original_receipt_row_count_for_id=0),"INCOMPLETE"),
      ("effect_missing",lambda v:v["effect"].update(after_exists=False),"EFFECT_UNPROVEN"),
      ("wrong_denial_success",lambda v:next(x for x in v["native_stdio_raw_frame_redacted_witnesses"]
         if x["parsed_redacted"].get("id")=="b44-denied-102" and x["direction"].startswith("original_external"))["parsed_redacted"]["result"].update(isError=False),"ORIGINAL_DENIAL_STATUS_MISCLASSIFIED"),
      ("original_undeclared_id",lambda v:v.update(original_model_agent_tool_call_id_observed=True),"LINK_INCOMPLETE"),
      ("original_pretend_all_linked",lambda v:v.update(original_model_agent_tool_call_id_observed=True,
                 original_native_request_id_to_model_agent_tool_call_id_mapping_present=True,
                 original_per_native_request_matched_persistent_start_and_terminal=True),"INCOMPLETE"),
      ("wrong_file_sha",lambda v:v["effect"].update(expected_bytes_sha256="0"*64),"EFFECT_UNPROVEN"),
    ]
    for key,action,expected in cases:
        q=mutated(action)
        assert q["verdict"]==expected,(key,q,expected)
    print("B44_POSTEXPOSURE_EVALUATOR_NEGATIVE_BOUNDARY_SELFTESTS_PASSED",len(cases))
    return len(cases)

def main():
    p=argparse.ArgumentParser();p.add_argument("--input",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True);p.add_argument("--selftest",action="store_true")
    args=p.parse_args()
    doc=json.loads(args.input.read_text())
    n=selftests(doc) if args.selftest else 0
    verdict=score(doc)
    assert verdict["verdict"]=="LINK_INCOMPLETE",verdict
    result={"schema":"risu-p6b44-original-native-durable-effect-strict-score-v1",
       "experiment":"PRESELECTED_P1_FIRST_ORIGINAL_RUNTIME",
       "five_edge_criteria_precommitted":True,
       "evaluation_extractor_post_source_inspection":True,
       "original_repository_source_modified":False,
       "full_chain_denominator_eligible":False,
       "actual_original_native_to_original_sqlite_and_file_proven":True,
       "one_external_source_owner":True,
       "score":verdict,
       "synthetic_postexposure_scorer_selftests":n}
    raw=json.dumps(result,indent=2,sort_keys=True)+"\n";args.output.write_text(raw)
    print("B44_NATIVE_EFFECT_ORIGINAL_SOURCE_PARTIAL_WITH_STRONG_MODEL_ID_LINK_INCOMPLETE")
    print("B44_SCORE_SHA256",sha(raw.encode()))
if __name__=="__main__": main()
