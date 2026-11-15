#!/usr/bin/env python3
"""P6-B43 POST-EXPOSURE DEVELOPMENT — original persisted cross-ID receipt verifier.

This is a proposed stronger contract for B44 blind validation, NOT the frozen
B43-LINK-1 evaluator, NOT public RISU Probe. Synthetic self-controls cannot
count as original positive or normal client samples. Inputs must be correlated
from independently executed original code; labels alone are not provenance.

D42 distinction: ACK/start != execution result != effective side effect.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

def as_canonical(obj:Any)->bytes:
    return json.dumps(obj,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
def sha(b:bytes)->str:return hashlib.sha256(b).hexdigest()
def incomplete(reason:str)->dict:return {"verdict":"INCOMPLETE","reason":reason,"verified_effect":False}

def verify(record:dict)->dict:
    if not isinstance(record,dict):return incomplete("RECORD_NOT_OBJECT")
    pair=record.get("native_wire_pair")
    if not isinstance(pair,dict):return incomplete("WIRE_MISSING")
    request=pair.get("request");response=pair.get("response")
    if not isinstance(request,dict) or request.get("method")!="tools/call" or request.get("jsonrpc")!="2.0":
        return incomplete("NATIVE_TOOL_REQUEST_NOT_ORIGINAL_JSONRPC")
    if type(request.get("id")) not in (str,int) or not isinstance(request.get("params"),dict):
        return incomplete("NATIVE_ID_OR_PARAMS_MISSING")
    native_conn=record.get("native_connection_id")
    if not isinstance(native_conn,str) or not native_conn:return incomplete("CONNECTION_ID_NOT_RECOVERABLE")
    if not isinstance(response,dict) or response.get("id")!=request["id"] or response.get("jsonrpc")!="2.0":
        return incomplete("NATIVE_REPLY_UNOBSERVED_OR_UNPAIRED")
    if not isinstance(response.get("result"),dict):
        return incomplete("NO_INBAND_TOOL_RESULT")
    result=response["result"]
    if not isinstance(result.get("content"),list) or type(result.get("isError",False)) is not bool:
        return incomplete("NATIVE_STATUS_NOT_BOOL_OR_CONTENT_UNOBSERVED")
    if record.get("original_run_executed") is not True:
        return incomplete("ORIGINAL_EXECUTION_NOT_ATTESTED")
    journal=record.get("original_persistent_journal")
    if not isinstance(journal,dict) or journal.get("source")!="ORIGINAL_DURABLE_EVENT_STORE":
        return incomplete("NO_ORIGINAL_DURABLE_STORE")
    events=journal.get("events")
    if not isinstance(events,list):
        return incomplete("NO_ORIGINAL_EVENTS")
    if journal.get("sha256")!=sha(as_canonical(events)):
        return incomplete("JOURNAL_DIGEST_DOES_NOT_MATCH")
    if not all(isinstance(e,dict) and isinstance(e.get("event_id"),str)
               and isinstance(e.get("kind"),str) for e in events):
        return incomplete("EVENT_SCHEMA_UNPROVEN")
    ids=[e["event_id"] for e in events]
    if len(ids)!=len(set(ids)):return incomplete("EVENT_ID_COLLISION")
    agent_id=record.get("original_agent_tool_call_id")
    if not isinstance(agent_id,str) or not agent_id:return incomplete("NO_ORIGINAL_AGENT_TOOL_ID")
    starts=[e for e in events if e.get("kind")=="tool_started" and
        e.get("agent_tool_call_id")==agent_id]
    if len(starts)!=1:return incomplete("START_CARDINALITY_NOT_ONE")
    start=starts[0]
    if start.get("native_connection_id")!=native_conn or start.get("native_request_id")!=request["id"]:
        return incomplete("NO_ORIGINAL_PERSISTENT_NATIVE_TO_AGENT_ID_BINDING")
    if start.get("tool")!=request["params"].get("name"):
        return incomplete("ORIGINAL_START_TOOL_IDENTITY_COLLISION")
    terminal=[e for e in events if e.get("kind")=="tool_terminal" and
      e.get("agent_tool_call_id")==agent_id and e.get("parent_event_id")==start["event_id"]]
    orphans=[e for e in events if e.get("kind")=="tool_terminal" and
      e.get("agent_tool_call_id")==agent_id and e.get("parent_event_id")!=start["event_id"]]
    if orphans:return {"verdict":"UNMATCHED_ORIGINAL_TERMINAL","event_ids":[e["event_id"] for e in orphans],"verified_effect":False}
    if len(terminal)>1:return {"verdict":"DUPLICATE_ORIGINAL_TERMINAL","event_ids":[e["event_id"] for e in terminal],"verified_effect":False}
    if not record.get("original_attempt_settled") or not record.get("original_run_joined") or not record.get("original_snapshot_after_join"):
        return incomplete("PENDING_OR_SNAPSHOT_BOUNDARY_UNVERIFIED")
    if not terminal:return {"verdict":"OMITTED_ORIGINAL_TERMINAL","start_event_id":start["event_id"],"verified_effect":False}
    final=terminal[0].get("status")
    if final not in ("success","error","cancelled","unknown"):
        return incomplete("ORIGINAL_TERMINAL_STATUS_NOT_EXPLICIT")
    if final=="cancelled":return {"verdict":"CONSUMER_CANCELLED_AFTER_NATIVE_RESULT","original_terminal":final,"verified_effect":False,
       "note":"Application cancellation is distinct from native tool error and business effect"}
    if final=="unknown":return incomplete("FINAL_OUTCOME_UNKNOWN")
    source="error" if result.get("isError",False) else "success"
    verdict="PRESERVED_ORIGINAL_NATIVE_TO_DURABLE_TERMINAL" if final==source else
      "ORIGINAL_ERROR_AS_SUCCESS" if source=="error" and final=="success" else
      "ORIGINAL_SUCCESS_AS_ERROR"
    return {"verdict":verdict,"native_status":source,"original_terminal":final,
      "original_native_request_id":request["id"],"original_agent_tool_call_id":agent_id,
      "original_start_event_id":start["event_id"],"original_terminal_event_id":terminal[0]["event_id"],
      "verified_effect":False,"journal_sha256":journal["sha256"],
      "boundary_tier":"ORIGINAL_NATIVE_TO_PERSISTED_AGENT_TERMINAL",
      "no_external_effect_confirmation":True}

def fixture(native_error=True,terminal="error",original_settled=True):
    req={"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"foo"}}
    res={"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"rejected"}],"isError":native_error}}
    events=[{"event_id":"evt1","kind":"tool_started","agent_tool_call_id":"tool-17",
      "native_connection_id":"conn-a","native_request_id":7,"tool":"foo"}]
    if terminal is not None:events.append({"event_id":"evt2","kind":"tool_terminal","agent_tool_call_id":"tool-17",
      "parent_event_id":"evt1","status":terminal})
    return {"native_wire_pair":{"request":req,"response":res},"native_connection_id":"conn-a",
      "original_run_executed":True,"original_agent_tool_call_id":"tool-17",
      "original_persistent_journal":{"source":"ORIGINAL_DURABLE_EVENT_STORE","events":events,"sha256":sha(as_canonical(events))},
      "original_attempt_settled":original_settled,"original_run_joined":original_settled,
      "original_snapshot_after_join":original_settled}

def revise(f,func):
    f=json.loads(json.dumps(f))
    func(f)
    ev=f.get("original_persistent_journal",{}).get("events")
    if isinstance(ev,list):f["original_persistent_journal"]["sha256"]=sha(as_canonical(ev))
    return f
def selftest():
    tests={
       "preserved_error":fixture(),
       "preserved_success":fixture(False,"success"),
       "false_success":fixture(True,"success"),
       "false_error":fixture(False,"error"),
       "pending_not_omission":fixture(True,None,False),
       "settled_missing_terminal":fixture(True,None,True),
       "after_response_cancelled":fixture(True,"cancelled"),
       "no_original_native_to_app_link":revise(fixture(),lambda f:f["original_persistent_journal"]["events"][0].update(native_request_id=99)),
       "misparented_terminal":revise(fixture(),lambda f:f["original_persistent_journal"]["events"][1].update(parent_event_id="evt-other")),
       "duplicate_terminal":revise(fixture(),lambda f:f["original_persistent_journal"]["events"].append({**f["original_persistent_journal"]["events"][1],"event_id":"evt3"})),
       "original_journal_hash_tamper":{**fixture(), "original_persistent_journal":{**fixture()["original_persistent_journal"],"sha256":"0"*64}},
       "native_reply_id_collision":revise(fixture(),lambda f:f["native_wire_pair"]["response"].update(id=8)),
    }
    expected={"preserved_error":"PRESERVED_ORIGINAL_NATIVE_TO_DURABLE_TERMINAL",
      "preserved_success":"PRESERVED_ORIGINAL_NATIVE_TO_DURABLE_TERMINAL",
      "false_success":"ORIGINAL_ERROR_AS_SUCCESS","false_error":"ORIGINAL_SUCCESS_AS_ERROR",
      "pending_not_omission":"INCOMPLETE","settled_missing_terminal":"OMITTED_ORIGINAL_TERMINAL",
      "after_response_cancelled":"CONSUMER_CANCELLED_AFTER_NATIVE_RESULT",
      "no_original_native_to_app_link":"INCOMPLETE",
      "misparented_terminal":"UNMATCHED_ORIGINAL_TERMINAL",
      "duplicate_terminal":"DUPLICATE_ORIGINAL_TERMINAL",
      "original_journal_hash_tamper":"INCOMPLETE",
      "native_reply_id_collision":"INCOMPLETE"}
    scores={k:verify(v)["verdict"] for k,v in tests.items()}
    assert scores==expected,(scores,expected)
    print("B43_POSTEXPOSURE_ORIGINAL_RECEIPT_BRIDGE_SELFTESTS_PASSED",len(scores))
    return scores
if __name__=="__main__":
    ap=argparse.ArgumentParser();ap.add_argument("--selftest",action="store_true")
    ap.add_argument("--input",type=Path);ap.add_argument("--output",type=Path)
    a=ap.parse_args()
    if a.selftest:
        selftest()
        if a.input is None:raise SystemExit(0)
    if a.input is None or a.output is None:ap.error("--input and --output required")
    src=json.loads(a.input.read_text())
    result=verify(src)
    a.output.write_text(json.dumps({"schema":"risu-b43-postexposure-bridge-development-v1",
      "not_B43_independent_holdout":True,"not_product_capability":True,
      "score":result},sort_keys=True,indent=2)+"\n")
    print("B43_DEVELOPMENT_BRIDGE",result["verdict"])
