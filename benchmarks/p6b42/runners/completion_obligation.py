#!/usr/bin/env python3
"""P6-B42 independent, opt-in completion obligation evaluator (RESEARCH ONLY).

Implements preregistered C42-COMPLETE-1. No import of original upstream source.
A missing result is a genuine omission only when original call was recorded,
exact call ID is observed, original call was proven settled, and the original
journal was snapshotted after the joined operation.
"""
from __future__ import annotations
import argparse
import json
import hashlib
from collections import Counter
from pathlib import Path

def score(record:dict)->dict:
    def incomplete(reason):
        return {"classification":"INCOMPLETE","reason":reason,
                "count_as_omission":False}
    events=record.get("original_journal_events")
    if not isinstance(events,list):
        return incomplete("ORIGINAL_JOURNAL_UNAVAILABLE")
    if record.get("original_function_called") is not True:
        return incomplete("ORIGINAL_FUNCTION_NOT_EXECUTED")
    if record.get("original_tool_attempt_settled") is not True:
        return incomplete("TOOL_ATTEMPT_NOT_PROVEN_SETTLED")
    if record.get("original_run_joined") is not True:
        return incomplete("ORIGINAL_RUN_NOT_JOINED")
    if record.get("snapshot_after_original_join") is not True:
        return incomplete("SNAPSHOT_BEFORE_SETTLED")
    expected=record.get("expected_tool_use_id")
    if not isinstance(expected,str) or not expected:
        return incomplete("CALL_ID_NOT_DECLARED")
    rows=[]
    for e in events:
        if not isinstance(e,dict) or type(e.get("id")) is not int or not isinstance(e.get("type"),str) or not isinstance(e.get("payload"),dict):
            return incomplete("ORIGINAL_JOURNAL_ROW_MALFORMED")
        if "parent_event_id" not in e:
            return incomplete("ROW_HAS_NO_PARENT_FIELD")
        rows.append(e)
    ids=[x["id"] for x in rows]
    if len(ids)!=len(set(ids)):
        return incomplete("JOURNAL_EVENT_ID_COLLISION")
    calls=[x for x in rows if x["type"]=="tool_call" and x["payload"].get("tool_use_id")==expected]
    if len(calls)!=1:
        return incomplete("EXPECTED_EXACTLY_ONE_ORIGINAL_START_EVENT")
    call=calls[0]
    terminal=[x for x in rows if x["type"]=="tool_result" and x["parent_event_id"]==call["id"] and x["payload"].get("tool_use_id")==expected]
    unmatched=[x for x in rows if x["type"]=="tool_result" and x["payload"].get("tool_use_id")==expected and (x["parent_event_id"]!=call["id"])]
    if unmatched:
        classification="UNMATCHED_TERMINAL_EVENT"
    elif len(terminal)==0:
        classification="OMITTED_TERMINAL_EVENT"
    elif len(terminal)==1:
        classification="OBSERVED_COMPLETION_PRESERVED"
    else:
        classification="DUPLICATED_TERMINAL_EVENT"
    return {"classification":classification,"expected_tool_use_id":expected,"original_call_event_id":call["id"],
      "original_event_ids":[e["id"] for e in rows],
      "matching_terminal_event_ids":[e["id"] for e in terminal],
      "unmatched_terminal_event_ids":[e["id"] for e in unmatched],
      "terminal_count":len(terminal),
      "start_seen":True,"settled_proof":True,"journal_snapshotted_after_join":True,
      "count_as_omission":classification=="OMITTED_TERMINAL_EVENT",
      "property":"C42-COMPLETE-1",
      "scope":"ORIGINAL_JOURNAL_SETTLED_TOOL_CALL_ONLY"}

def selftest():
    def e(i,k,tid,parent=None):return {"id":i,"type":k,"parent_event_id":parent,"payload":{"tool_use_id":tid}}
    base={"expected_tool_use_id":"tool-7","original_function_called":True,"original_tool_attempt_settled":True,
      "original_run_joined":True,"snapshot_after_original_join":True,
      "original_journal_events":[e(1,"tool_call","tool-7")]}
    assert score(base)["classification"]=="OMITTED_TERMINAL_EVENT"
    ok={**base,"original_journal_events":[e(1,"tool_call","tool-7"),e(2,"tool_result","tool-7",1)]}
    assert score(ok)["classification"]=="OBSERVED_COMPLETION_PRESERVED"
    assert score({**ok,"original_journal_events":ok["original_journal_events"]+[e(3,"tool_result","tool-7",1)]})["classification"]=="DUPLICATED_TERMINAL_EVENT"
    assert score({**ok,"original_journal_events":[ok["original_journal_events"][0],e(2,"tool_result","tool-7",999)]})["classification"]=="UNMATCHED_TERMINAL_EVENT"
    assert score({**base,"original_tool_attempt_settled":False})["classification"]=="INCOMPLETE"
    assert score({**base,"snapshot_after_original_join":False})["classification"]=="INCOMPLETE"
    assert score({**base,"original_journal_events":[]})["classification"]=="INCOMPLETE"
    assert score({**base,"original_journal_events":None})["classification"]=="INCOMPLETE"
    print("B42_COMPLETION_POLICY_NEGATIVE_AND_POSITIVE_SELFTESTS_PASSED_8")

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--input",type=Path)
    p.add_argument("--output",type=Path)
    p.add_argument("--selftest",action="store_true")
    a=p.parse_args()
    if a.selftest:
        selftest()
        if not a.input:return
    if a.input is None or a.output is None:p.error("--input and --output required")
    src=json.loads(a.input.read_text())
    cases=src.get("cases",[])
    if not isinstance(cases,list) or not cases:
        raise SystemExit("no original cases")
    scores=[{"case":r.get("scenario"),"variant":src.get("variant"),"result":score(r)} for r in cases]
    out={"schema":"risu-p6b42-completion-property-v1","contract":"C42-COMPLETE-1",
      "upstream_original_repo":src.get("original_repo"),"upstream_original_commit":src.get("original_commit"),
      "original_source_modified":src.get("original_source_modified"),
      "source_full_app_claim":False,
      "records":scores,"summary":dict(Counter(x["result"]["classification"] for x in scores)),
      "no_population_or_generic_accuracy_claim":True,
      "source_case_count":len(cases)}
    b=json.dumps(out,ensure_ascii=False,sort_keys=True,indent=2)+"\n"
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(b)
    print("B42_COMPLETION_SCORE",src.get("variant"),out["summary"],"sha256",hashlib.sha256(b.encode()).hexdigest())

if __name__=="__main__":main()
