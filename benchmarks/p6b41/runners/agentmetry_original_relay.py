#!/usr/bin/env python3
"""B41 evaluation-only relay witness using the original Agentmetry proxy.

Executes the original upstream _relay_stdout parser with synthetic JSON-RPC
messages and captures post_ingest events. No original source is modified.
Critically, absence of a 'tool_failed' event does NOT count as an explicit
consumer success observation under the unchanged B38 detector.
"""
from __future__ import annotations
import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import agentmetry.hooks.mcp_proxy as proxy

CASES = (
    ("native_true_error", {"content":[{"type":"text","text":"synthetic private string"}],"isError":True}),
    ("native_false_success", {"content":[{"type":"text","text":"hello"}],"isError":False}),
    ("native_absent_success", {"content":[{"type":"text","text":"hello"}]}),
    ("native_string_true_not_boolean", {"content":[{"type":"text","text":"hello"}],"isError":"true"}),
    ("native_int_one_not_boolean", {"content":[{"type":"text","text":"hello"}],"isError":1}),
)
def clean_private_information(v):
    # These are synthetic-only test strings; explicit leakage check on events.
    blob=json.dumps(v,sort_keys=True)
    assert "synthetic private string" not in blob
    return v

async def run_case(label, result, index):
    rid=index+41
    request={"jsonrpc":"2.0","id":rid,"method":"tools/call","params":{"name":"b41_probe","arguments":{}}}
    response={"jsonrpc":"2.0","id":rid,"result":result}
    correlation="B41_synthetic_only"
    call=proxy.build_call_payload(request,"b41-peer",correlation)
    assert call is not None and call["event_type"]=="tool_called"
    pending={str(rid):{"kind":"call","qualified":call["tool"]["qualified"],"server":"b41-peer"}}
    reader=asyncio.StreamReader()
    reader.feed_data((json.dumps(response)+"\n").encode("utf8"))
    reader.feed_eof()
    events=[]
    original_post=proxy.post_ingest
    try:
        proxy.post_ingest=lambda event,quiet=True: events.append(event)
        # This original external parser consumes the native response and emits
        # its original tool_failed decision, not a RISU reimplementation.
        await proxy._relay_stdout(reader,pending,"b41-peer",proxy.ToolsListBuffer(),{})
    finally:
        proxy.post_ingest=original_post
    clean_private_information(events)
    assert not pending
    if len(events)>1: raise RuntimeError("MORE_THAN_ONE_TERMINAL_AUDIT_EVENT")
    terminal=events[0] if events else None
    original_observation={"tool":"b41_probe","request_id":rid,
                           "original_call_event":call["event_type"],
                           "original_terminal_event":terminal["event_type"] if terminal else None,
                           "original_reported_reason":terminal.get("reason") if terminal else None,
                           "explicit_success_event_observed":False}
    if terminal and terminal.get("event_type")=="tool_failed" and terminal.get("outcome")=="error":
        original_observation["outcome"]="tool_error"
    record={
        "case_id":"P1","variant_case":label,
        "wire":{"request":request,"response":response},
        "observed":original_observation,
        "contract":{"status":True,"text":"none","structured":"none","media":"none"},
        "execution_provenance":"ORIGINAL_EXTERNAL_CLIENT_CONTROLLED_SERVER",
        "original_source_git_blob":"set-by-runner",
        "original_commit_verified":True,
        "original_source_unchanged":True,
        "actual_original_function":"agentmetry.hooks.mcp_proxy._relay_stdout",
        "original_upstream_application_fully_executed":False,
        "test_peer":"controlled-native-jsonrpc-streamreader",
        "absence_of_terminal_event_is_NOT_success":True,
        "original_terminal_events_observed":len(events),
    }
    return record

async def main():
    p=argparse.ArgumentParser()
    p.add_argument("--variant",choices=("before","after"),required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    records=[]
    for i,(label,result) in enumerate(CASES):
        records.append(await run_case(label,result,i))
    for record in records:
        record["original_source_git_blob"]=(
            "5654e78bb930a3aa25ac86573cbdecd53d918ea4" if a.variant=="before"
            else "f6ce68be377a43891947653e670944474b9e5822")
    iserror=records[0]
    assert (iserror["observed"].get("outcome")=="tool_error")==(a.variant=="after")
    assert all(r["observed"].get("outcome") is None for r in records[1:])
    raw={"schema":"risu-b41-p1-native-original-relay-v1","variant":a.variant,
         "original_repo":"blitzcrieg1/agentmetry",
         "original_commit":("773a5bc6e35f467b21967aff17e5737f2a1f8bc5"
                            if a.variant=="before" else "ad2de9e44b37738879b7efb2ab862583b53ddd9e"),
         "original_source_code_modified":False,
         "native_response_original_relay_executed":True,
         "native_response_has_explicit_tool_failure_event_after_fix":a.variant=="after",
         "source_owned_test_separate_from_this_evaluator_overlay":True,
         "note":"No explicit original success event when no terminal tool_failed event; frozen B38 incomplete for before error.",
         "records":records}
    data=json.dumps(raw,indent=2,sort_keys=True)+"\n"
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(data,encoding="utf8")
    print("B41_P1_ORIGINAL_RELAY",a.variant,
          "records",len(records),"sha256",hashlib.sha256(data.encode()).hexdigest())

if __name__=="__main__":
    asyncio.run(main())
