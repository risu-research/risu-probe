#!/usr/bin/env python3
"""B43 post-exposure synthetic identifiability counterexample (not held-out).

A tool name and arguments are NOT an exact identity join when two native
tools/call requests overlap and original agent tool-call IDs belong to a
different namespace. We enumerate distinct bijections with identical
observables but opposite conformance conclusions. This is a mathematical
ambiguity, not an observed misclassification of an external application.
"""
import json
from itertools import permutations
from pathlib import Path
import argparse
import hashlib

def evaluate(native, agent):
    assert len(native)==len(agent)
    if any("original_native_request_id" in a for a in agent):
        raise ValueError("Run only on events without source-native identity link")
    if any("original_agent_tool_call_id" in n for n in native):
        raise ValueError("Run only on source-native events without agent tool ID")
    alternatives=[]
    for seq in permutations(agent):
        if any(n["name"]!=a["name"] or n["arguments"]!=a["arguments"] for n,a in zip(native,seq)):
            continue
        contradictions=[]
        for n,a in zip(native,seq):
            source="error" if n["native_isError"] else "success"
            original_agent="error" if a["status"]=="failed" else "success"
            if source!=original_agent:
                contradictions.append({"native_req_id":n["native_request_id"],
                                       "agent_call_id":a["agent_call_id"],
                                       "native_kind":source,"app_kind":original_agent})
        alternatives.append({"proposed_links":[{"native_req_id":n["native_request_id"],
                                                "agent_call_id":a["agent_call_id"]}
                                               for n,a in zip(native,seq)],
                             "status_discrepancies":contradictions,
                             "all_status_preserved":not contradictions})
    return alternatives

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--output",required=True,type=Path)
    a=p.parse_args()
    native=[
        {"native_request_id":"rpc-901","name":"write_note","arguments":{"key":"same"},
         "native_isError":True,"native_reply_received":True},
        {"native_request_id":"rpc-902","name":"write_note","arguments":{"key":"same"},
         "native_isError":False,"native_reply_received":True},
    ]
    agent=[
        {"agent_call_id":"agent-A","name":"write_note","arguments":{"key":"same"},
         "status":"failed","settled":True},
        {"agent_call_id":"agent-B","name":"write_note","arguments":{"key":"same"},
         "status":"completed","settled":True},
    ]
    alts=evaluate(native,agent)
    assert len(alts)==2
    assert sum(bool(x["all_status_preserved"]) for x in alts)==1
    assert sum(bool(x["status_discrepancies"]) for x in alts)==1
    assert len({tuple((v["native_req_id"],v["agent_call_id"]) for v in a["proposed_links"]) for a in alts})==2
    result={
      "schema":"risu-p6b43-postexposure-identity-ambiguity-v1",
      "evidence_class":"SYNTHETIC_COUNTEREXAMPLE_ONLY_NOT_ORIGINAL_UPSTREAM_EXECUTION",
      "input_native":[{"id":n["native_request_id"],"name":n["name"],"arguments":n["arguments"],
                       "isError":n["native_isError"]} for n in native],
      "input_original_agent_terminal":agent,
      "source_provided_native_to_agent_binding":False,
      "indistinguishable_original_observation_alternative_linkings":alts,
      "compatible_bijection_count":2,
      "one_linking_all_status_preserved":True,
      "another_linking_contains_false_success_and_false_error":True,
      "identifiable_result":"INCOMPLETE_CROSS_BOUNDARY_IDENTITY",
      "no_production_sensitivity_claim":True,
      "no_original_upstream_execution_claim":True,
      "note":"Original concurrent same-tool calls without persisted native↔agent ID mapping cannot be uniquely paired by name/arguments even when all terminal statuses are observed."
    }
    b=json.dumps(result,indent=2,sort_keys=True)+"\n"
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(b)
    print("B43_POSTEXPOSURE_TWO_COMPATIBLE_PAIRINGS_ONE_CLEAN_ONE_CONTRADICTORY")
    print("B43_COLLISION_PROOF_SHA256",hashlib.sha256(b.encode()).hexdigest())
if __name__=="__main__":main()
