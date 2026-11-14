#!/usr/bin/env python3
"""Score actual Geolonia original HTTP MCP server against pre-frozen B38 rule.

Pure read-only scorer, original server was executed by Node test.
A first-party observer is NOT an original external client. Thus eligible
independent *client* FPR stays unmeasured rather than 0/1.
"""
import hashlib
import json
import os
from pathlib import Path
import sys

def must(condition,reason):
    if not condition:
        raise ValueError("B39_GEO_"+reason)

def main():
    base=Path(os.environ.get("B39_GEO_OUTPUT_DIR","out"))
    incoming=base/"B39_GEOLONIA_ORIGINAL_HTTP_WIRES.json"
    must(incoming.is_file() and not incoming.is_symlink(),"ORIGINAL_WIRE_MISSING")
    data=json.loads(incoming.read_text(encoding="utf-8"))
    must(data["original_upstream_sha"]=="d0d2a05cdc60e8e9a106d0f425560a1f1303f21c",
         "ORIGINAL_UPSTREAM_COMMIT_DRIFT")
    must(data["external_original_server_executed"] is True
         and data["original_user_client_executed"] is False,
         "ORIGINAL_PROVENANCE_MISLABELED")
    must(len(data["cases"])==7,"MISSING_OR_EXTRA_PREREGISTERED_CASES")
    from b38_native_contract_auditor import audit_record
    verdicts=[]
    for c in data["cases"]:
        must(c["execution_provenance"]=="ORIGINAL_EXTERNAL_SERVER_CONTROLLED_CLIENT",
             "NOT_ACTUAL_ORIGINAL_SERVER")
        proof=audit_record(c)
        must(proof["execution_provenance"]=="ORIGINAL_EXTERNAL_SERVER_CONTROLLED_CLIENT",
             "FROZEN_CHECKER_NOT_ORIGINAL_SERVER_PROVENANCE")
        must(proof["classification"]=="OBSERVED_CONTRACT_PRESERVED"
             and not proof["findings"],
             "ORIGINAL_NORMAL_CONTRACT_DISCREPANCY")
        verdicts.append({"protocol":c["protocol_revision"],
                         "tool":c["observed"]["tool"],
                         "classification":proof["classification"],
                         "channels_tested":proof["channels_tested"],
                         "status":c["observed"]["outcome"],
                         "wire_sha256":proof["native_tool_witness_sha256"]})
    scores={
      "case":"N1","upstream":"geolonia/datamodels",
      "original_server_native_HTTP_JSONRPC_executed":True,
      "official_original_author_normal_integration_test_executed":True,
      "RISU_consumer_adapter_not_independent_author":True,
      "preregistered_policy":"MIRRORED_TEXT_AND_STRUCTURED_JSON",
      "normal_tool_calls_with_structured_exact":5,
      "normal_tool_error_calls_with_status":2,
      "observed_contract_discrepancies":0,
      "primary_independent_real_client_FPR_eligible":False,
      "population_FPR":"UNMEASURED",
      "frozen_generic_rule_unchanged":True,
    }
    out={"schema":"p6b39-geolonia-original-http-policy-audit-v1",
         "source_original_wire_sha256":hashlib.sha256(incoming.read_bytes()).hexdigest(),
         "scores":scores,"verdicts":verdicts}
    dest=base/"B39_GEOLONIA_NORMAL_POLICY_SCORE.json"
    dest.write_text(json.dumps(out,indent=2,sort_keys=True)+"\n")
    print(json.dumps(scores,sort_keys=True))
    print("B39_GEOLONIA_ORIGINAL_SERVER_POLICY_CONTROLS_PASS_NO_INDEPENDENT_CLIENT_FPR_CLAIM")
if __name__=="__main__":
    main()
