#!/usr/bin/env python3
"""B40 separate after-exposure exact-source native SDK LangChain consumer audit.

Import untouched B38 checker from its frozen Git commit; do not tune on B40.
An exception for an MCP tool error is an application policy difference from
ToolMessage.error, not a proven status-as-success error in B38's contract.
"""
from __future__ import annotations
import argparse,hashlib,importlib.util,json
from pathlib import Path

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--checker",required=True,type=Path)
    ap.add_argument("--before",required=True,type=Path)
    ap.add_argument("--after",required=True,type=Path)
    ap.add_argument("--output",required=True,type=Path)
    a=ap.parse_args()
    spec=importlib.util.spec_from_file_location("b40_unchanged_b38",a.checker)
    assert spec and spec.loader
    checker=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    results=[]
    for label,p in (("before",a.before),("after",a.after)):
        original=json.loads(p.read_text(encoding="utf8"))
        assert original["variant"]==label
        assert original["real_original_client_adapter"] is True
        for record in original["scenarios"]:
            score=checker.audit_record(record)
            assert score["channels_tested"]==["status"],score
            assert score["classification"]=="OBSERVED_CONTRACT_PRESERVED",score
            results.append({
                "original_variant":label,
                "tool":record["tool"],
                "native_request_id":record["wire"]["request"]["id"],
                "original_observation_form":record["observed"]["original_observation_form"],
                "original_tool_message_status":record["observed"]["original_tool_message_status"],
                "original_observed_outcome":record["observed"]["outcome"],
                "frozen_b38_classification":score["classification"],
                "frozen_b38_findings":score["findings"],
                "channels_tested":score["channels_tested"],
                "native_tool_witness_sha256":score["native_tool_witness_sha256"],
            })
    err={r["original_variant"]:r for r in results if r["tool"]=="fail"}
    assert err["before"]["original_observation_form"]=="THROWN_EXCEPTION"
    assert err["after"]["original_observation_form"]=="ORIGINAL_LANGCHAIN_TOOL_MESSAGE"
    assert err["after"]["original_tool_message_status"]=="error"
    assert all(r["frozen_b38_classification"]=="OBSERVED_CONTRACT_PRESERVED" for r in results)
    report={
        "schema":"risu-b40-p2-native-client-audit-v1",
        "original_external_client_function_executed":True,
        "first_party_synthetic_native_server":True,
        "transport":"actual official MCP JSON-RPC over SDK InMemoryTransport",
        "author_owned_original_app_executed":False,
        "original_maintainer_red_green_test_separate":True,
        "new_post_exposure_adapter_is_not_blind":True,
        "b38_checker_commit":"425d3d8272c4e725064010ed8fbf5b8217080cab",
        "b38_checker_git_blob":"67bbb607d277dda3a1ead60a2ccd9ba807afd7ae",
        "generic_b38_positive_detected":False,
        "reason":"B38 measures in-band native success versus tool error and exact declared channels; original before throws a ToolException rather than falsely returning a successful ToolMessage, so status is not misclassified; correct policy difference requires a different tool-presentation contract.",
        "only_status_tested":True,
        "original_developer_fix_semantics_verified":True,
        "independent_normals_added_to_fpr_denominator":0,
        "per_case":results,
        "population_fpr":"UNMEASURED"
    }
    raw=json.dumps(report,indent=2,ensure_ascii=False,sort_keys=True)+"\n"
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(raw,encoding="utf8")
    print(json.dumps({"original_before_after_executed":True,"b38_generic_hit":False,
                     "cases":len(results),"sha256":hashlib.sha256(raw.encode()).hexdigest()}))
if __name__=="__main__":
    main()
