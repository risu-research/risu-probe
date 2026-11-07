"""Independent audit of released SDK 2.0/2.1 in-memory MCP legacy JSON-RPC runs."""
from __future__ import annotations
import argparse
import json
from pathlib import Path

def audit(old:dict,new:dict)->dict:
    assert old["schema"]==new["schema"]=="risu-p6b2-public-mcp-native-runtime-v1"
    assert old["official_package_versions"]=={"mcp":"2.0.0","mcp-types":"2.0.0"}
    assert new["official_package_versions"]=={"mcp":"2.1.0","mcp-types":"2.1.0"}
    for r in (old,new):
        assert r["production_server_contacted"] is False
        assert r["third_party_checkout_executed"] is False
        assert r["model_calls"] is False
        assert r["scenario_bool"]["issue"].endswith("/3353")
        assert r["scenario_recursive"]["issue"].endswith("/3337")
        assert r["scenario_bool"]["native_validation"]["2026-07-28"]["accepted"] is True
        assert r["scenario_recursive"]["live_mcp"]["client_mode"]=="legacy"
        assert r["scenario_recursive"]["live_mcp"]["negotiated_protocol"]=="2025-11-25"
        assert r["scenario_recursive"]["live_mcp"]["protocol_transport"]=="MCP_SDK_IN_MEMORY_LEGACY_JSONRPC"
    assert old["scenario_bool"]["native_validation"]["2025-11-25"]["accepted"] is False
    assert new["scenario_bool"]["native_validation"]["2025-11-25"]["accepted"] is True
    o=old["scenario_recursive"]["live_mcp"]
    n=new["scenario_recursive"]["live_mcp"]
    assert o["emitted_output_schema_root_type"] is None
    assert isinstance(o["emitted_output_schema_root_ref"],str)
    assert not o["list_tools_success"] and not o["call_tool_success"]
    assert o["error"] is not None
    assert n["emitted_output_schema_root_type"]=="object"
    assert n["list_tools_success"] and n["call_tool_success"]
    assert {"tree","heartbeat"} <= set(n["tool_names"])
    assert n["result"]["name"]=="root"
    assert n["result"]["children"][0]["name"]=="leaf"
    return {
        "status":"PASS","cases":2,
        "legacy_boolean_subschema":{"old":"VALIDATOR_REJECTED","new":"VALIDATOR_ACCEPTED"},
        "recursive_tool":{"old":"LIVE_MCP_LIST_FAILED","new":"LIVE_MCP_LIST_AND_CALL_SUCCEEDED"},
        "transport_boundary":"SDK in-memory legacy JSON-RPC, NOT stdio or production MCP",
        "claim":"Actual released SDK operation, no inference that RISU static analyzer detected these failures"
    }

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--old",type=Path,required=True)
    p.add_argument("--new",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    x=audit(json.loads(a.old.read_text()),json.loads(a.new.read_text()))
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(x,indent=2,sort_keys=True)+"\n")
    print("P6B2_RELEASED_MCP_RUNTIME_AUDIT",x,flush=True)
