"""Execute real, released MCP Python SDK methods and legacy JSON-RPC client/server.

Both SDK versions are installed in separate environments. This code contains
synthetic, public example schemas only; never runs a fetched upstream project,
external API, arbitrary URL, AI model, credential, or untrusted payload.
"""
from __future__ import annotations

import argparse
import asyncio
import importlib.metadata
import json
from pathlib import Path
from pydantic import BaseModel

class Node(BaseModel):
    name: str
    children: list["Node"] = []

Node.model_rebuild()

def exception_summary(exc: BaseException) -> dict:
    text=str(exc)
    return {"class":type(exc).__name__,"snippet":text[:450],
            "root_cause_in_message":("outputSchema" in text or "invalid result" in text or "dict_type" in text)}

def boolean_subschemas() -> dict:
    from mcp_types.methods import validate_server_result
    tool={
        "name":"read_local_fixture",
        "inputSchema":{"type":"object","properties":{"arg":True}},
        "outputSchema":{"type":"object","properties":{"result":True,"hidden":False},
                        "required":["result"]}
    }
    rows={}
    for ver in ("2025-11-25","2026-07-28"):
        data={"tools":[tool]}
        if ver=="2026-07-28":
            data.update({"resultType":"complete","ttlMs":0,"cacheScope":"private"})
        try:
            validate_server_result("tools/list",ver,data)
            rows[ver]={"accepted":True,"error":None}
        except Exception as e:
            rows[ver]={"accepted":False,"error":exception_summary(e)}
    # The modern protocol's boolean subschemas must be a positive control
    assert rows["2026-07-28"]["accepted"] is True,rows
    return rows

async def recursive_mcp_protocol() -> dict:
    from mcp.client import Client
    from mcp.server.mcpserver import MCPServer
    from mcp.server.mcpserver.utilities.func_metadata import func_metadata
    def tree() -> Node:
        return Node(name="root",children=[Node(name="leaf")])
    mcp=MCPServer("p6b2-public-synthetic")
    mcp.tool()(tree)
    @mcp.tool()
    def heartbeat() -> int:
        return 1

    emitted=func_metadata(tree).output_schema
    root_type=emitted.get("type")
    root_ref=emitted.get("$ref")
    entry={"protocol_transport":"MCP_SDK_IN_MEMORY_LEGACY_JSONRPC",
           "client_mode":"legacy", "negotiated_protocol":"2025-11-25",
           "emitted_output_schema_root_type":root_type,
           "emitted_output_schema_root_ref":root_ref,
           "list_tools_success":False,
           "call_tool_success":False,
           "tool_names":[],"result":None,"error":None}
    try:
        async with Client(mcp,mode="legacy") as client:
            tools=await client.list_tools()
            entry["list_tools_success"]=True
            entry["tool_names"]=sorted(t.name for t in tools.tools)
            result=await client.call_tool("tree",{})
            data=getattr(result,"structured_content",None)
            entry["result"]=data
            entry["call_tool_success"]=bool(
                isinstance(data,dict) and data.get("name")=="root" and data.get("children"))
    except Exception as e:
        entry["error"]=exception_summary(e)
    return entry

async def run(out:Path)->dict:
    ver=importlib.metadata.version("mcp")
    typed=importlib.metadata.version("mcp-types")
    if ver not in ("2.0.0","2.1.0") or typed!=ver:
        raise RuntimeError("Exactly frozen official mcp and mcp-types 2.0.0 or 2.1.0 required")
    b=boolean_subschemas()
    rec=await recursive_mcp_protocol()
    old=ver=="2.0.0"
    assert b["2025-11-25"]["accepted"] is not old, ("boolean version drift",b)
    assert rec["list_tools_success"] is not old,("recursive version drift",rec)
    assert rec["call_tool_success"] is not old,("recursive tool call",rec)
    if old:
        assert rec["emitted_output_schema_root_type"] is None
        assert rec["emitted_output_schema_root_ref"] is not None
    else:
        assert rec["emitted_output_schema_root_type"]=="object"
    report={
        "schema":"risu-p6b2-public-mcp-native-runtime-v1",
        "official_package_versions":{"mcp":ver,"mcp-types":typed},
        "official_release_tag":"https://github.com/modelcontextprotocol/python-sdk/releases/tag/v"+ver,
        "scenario_bool":{"issue":"https://github.com/modelcontextprotocol/python-sdk/issues/3353",
                         "native_validation":b},
        "scenario_recursive":{"issue":"https://github.com/modelcontextprotocol/python-sdk/issues/3337",
                              "live_mcp":rec},
        "production_server_contacted":False,
        "third_party_checkout_executed":False,
        "model_calls":False,
        "claim_boundary":"Boolean case is actual SDK validator, not a wire session. Recursive case is real MCP in-memory legacy JSON-RPC client/server, not external stdio."
    }
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(report,indent=2,sort_keys=True,default=str)+"\n")
    return report

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    r=asyncio.run(run(a.out))
    print("P6B2_REAL_RELEASED_MCP_PROTOCOL",r["official_package_versions"],
          r["scenario_bool"]["native_validation"]["2025-11-25"]["accepted"],
          r["scenario_recursive"]["live_mcp"]["list_tools_success"],flush=True)
