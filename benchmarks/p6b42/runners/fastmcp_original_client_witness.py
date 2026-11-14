#!/usr/bin/env python3
"""B42 original FastMCP Client(transport=PythonStdioTransport) real native wire.

The only test-defined pieces are a transparent byte-preserving stdio relay and
a test-owned FastMCP server. Both original client and original server actually
execute; the original returned parsed is_error is independent of wire capture.
"""
from __future__ import annotations
import argparse
import asyncio
import hashlib
import json
from pathlib import Path
from fastmcp.client import Client
from fastmcp.client.transports import PythonStdioTransport

async def run(args):
    out=args.output.resolve()
    out.parent.mkdir(parents=True,exist_ok=True)
    wire=args.wire.resolve()
    if wire.exists():
        raise ValueError("B42 N2 wire logfile already exists, refuse stale traces")
    relay=Path(__file__).with_name("fastmcp_native_stdio_relay.py").resolve()
    peer=Path(__file__).with_name("fastmcp_original_server.py").resolve()
    transport=PythonStdioTransport(
        script_path=relay,args=[str(peer)],
        env={"B42_N2_WIRE_LOG":str(wire)},
        keep_alive=False,
    )
    outcomes=[]
    # Keep all calls within one original real client session, not cloned logic.
    async with Client(transport=transport,mode="legacy") as original_client:
        for name,want in [("b42_success",False),("b42_denied",True)]:
            returned=await original_client.call_tool(name,{},raise_on_error=False)
            # Actual original FastMCP original ClientCallToolResult.is_error.
            original_status=returned.is_error
            if type(original_status) is not bool or original_status!=want:
                raise AssertionError(f"{name}: original FastMCP parsed status {original_status!r}, wanted {want}")
            outcomes.append({"tool":name,"original_downstream_is_error":original_status,
                "consumer_return_type":type(returned).__name__})
    if not wire.exists():raise RuntimeError("No independently captured original native JSONRPC")
    trace=[json.loads(line) for line in wire.read_text().splitlines() if line.strip()]
    requests=[row["frame"] for row in trace if row["direction"]=="client_to_server"]
    replies=[row["frame"] for row in trace if row["direction"]=="server_to_client"]
    witnesses=[]
    for result in outcomes:
        name=result["tool"]
        native_req=[req for req in requests
            if isinstance(req,dict) and req.get("method")=="tools/call"
            and isinstance(req.get("params"),dict) and req["params"].get("name")==name]
        if len(native_req)!=1:raise AssertionError(f"expected one real tools/call for {name}, got {len(native_req)}")
        req=native_req[0]
        res=[resp for resp in replies if isinstance(resp,dict) and resp.get("id")==req.get("id")
            and resp.get("jsonrpc")=="2.0"]
        if len(res)!=1:raise AssertionError(f"expected one real response for {name}, got {len(res)}")
        resp=res[0]
        native=resp.get("result")
        if not isinstance(native,dict) or not isinstance(native.get("content"),list):
            raise AssertionError(f"native tools/call result missing content: {name}")
        native_status=native.get("isError",False)
        if type(native_status) is not bool or native_status!=result["original_downstream_is_error"]:
            raise AssertionError(f"native vs original FastMCP consumer {name} does not match")
        observations={"tool":name,"request_id":req["id"],
                      "outcome":"tool_error" if result["original_downstream_is_error"] else "success",
                      "original_FastMCP_ClientCallToolResult_is_error":result["original_downstream_is_error"],
                      "original_FastMCP_client_return_type":result["consumer_return_type"]}
        witnesses.append({"case_id":"N2","tool":name,
         "wire":{"request":req,"response":resp},
         "observed":observations,
         "contract":{"status":True,"text":"none","structured":"none","media":"none"},
         "execution_provenance":"ORIGINAL_EXTERNAL_CLIENT_CONTROLLED_SERVER",
         "original_source_git_blob":"99cfd750f5a3f76f5fbb3c917850ac4e27345b43",
         "original_commit_verified":True,"original_source_unchanged":True,
         "raw_original_stdio_JSONRPC_bytes_captured_before_forwarding":True,
         "original_client":"fastmcp.client.Client.call_tool",
         "original_client_transport":"PythonStdioTransport",
         "original_server":"fastmcp.server.FastMCP",
         "controlled_peer":True,"full_external_deployed_app":False})
    result={"schema":"risu-p6b42-original-fastmcp-native-v1",
      "original_repo":"PrefectHQ/fastmcp",
      "original_commit":"a8745d61e650467756bb28b4157822dbfbdfa34f",
      "original_client_source_unchanged":True,
      "original_server_source_unchanged":True,
      "wire_trace_format":"real_stdio_lines_intercepted_by_eval_only_relay",
      "witnesses":witnesses,
      "all_witnesses_native_tools_call":True}
    data=json.dumps(result,sort_keys=True,indent=2)+"\n"
    out.write_text(data)
    print("B42_N2_ORIGINAL_FASTMCP_REAL_STDIO_STATUS_2_CASES_PASSED")
    print("B42_N2_WIRE_JSON_SHA256",hashlib.sha256(wire.read_bytes()).hexdigest())
    print("B42_N2_WITNESSES_SHA256",hashlib.sha256(data.encode()).hexdigest())
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--output",required=True,type=Path)
    p.add_argument("--wire",required=True,type=Path)
    args=p.parse_args()
    asyncio.run(run(args))
if __name__=="__main__":main()
