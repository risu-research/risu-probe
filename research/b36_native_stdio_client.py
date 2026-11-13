#!/usr/bin/env python3
"""B36 controlled native stdio MCP wire audit, separately labeled as CONTROL.

The child is an original safe local fixture built on genuine MCP SDK 2.3.0.
This does NOT reproduce an upstream GitHub bug. It validates what a lossy
consumer would discard from a real MCP wire reply and a clean normal control.
"""
from __future__ import annotations

import asyncio
import hashlib
import importlib.metadata
import json
from pathlib import Path
import sys


HERE = Path(__file__).resolve().parent
SERVER = HERE / "b36_native_stdio_server.py"
EXPECTED_SDK = "2.3.0"
RECORDED = []


def insist(value, code):
    if not value:
        raise RuntimeError("B36_STDIO_" + code)


async def main():
    sdk = importlib.metadata.version("mcp")
    insist(sdk == EXPECTED_SDK, "PINNED_SDK_MISMATCH")
    insist(SERVER.is_file(), "MISSING_LOCAL_CONTROLLED_SERVER")
    source_sha = hashlib.sha256(SERVER.read_bytes()).hexdigest()
    proc = await asyncio.create_subprocess_exec(
        sys.executable, str(SERVER),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    async def send(message):
        raw=json.dumps(message,ensure_ascii=False,separators=(",",":"))
        proc.stdin.write((raw+"\n").encode("utf-8"))
        await asyncio.wait_for(proc.stdin.drain(),timeout=12)
        return raw

    async def request(i,method,params=None):
        req={"jsonrpc":"2.0","id":i,"method":method}
        if params is not None:
            req["params"]=params
        original=await send(req)
        messages=[]
        for _ in range(12):
            raw=await asyncio.wait_for(proc.stdout.readline(),timeout=20)
            insist(bool(raw),"SERVER_STOPPED_BEFORE_RESPONSE")
            obj=json.loads(raw)
            messages.append(raw.decode("utf-8").rstrip("\r\n"))
            if obj.get("id")==i:
                insist("error" not in obj,method+"_JSONRPC_ERROR_"+str(obj.get("error")))
                RECORDED.append({"request":original,"responses":messages})
                return obj.get("result")
        raise RuntimeError("B36_STDIO_TOO_MANY_NONMATCHING_PROTOCOL_RESPONSES")

    try:
        hello=await request(1,"initialize",{
            "protocolVersion":"2025-11-25",
            "capabilities":{},
            "clientInfo":{"name":"RISU-B36-controlled-stdio-client","version":"0.1"},
        })
        insist(isinstance(hello,dict),"NO_INITIALIZE_RESULT")
        insist(hello.get("protocolVersion")=="2025-11-25","UNEXPECTED_PROTOCOL_VERSION")
        await send({"jsonrpc":"2.0","method":"notifications/initialized"})
        listing=await request(2,"tools/list",{})
        names={t.get("name") for t in listing.get("tools",[])}
        insist({"rich_result","plain_result","error_result"}<=names,
               "INCOMPLETE_TOOL_LIST")
        rich=await request(3,"tools/call",{"name":"rich_result","arguments":{}})
        plain=await request(4,"tools/call",{"name":"plain_result","arguments":{}})
        err=await request(5,"tools/call",{"name":"error_result","arguments":{}})
        insist(len(rich.get("content",[]))==3,"RICH_MULTIBLOCK_ORIGINAL_MISSING")
        insist([x.get("type") for x in rich["content"]]==["text","image","text"],
               "RICH_MEDIA_ORIGINAL_MISSING")
        insist(rich["content"][2].get("text")=="second message",
               "ORIGINAL_SECOND_BLOCK_CHANGED")
        insist(rich.get("structuredContent")=={"item_id":"B36-CONTROL","quantity":17},
               "ORIGINAL_STRUCTURED_CHANNEL_MISSING")
        insist(rich.get("isError") is not True,"RICH_ERRONEOUS_ISERROR")
        insist(len(plain.get("content",[]))==1 and
               plain.get("structuredContent") is None and
               plain["content"][0].get("text")=="safe singleton",
               "NORMAL_CONTROL_ALTERED")
        insist(err.get("isError") is True and
               err["content"][0].get("text")=="VALIDATION_FAILED: missing document",
               "ERROR_STATUS_OR_REASON_DROPPED")
        # Deterministic example consumers; they are part of this controlled
        # fixture, NOT claims about a third-party implementation.
        first_only_rich=[rich["content"][0]]
        first_only_plain=[plain["content"][0]]
        lose_error_status={"content":err["content"]}
        assert len(first_only_rich)==1 and len(rich["content"])==3
        assert rich.get("structuredContent") is not None
        assert first_only_plain==plain["content"]
        assert lose_error_status.get("isError") is None and err["isError"] is True
        report={
           "schema":"risu-b36-native-stdio-controlled-original-wire-v1",
           "fixture_type":"FIRST_PARTY_SYNTHETIC_CONTROL_NOT_THIRD_PARTY_UPSTREAM",
           "genuine_mcp_sdk_version":sdk,
           "transport":"ACTUAL_SUBPROCESS_STDIO_JSONRPC",
           "protocol_version":hello["protocolVersion"],
           "server_source_sha256":source_sha,
           "raw_jsonrpc_recorded":True,
           "third_party_original_server_executed":False,
           "network_or_privileged_resources":False,
           "observations":{
              "native_rich_result_content_blocks":len(rich["content"]),
              "native_rich_content_types":[x["type"] for x in rich["content"]],
              "native_rich_structured_content":rich["structuredContent"],
              "first_only_projection_lost_blocks":len(rich["content"])-len(first_only_rich),
              "first_only_projection_lost_structured_channel":True,
              "normal_single_text_first_only_lost_content":False,
              "mcp_error_flag_true":err["isError"] is True,
              "lossy_error_text_only_mapping_lost_error_flag":True,
           },
           "requests_and_original_raw_server_responses":RECORDED,
           "no_population_false_positive_rate_claim":True,
           "no_external_mcp_defect_reproduced":True,
        }
        out=HERE/"out"
        out.mkdir(exist_ok=True)
        path=out/"B36_CONTROLLED_NATIVE_STDIO_WIRE.json"
        path.write_text(json.dumps(report,sort_keys=True,indent=2,ensure_ascii=False)+"\n",
                        encoding="utf-8")
        print(json.dumps(report["observations"],sort_keys=True))
        print("B36_NATIVE_MCP_STDIO_CONTROLLED_ORIGINAL_WIRE_PASS")
        print("B36_CONTROLLED_NATIVE_WIRE_SHA256="+hashlib.sha256(path.read_bytes()).hexdigest())
    finally:
        if proc.stdin and not proc.stdin.is_closing():
            proc.stdin.close()
        try:
            await asyncio.wait_for(proc.wait(),timeout=12)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
        if proc.returncode is not None:
            insist(proc.returncode==0,"SERVER_PROCESS_EXIT_"+str(proc.returncode))


if __name__=="__main__":
    asyncio.run(main())
