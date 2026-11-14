#!/usr/bin/env python3
"""B38 controlled real MCP stdio peer, JSON-RPC 2.0, raw wire logging.

Only synthetic fixed values; no network, no user data, no external process.
The client under test is the ORIGINAL external Waterworks MCP client module.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import sys

def handle(req:dict) ->dict|None:
    rid=req.get("id")
    meth=req.get("method")
    if rid is None:
        return None
    if meth=="initialize":
        return {"jsonrpc":"2.0","id":rid,"result":{
            "protocolVersion":req.get("params",{}).get("protocolVersion","2025-11-25"),
            "capabilities":{"tools":{}},
            "serverInfo":{"name":"RISU-B38-test-peer","version":"1.0"}}}
    if meth=="tools/list":
        names=("normal","refusal","empty_refusal","multi","structured","rpc_error")
        return {"jsonrpc":"2.0","id":rid,"result":{"tools":[
            {"name":name,"description":"synthetic "+name,
             "inputSchema":{"type":"object","properties":{}}} for name in names]}}
    if meth=="ping":
        return {"jsonrpc":"2.0","id":rid,"result":{}}
    if meth!="tools/call":
        return {"jsonrpc":"2.0","id":rid,"error":{
            "code":-32601,"message":"unsupported controlled method"}}
    name=req.get("params",{}).get("name")
    if name=="normal":
        result={"content":[{"type":"text","text":"normal result"}],"isError":False}
    elif name=="refusal":
        result={"content":[{"type":"text","text":"VALIDATION_FAILED: missing document"}],
                "isError":True}
    elif name=="empty_refusal":
        result={"content":[],"isError":True}
    elif name=="multi":
        result={"content":[{"type":"text","text":"first"},
                           {"type":"text","text":"second"}],"isError":False}
    elif name=="structured":
        result={"content":[],"structuredContent":{"item_id":"W38","quantity":17},
                "isError":False}
    elif name=="rpc_error":
        return {"jsonrpc":"2.0","id":rid,"error":{
            "code":-32603,"message":"controlled transport error"}}
    else:
        return {"jsonrpc":"2.0","id":rid,"error":{
            "code":-32601,"message":"unknown controlled tool"}}
    return {"jsonrpc":"2.0","id":rid,"result":result}

def main()->int:
    target=os.environ.get("B38_NATIVE_WIRE_RECORD")
    if not target:
        print("B38_NO_TRACE_DESTINATION",file=sys.stderr)
        return 2
    path=Path(target)
    if not path.parent.is_dir() or path.is_symlink():
        print("B38_UNSAFE_TRACE_DESTINATION",file=sys.stderr)
        return 2
    with path.open("w",encoding="utf-8") as trace:
        for raw in sys.stdin.buffer:
            try:
                request=json.loads(raw.decode("utf-8"))
                answer=handle(request)
                trace.write(json.dumps({"request":request,"response":answer},
                                       sort_keys=True,ensure_ascii=False)+"\n")
                trace.flush()
                if answer is not None:
                    sys.stdout.write(json.dumps(answer,separators=(",",":"),
                                                ensure_ascii=False)+"\n")
                    sys.stdout.flush()
            except (ValueError,UnicodeError,TypeError,KeyError) as exc:
                print("B38_PROTOCOL_REJECTED_"+type(exc).__name__,file=sys.stderr)
                return 2
    return 0

if __name__=="__main__":
    raise SystemExit(main())
