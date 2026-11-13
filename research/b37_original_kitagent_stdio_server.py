#!/usr/bin/env python3
"""First-party controlled MCP JSON-RPC stdio server for B37 upstream replay.

This implements the actual MCP initialize/list-tools/call-tool wire exchange.
No sockets, arbitrary commands, files other than the explicit trace, secrets
or external network. Third-party ORIGINAL source executes only in the client.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys


def answer(req: dict) -> dict | None:
    i=req.get("id")
    method=req.get("method")
    if i is None:
        return None  # initialized notification
    if method=="initialize":
        payload={
          "protocolVersion":"2024-11-05",
          "capabilities":{"tools":{}},
          "serverInfo":{"name":"RISU-B37-controlled","version":"1"},
        }
    elif method=="tools/list":
        payload={"tools":[
          {"name":name,"description":"controlled no-network "+name,
           "inputSchema":{"type":"object","properties":{}}}
          for name in ["normal","refusal","empty_refusal","multi","rpc_error"]
        ]}
    elif method=="tools/call":
        tool=req.get("params",{}).get("name")
        if tool=="normal":
            payload={"content":[{"type":"text","text":"normal result"}],"isError":False}
        elif tool=="refusal":
            payload={"content":[{"type":"text","text":"VALIDATION_FAILED: missing document"}],
                     "isError":True}
        elif tool=="empty_refusal":
            payload={"content":[],"isError":True}
        elif tool=="multi":
            payload={"content":[{"type":"text","text":"first"},{"type":"text","text":"second"}],
                     "isError":False}
        elif tool=="rpc_error":
            return {"jsonrpc":"2.0","id":i,
                    "error":{"code":-32603,"message":"controlled JSON-RPC failure"}}
        else:
            return {"jsonrpc":"2.0","id":i,
                    "error":{"code":-32601,"message":"unknown controlled tool"}}
    else:
        return {"jsonrpc":"2.0","id":i,
                "error":{"code":-32601,"message":"method not found"}}
    return {"jsonrpc":"2.0","id":i,"result":payload}


def main():
    trace=os.environ.get("B37_NATIVE_WIRE_LOG")
    if not trace:
        raise SystemExit("B37_MISSING_EXPLICIT_TRACE_PATH")
    dest=Path(trace)
    if not dest.parent.is_dir() or dest.is_symlink():
        raise SystemExit("B37_UNSAFE_TRACE_PATH")
    with dest.open("w",encoding="utf-8") as out:
        for raw in sys.stdin.buffer:
            try:
                req=json.loads(raw.decode("utf-8"))
                resp=answer(req)
                if resp is None:
                    out.write(json.dumps({"request":req,"notification":True})+"\n")
                    out.flush()
                    continue
                out.write(json.dumps({"request":req,"response":resp},
                                     ensure_ascii=False,sort_keys=True)+"\n")
                out.flush()
                sys.stdout.write(json.dumps(resp,ensure_ascii=False,separators=(",",":"))+"\n")
                sys.stdout.flush()
            except (UnicodeError,ValueError,TypeError,KeyError) as exc:
                print("B37_CONTROLLED_PROTOCOL_ERROR "+type(exc).__name__,file=sys.stderr)
                return 2
    return 0


if __name__=="__main__":
    raise SystemExit(main())
