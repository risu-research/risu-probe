#!/usr/bin/env python3
"""Original independent Langboard bridge native MCP test peer (first-party).
No external user data, network, account, or foreign server code.
"""
from __future__ import annotations
import json, os, sys
from pathlib import Path
PNG="iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="

def respond(q):
    i=q.get("id")
    if i is None:return None
    method=q.get("method")
    if method=="initialize":
        return {"jsonrpc":"2.0","id":i,"result":{
            "protocolVersion":q.get("params",{}).get("protocolVersion","2025-11-25"),
            "capabilities":{"tools":{}},
            "serverInfo":{"name":"B38-Langboard-first-party-peer","version":"1"}}}
    if method=="tools/list":
        return {"jsonrpc":"2.0","id":i,"result":{"tools":[
            {"name":n,"description":n,"inputSchema":{"type":"object","properties":{}}}
            for n in ("plain_text","structured_only","image_with_structured","multi_text")]}}
    if method!="tools/call":
        return {"jsonrpc":"2.0","id":i,"error":{"code":-32601,"message":"unknown method"}}
    n=q.get("params",{}).get("name")
    if n=="plain_text":
        result={"content":[{"type":"text","text":"plain text"}],"isError":False}
    elif n=="structured_only":
        result={"content":[],"structuredContent":{"id":"N","value":7},"isError":False}
    elif n=="image_with_structured":
        result={"content":[{"type":"image","data":PNG,"mimeType":"image/png"}],
                "structuredContent":{"id":"IMG","value":17},"isError":False}
    elif n=="multi_text":
        result={"content":[{"type":"text","text":"first"},
                           {"type":"text","text":"second"}],"isError":False}
    else:
        return {"jsonrpc":"2.0","id":i,"error":{"code":-32601,"message":"unknown tool"}}
    return {"jsonrpc":"2.0","id":i,"result":result}

def main():
    name=os.environ.get("B38_LANGBOARD_NATIVE_WIRE")
    if not name:raise SystemExit("B38_WIRE_LOG_NOT_SET")
    p=Path(name)
    if not p.parent.is_dir() or p.is_symlink():raise SystemExit("B38_UNSAFE_LOG")
    with p.open("w",encoding="utf-8") as out:
        for raw in sys.stdin.buffer:
            req=json.loads(raw.decode("utf-8"))
            r=respond(req)
            out.write(json.dumps({"request":req,"response":r},
                                 sort_keys=True,ensure_ascii=False)+"\n")
            out.flush()
            if r is not None:
                sys.stdout.write(json.dumps(r,separators=(",",":"),ensure_ascii=False)+"\n")
                sys.stdout.flush()
if __name__=="__main__":
    main()
