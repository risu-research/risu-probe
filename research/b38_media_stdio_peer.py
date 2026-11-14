#!/usr/bin/env python3
"""Bounded synthetic MCP stdio peer for original Onyx *function-only* replay.

The original external code compiled from exact pinned Git AST function
transforms real official MCP SDK CallToolResult content. No external network.
"""
import json
import os
from pathlib import Path
import sys

PNG="iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
WAV="UklGRiQAAABXQVZFZm10IBAAAAABAAEAESsAACJWAAACABAAZGF0YQAAAAA="

def reply(req):
    ident=req.get("id")
    if ident is None:return None
    op=req.get("method")
    if op=="initialize":
        return {"jsonrpc":"2.0","id":ident,"result":{
            "protocolVersion":req.get("params",{}).get("protocolVersion","2025-11-25"),
            "capabilities":{"tools":{}},
            "serverInfo":{"name":"B38-media-control","version":"1.0"}}}
    if op=="tools/list":
        return {"jsonrpc":"2.0","id":ident,"result":{"tools":[
            {"name":name,"description":name,
             "inputSchema":{"type":"object","properties":{}}}
            for name in ("text","multi","image_only","audio_only","structured_only")
        ]}}
    if op!="tools/call":
        return {"jsonrpc":"2.0","id":ident,"error":{"code":-32601,"message":"method not found"}}
    name=req.get("params",{}).get("name")
    if name=="text":
        result={"content":[{"type":"text","text":"normal result"}],"isError":False}
    elif name=="multi":
        result={"content":[{"type":"text","text":"first"},
                           {"type":"text","text":"second"}],"isError":False}
    elif name=="image_only":
        result={"content":[{"type":"image","data":PNG,"mimeType":"image/png"}],
                "isError":False}
    elif name=="audio_only":
        result={"content":[{"type":"audio","data":WAV,"mimeType":"audio/wav"}],
                "isError":False}
    elif name=="structured_only":
        result={"content":[],"structuredContent":{"item_id":"B38","count":17},
                "isError":False}
    else:
        return {"jsonrpc":"2.0","id":ident,
                "error":{"code":-32601,"message":"unknown tool"}}
    return {"jsonrpc":"2.0","id":ident,"result":result}

def main():
    dest=os.environ.get("B38_MEDIA_WIRE_PATH")
    if not dest:raise SystemExit("B38_NO_ORIGINAL_WIRE_DESTINATION")
    path=Path(dest)
    if not path.parent.is_dir() or path.is_symlink():
        raise SystemExit("B38_UNSAFE_LOG_DESTINATION")
    with path.open("w",encoding="utf-8") as out:
        for raw in sys.stdin.buffer:
            req=json.loads(raw.decode("utf-8"))
            resp=reply(req)
            out.write(json.dumps({"request":req,"response":resp},
                                 ensure_ascii=False,sort_keys=True)+"\n")
            out.flush()
            if resp is not None:
                sys.stdout.write(json.dumps(resp,separators=(",",":"))+"\n")
                sys.stdout.flush()

if __name__=="__main__":
    main()
