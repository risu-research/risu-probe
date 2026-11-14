#!/usr/bin/env python3
"""B39 synthetic, credential-free MCP stdio producer for KiraAI normal budget test."""
import json,os,sys
from pathlib import Path
DATA={
 "short":"short response",
 "long_ascii":"A"*850,
 "long_unicode":"서울의 알림 내용 " * 130,
 "base64":"iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB" * 60,
 "empty":"",
}
def reply(req):
    i=req.get("id")
    if i is None:return None
    method=req.get("method")
    if method=="initialize":
        return {"jsonrpc":"2.0","id":i,"result":{
          "protocolVersion":req.get("params",{}).get("protocolVersion","2025-11-25"),
          "capabilities":{"tools":{}},
          "serverInfo":{"name":"RISU-B39-budget-controlled","version":"1"}}}
    if method=="tools/list":
        return {"jsonrpc":"2.0","id":i,"result":{"tools":[
            {"name":n,"description":n,"inputSchema":{"type":"object","properties":{}}}
            for n in DATA]}}
    if method=="tools/call":
        n=req.get("params",{}).get("name")
        if n in DATA:return {"jsonrpc":"2.0","id":i,"result":{
          "content":[{"type":"text","text":DATA[n]}],"isError":False}}
    return {"jsonrpc":"2.0","id":i,
            "error":{"code":-32601,"message":"unsupported tool"}}
def main():
    dest=os.environ.get("B39_KIRA_WIRE")
    if not dest:raise SystemExit("B39_WIRE_OUTPUT_MISSING")
    p=Path(dest)
    if not p.parent.is_dir() or p.is_symlink():raise SystemExit("B39_INVALID_OUTPUT")
    with p.open("w",encoding="utf-8") as f:
        for raw in sys.stdin.buffer:
            req=json.loads(raw.decode("utf-8"))
            r=reply(req)
            f.write(json.dumps({"request":req,"response":r},ensure_ascii=False,
                               sort_keys=True)+"\n");f.flush()
            if r is not None:
                sys.stdout.write(json.dumps(r,ensure_ascii=False,separators=(",",":"))+"\n")
                sys.stdout.flush()
if __name__=="__main__":main()
