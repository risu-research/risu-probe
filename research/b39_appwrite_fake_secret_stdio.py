#!/usr/bin/env python3
"""Credential-free synthetic MCP stdio peer. Values labeled FAKE_B39 never real secrets."""
import json,os,sys
from pathlib import Path
FAKE="FAKE_B39_PASSWORD_SAMPLE_NOT_REAL"
def make(req):
 i=req.get("id")
 if i is None:return None
 m=req.get("method")
 if m=="initialize":
  return {"jsonrpc":"2.0","id":i,"result":{"protocolVersion":req.get("params",{}).get("protocolVersion","2025-11-25"),"capabilities":{"tools":{}},"serverInfo":{"name":"B39-fake-secrets","version":"1"}}}
 if m=="tools/list":
  return {"jsonrpc":"2.0","id":i,"result":{"tools":[{"name":"read_dummy","inputSchema":{"type":"object","properties":{}}}]}}
 if m=="tools/call" and req.get("params",{}).get("name")=="read_dummy":
  data={"secret":FAKE,"title":"Visible summary","nested":{"secret":FAKE+"2"},"blank":{"secret":""}}
  return {"jsonrpc":"2.0","id":i,"result":{"content":[{"type":"text","text":json.dumps(data)}],"structuredContent":data,"isError":False}}
 return {"jsonrpc":"2.0","id":i,"error":{"code":-32601,"message":"unrecognized fake tool"}}
def main():
 p=Path(os.environ["B39_APPWRITE_WIRE"])
 if not p.parent.is_dir() or p.is_symlink():raise SystemExit("BAD_WIRE_PATH")
 with p.open("w",encoding="utf-8") as f:
  for raw in sys.stdin.buffer:
   q=json.loads(raw.decode("utf-8"))
   r=make(q)
   f.write(json.dumps({"request":q,"response":r},sort_keys=True)+"\n");f.flush()
   if r is not None:
    sys.stdout.buffer.write((json.dumps(r,ensure_ascii=True,separators=(",",":"))+"\n").encode("utf-8"))
    sys.stdout.flush()
if __name__=="__main__":main()
