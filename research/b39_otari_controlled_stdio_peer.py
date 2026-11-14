#!/usr/bin/env python3
"""B39 controlled MCP stdio peer: original external client resource rendering."""
import json,os,sys
from pathlib import Path
BLOB="aGVsbG8="
def make(req):
 i=req.get("id")
 if i is None:return None
 m=req.get("method")
 if m=="initialize":
  return {"jsonrpc":"2.0","id":i,"result":{"protocolVersion":req.get("params",{}).get("protocolVersion","2025-11-25"),"capabilities":{"tools":{}},"serverInfo":{"name":"B39-Otari-stdio","version":"1"}}}
 if m=="tools/list":
  return {"jsonrpc":"2.0","id":i,"result":{"tools":[{"name":n,"description":n,"inputSchema":{"type":"object","properties":{}}} for n in ("normal","embedded_text","embedded_blob","mixed")]}}
 if m=="tools/call":
  n=req.get("params",{}).get("name")
  txt={"type":"text","text":"normal"}
  res={"type":"resource","resource":{"uri":"file:///controlled/hello.txt","text":"PRINT_THIS_ORIGINAL_BODY","mimeType":"text/plain"}}
  blob={"type":"resource","resource":{"uri":"file:///controlled/hello.bin","blob":BLOB,"mimeType":"application/octet-stream"}}
  if n=="normal":content=[txt]
  elif n=="embedded_text":content=[res]
  elif n=="embedded_blob":content=[blob]
  elif n=="mixed":content=[txt,res,blob]
  else:return {"jsonrpc":"2.0","id":i,"error":{"code":-32601,"message":"not found"}}
  return {"jsonrpc":"2.0","id":i,"result":{"content":content,"isError":False}}
 return {"jsonrpc":"2.0","id":i,"error":{"code":-32601,"message":"not supported"}}
def main():
 path=Path(os.environ["B39_OTARI_ORIGINAL_WIRE"])
 if not path.parent.is_dir() or path.is_symlink():raise SystemExit("UNSAFE_LOG_PATH")
 with path.open("w",encoding="utf-8") as f:
  for raw in sys.stdin.buffer:
   q=json.loads(raw.decode("utf-8"))
   r=make(q)
   f.write(json.dumps({"request":q,"response":r},sort_keys=True)+"\n");f.flush()
   if r is not None:
    sys.stdout.buffer.write((json.dumps(r,ensure_ascii=True,separators=(",",":"))+"\n").encode("utf-8"));sys.stdout.flush()
if __name__=="__main__":main()
