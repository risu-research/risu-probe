#!/usr/bin/env python3
"""B42 evaluation-only transparent stdio JSON-RPC capture relay.

Original independently authored FastMCP client communicates over original
PythonStdioTransport through this byte-preserving local bridge to an actual
original FastMCP server. Raw request and response lines are captured BEFORE
forwarding, independently of client return values. No upstream code edits.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
import sys
import threading

def main():
    if len(sys.argv)!=2:raise SystemExit("usage: relay.py <synthetic-server.py>")
    logfile=Path(os.environ["B42_N2_WIRE_LOG"])
    logfile.parent.mkdir(parents=True,exist_ok=True)
    lock=threading.Lock()
    server=subprocess.Popen(
        [sys.executable,"-u",sys.argv[1]],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
        bufsize=0,
    )
    assert server.stdin and server.stdout
    def record(direction,data):
        try:frame=json.loads(data)
        except json.JSONDecodeError:return
        with lock, logfile.open("a",encoding="utf8") as f:
            f.write(json.dumps({"direction":direction,"frame":frame},sort_keys=True)+"\n")
            f.flush()
            os.fsync(f.fileno())
    def forward_client_to_server():
        try:
            for line in sys.stdin.buffer:
                record("client_to_server",line)
                server.stdin.write(line)
                server.stdin.flush()
        except (BrokenPipeError,ValueError):
            pass
        finally:
            try:server.stdin.close()
            except OSError:pass
    thread=threading.Thread(target=forward_client_to_server,daemon=True)
    thread.start()
    try:
        for line in server.stdout:
            record("server_to_client",line)
            sys.stdout.buffer.write(line)
            sys.stdout.buffer.flush()
    except (BrokenPipeError,OSError):
        pass
    finally:
        server.terminate()
        try:server.wait(timeout=3)
        except subprocess.TimeoutExpired:server.kill()
if __name__=="__main__":main()
