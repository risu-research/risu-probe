"""External upstream source-only stdio tee: preserve exact real MCP transport bytes.

This proxy is a local, preselected Python command, never an arbitrary executable.
Capture format preserves base64 of the original frame bytes and SHA256, not
fabricated JSON-RPC envelopes. Synthetic test data only. Offline execution.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import threading

MAX_FRAME = 524288
MAX_BYTES = 4194304
MAX_FRAMES = 1024


def proxy(capture: Path, root: Path, allowed: Path) -> int:
    workspace=Path(__file__).resolve().parents[2]
    expected={
        ".b11-upstream-FS5184-old":(
            "3bd1337713c796ada8a3dbb088dd911aa83dc932",
            "b1a90a409469fb34e7580cce3356d02908be34b3"),
        ".b11-upstream-FS5184-fixed":(
            "0dce8bd9b65d91a6f7afe1d8f99ffea5d5cf8fe4",
            "266801190ce1cc461c2c770b756161cc4ca03b99"),
    }
    root=root.resolve(strict=True)
    allowed=allowed.resolve(strict=True)
    if (root.parent!=workspace or root.name not in expected
        or allowed.parent!=workspace or allowed.name!=".b11-external-synthetic-allowed"
        or (allowed/"sample.txt").read_text(encoding="utf-8")!="one\ntwo\nthree\nfour\n"):
        raise RuntimeError("Refuse unpinned executable or unexpected synthetic path")
    sha,blob=expected[root.name]
    for args,want in ((["rev-parse","HEAD"],sha),
                      (["rev-parse","HEAD:src/filesystem/server.ts"],blob)):
        actual=subprocess.check_output(
            ["git","-C",str(root),*args],text=True,timeout=5).strip()
        if actual!=want:
            raise RuntimeError("Pinned original upstream source identity mismatch")
    exe=(root/"src/filesystem/dist/index.js").resolve(strict=True)
    if not exe.is_file() or not exe.is_relative_to(root) or capture.exists() or capture.is_symlink():
        raise RuntimeError("Expected exact original built upstream source and new capture")
    command=["node",str(exe),str(allowed)]
    capture.parent.mkdir(parents=True, exist_ok=True)
    safe_env = {
        k: v for k, v in os.environ.items()
        if k in ("PATH", "SYSTEMROOT", "WINDIR", "PYTHONPATH", "VIRTUAL_ENV",
                 "HOME", "TMP", "TEMP", "TMPDIR", "LANG", "LC_ALL")
    }
    safe_env["CI"] = "true"
    safe_env["NODE_ENV"] = "production"
    safe_env["NO_COLOR"] = "1"
    child = subprocess.Popen(
        command,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env=safe_env, cwd=str(exe.parent)
    )
    lock = threading.Lock()
    totals = {"frames":0,"bytes":0}
    errors = []
    with capture.open("x", encoding="utf-8") as stream:
        def relay(src, dst, direction):
            try:
                while True:
                    raw = src.readline(MAX_FRAME + 1)
                    if not raw:
                        break
                    with lock:
                        totals["frames"] += 1
                        totals["bytes"] += len(raw)
                        if (len(raw)>MAX_FRAME or not raw.endswith(b"\n")
                              or totals["frames"]>MAX_FRAMES or totals["bytes"]>MAX_BYTES):
                            raise RuntimeError("Refuse oversized or unterminated stdio frame")
                        frame={
                            "schema":"risu-b11-raw-stdio-frame-v1",
                            "sequence":totals["frames"],
                            "direction":direction,
                            "raw_base64":base64.b64encode(raw).decode("ascii"),
                            "frame_sha256":hashlib.sha256(raw).hexdigest(),
                            "frame_length":len(raw),
                        }
                        stream.write(json.dumps(frame,sort_keys=True)+"\n")
                        stream.flush()
                    dst.write(raw)
                    dst.flush()
            except (OSError, ValueError, RuntimeError) as e:
                errors.append(type(e).__name__)
                child.kill()
            finally:
                try: dst.close()
                except OSError: pass
        assert child.stdin is not None and child.stdout is not None
        a=threading.Thread(target=relay,args=(sys.stdin.buffer,child.stdin,"client_to_server"),daemon=True)
        b=threading.Thread(target=relay,args=(child.stdout,sys.stdout.buffer,"server_to_client"),daemon=True)
        a.start();b.start()
        a.join(timeout=35)
        if a.is_alive(): child.kill()
        try: status=child.wait(timeout=8)
        except subprocess.TimeoutExpired:
            child.kill();status=child.wait(timeout=4)
        b.join(timeout=5)
    if errors or status not in (0,):
        return 2
    return 0


if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--capture",required=True,type=Path)
    p.add_argument("--root",required=True,type=Path)
    p.add_argument("--allowed",required=True,type=Path)
    a=p.parse_args()
    try: raise SystemExit(proxy(a.capture,a.root,a.allowed))
    except (OSError, ValueError, RuntimeError):
        print("P6B11_PROXY_CAPTURE_UNAVAILABLE",file=sys.stderr)
        raise SystemExit(2)
