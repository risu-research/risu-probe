"""Transport tee: preserve exact bytes of real client/server stdio JSON-RPC.

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


def proxy(capture: Path) -> int:
    path = Path(__file__).resolve().with_name("stdio_server.py")
    if not path.is_file() or capture.exists() or capture.is_symlink():
        raise RuntimeError("Expected trusted local server and new capture file")
    capture.parent.mkdir(parents=True, exist_ok=True)
    safe_env = {
        k: v for k, v in os.environ.items()
        if k in ("PATH", "SYSTEMROOT", "WINDIR", "PYTHONPATH", "VIRTUAL_ENV",
                 "HOME", "TMP", "TEMP", "TMPDIR", "LANG", "LC_ALL")
    }
    safe_env["PYTHONUNBUFFERED"] = "1"
    child = subprocess.Popen(
        [sys.executable, "-u", str(path)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env=safe_env, cwd=str(path.parent)
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
    a=p.parse_args()
    try: raise SystemExit(proxy(a.capture))
    except (OSError, ValueError, RuntimeError):
        print("P6B11_PROXY_CAPTURE_UNAVAILABLE",file=sys.stderr)
        raise SystemExit(2)
