#!/usr/bin/env python3
"""Restore the exact archived ConditionEffect v0.7 ZIP; Python 3.9+."""
import base64
import hashlib
import io
from pathlib import Path
from zipfile import ZipFile

HERE = Path(__file__).resolve().parent
ENCODED = HERE / "archive" / "PLDI_2027_ConditionEffect_v07.zip.base64"
EXPECTED_SHA256 = "2612dfc24a580de882ae9a2f64f6e0eb5dc006de6fc15ab65d79cc0aca7c2e70"
DEST = HERE / "restored"

payload = base64.b64decode(ENCODED.read_text("ascii"), validate=False)
actual = hashlib.sha256(payload).hexdigest()
if actual != EXPECTED_SHA256:
    raise SystemExit("FAIL: archive SHA-256 mismatch: " + actual)

with ZipFile(io.BytesIO(payload)) as zf:
    for info in zf.infolist():
        # Archive extraction is intentionally limited to the known top-level folder.
        name = info.filename.replace("\\", "/")
        if (name.startswith("/") or ".." in Path(name).parts or
                not name.startswith("PLDI_2027_ConditionEffect_v07/")):
            raise SystemExit("FAIL: unsafe archive member " + name)
    zf.extractall(DEST)
    bad = zf.testzip()
    if bad:
        raise SystemExit("FAIL: corrupt ZIP member " + bad)
print("RESTORED", str(DEST / "PLDI_2027_ConditionEffect_v07"))
print("SHA256", actual)
