"""P6-B22 separate POSIX resource owner's private-key custody and grant issuance.

Run this script ONLY under the distinct test-resource-owner Unix UID in CI.
Private signing keys are generated under the owner's OS-protected home and
NEVER exported, copied to RISU runner, or made readable by the executor.
Release artifacts contain only the public root, signed grants and revocations.

This proves separate OS principal control of synthetic fixtures, not that a
third-party human authenticated or consented to production resource access.
"""
from __future__ import annotations
import argparse,base64
from datetime import datetime,timezone,timedelta
import hashlib,json,os
from pathlib import Path
import secrets
import stat

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


ROOT="risu-b22-os-owner-root-v1"
GRANT="risu-b22-precall-owner-grant-v1"
REV="risu-b22-owner-revocation-v1"
PREFIX=b"RISU-B22-OS-OWNER-PRECALL-V1\x00"
REVPREFIX=b"RISU-B22-OS-OWNER-REVOCATION-V1\x00"


def canon(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),
                     ensure_ascii=False,allow_nan=False).encode()
def sha(b):return hashlib.sha256(b).hexdigest()
def b64(b):return base64.b64encode(b).decode()
def time_utc(t=None):
    return (t or datetime.now(timezone.utc)).isoformat(timespec="seconds").replace("+00:00","Z")
def load(path):return json.loads(Path(path).read_text())
def write(path,obj):
    path=Path(path)
    with path.open("x") as f:
        json.dump(obj,f,sort_keys=True,indent=2)
        f.write("\n")
    os.chmod(path,0o644)


def signing_key(path):
    path=Path(path)
    assert path.is_file() and not path.is_symlink()
    assert path.stat().st_uid==os.geteuid() and path.stat().st_mode&0o077==0
    data=path.read_bytes()
    return serialization.load_pem_private_key(data,password=None)


def bootstrap(a):
    assert os.name=="posix" and os.geteuid()!=0
    private=Path(a.private)
    assert not private.exists()
    assert private.parent.stat().st_uid==os.geteuid()
    assert private.parent.stat().st_mode&0o077==0
    key=Ed25519PrivateKey.generate()
    pem=key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
    fd=os.open(private,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    try:os.write(fd,pem);os.fsync(fd)
    finally:os.close(fd)
    public=key.public_key().public_bytes(
       serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    directory=Path(a.directory)
    assert directory.is_absolute() and directory.is_dir()
    assert directory.stat().st_uid==os.geteuid()
    assert os.geteuid()!=a.executor_uid
    root={
      "schema":ROOT,"issuer":a.issuer,
      "owner_uid":os.geteuid(),"executor_uid":a.executor_uid,
      "resource_dir":str(directory),"resource_id":a.resource_id,
      "key_id":sha(public),"ed25519_public_key_b64":b64(public),
      "approved_tool":"write_file","server_module":"filesystem_mcp",
      "wheel_sha256":a.wheel_sha256,
      "trust_level":"OS_UID_ISOLATED_FIXTURE_ONLY"
    }
    write(a.root,root)
    print("B22_OWNER_PRIVATE_KEY_OS_UID",os.geteuid())
    print("B22_OWNER_PUBLIC_TRUST_ROOT_SHA256",sha(Path(a.root).read_bytes()))
    print("B22_OWNER_PRIVATE_KEY_NEVER_EXPORTED")


def issue(a):
    key=signing_key(a.private)
    root=load(a.root)
    assert root["owner_uid"]==os.geteuid()
    assert Path(root["resource_dir"]).stat().st_uid==os.geteuid()
    request=load(a.request)
    assert request["method"]=="tools/call"
    assert request["params"]["name"]==root["approved_tool"]
    values=request["params"]["arguments"]
    assert set(values)=={"path","content","append"} and values["append"] is False
    target=Path(values["path"])
    assert target.parent==Path(root["resource_dir"])
    assert a.allow_operation in ("CREATE","REPLACE","NO_CHANGE")
    if target.exists():
        assert target.is_file() and target.stat().st_size<=4096
        before=sha(target.read_bytes())
    else:before=None
    content=values["content"].encode("utf-8")
    assert len(content)<=4096
    now=datetime.now(timezone.utc)
    grant_policy={
      "audience":"risu-b22-unmodified-mcp-gateway",
      "issuer":root["issuer"],
      "owner_uid":root["owner_uid"],"executor_uid":root["executor_uid"],
      "resource_id":root["resource_id"],
      "resource_dir":root["resource_dir"],
      "target_path":str(target),
      "request_sha256":sha(canon(request)),
      "original_tool":"write_file","server_module":"filesystem_mcp",
      "wheel_sha256":root["wheel_sha256"],
      "nonce":secrets.token_hex(32),
      "issued_at":time_utc(now),
      "expires_at":time_utc(now+timedelta(minutes=5)),
      "pre_state_sha256":before,
      "allowed_operation":a.allow_operation,
      "desired_post_sha256":sha(content)
    }
    signed={
       "schema":GRANT,"policy":grant_policy,
       "signature_ed25519_b64":b64(key.sign(PREFIX+canon(grant_policy)))
    }
    write(a.out,signed)
    print("B22_SEPARATE_OWNER_GRANTED",a.allow_operation,
        grant_policy["nonce"],"subject_to_OS_DAC_and_prestate")


def revocation(a):
    key=signing_key(a.private)
    root=load(a.root)
    nonces=a.nonces.split(",") if a.nonces else []
    assert all(len(x)==64 and all(z in "0123456789abcdef" for z in x)
               for x in nonces)
    body={"issuer":root["issuer"],"key_id":root["key_id"],
          "sequence":a.sequence,"published_at":time_utc(),
          "revoked_nonces":nonces}
    msg={
        "schema":REV,"revocations":body,
        "signature_ed25519_b64":b64(key.sign(REVPREFIX+canon(body)))
    }
    write(a.out,msg)
    print("B22_OWNER_PUBLISHED_REVOCATIONS",a.sequence,len(nonces),
          sha(Path(a.out).read_bytes()))


def main():
    p=argparse.ArgumentParser()
    sub=p.add_subparsers(dest="phase",required=True)
    init=sub.add_parser("bootstrap")
    for k in ("private","root","directory","issuer","resource-id",
              "wheel-sha256"):
        init.add_argument("--"+k,required=True)
    init.add_argument("--executor-uid",type=int,required=True)
    grant=sub.add_parser("grant")
    for k in ("private","root","request","out"):
        grant.add_argument("--"+k,required=True)
    grant.add_argument("--allow-operation",
                       choices=("CREATE","REPLACE","NO_CHANGE"),required=True)
    revoke=sub.add_parser("revocation")
    for k in ("private","root","out"):
        revoke.add_argument("--"+k,required=True)
    revoke.add_argument("--sequence",type=int,required=True)
    revoke.add_argument("--nonces",default="")
    a=p.parse_args()
    if a.phase=="bootstrap":bootstrap(a)
    if a.phase=="grant":issue(a)
    if a.phase=="revocation":revocation(a)
if __name__=="__main__":main()
