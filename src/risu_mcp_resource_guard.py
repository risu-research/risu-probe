"""RISU P6-B26 research fixture: resource-side capability enforcement.

Three separate Linux users in the live benchmark: grant issuer, data server,
requesting agent. The service, not the invoking MCP gateway, checks exactly
which resource and bytes an owner signed. Grant alone is insufficient:
the requester separately signs each HTTP action using a bound Ed25519 key.

This is a narrow reference implementation, NOT a production OAuth server,
not an RFC 9449 DPoP implementation, and not third-party human consent.
"""
from __future__ import annotations
import argparse
import base64
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import sys
import time
import urllib.error
import urllib.request

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

GRANT_SCHEMA = 'risu-b26-owner-object-grant-v1'
PROOF_SCHEMA = 'risu-b26-resource-bound-request-v1'
GRANT_DOMAIN = b'RISU-B26-ISSUER-V1\x00'
PROOF_DOMAIN = b'RISU-B26-HOLDER-V1\x00'
AUDIENCE = 'risu-b26-local-owner-resource-service-a'
ISSUER = 'risu-b26-posix-owner-issuer'
RESOURCE_IDS = ('alpha', 'beta')
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
MAX_BODY = 16384
MAX_VALUE = 1024

class Denied(Exception):
    def __init__(self, code, status=403):
        self.code, self.status = code, status
        super().__init__(code)

def require(ok, code, status=403):
    if not ok:
        raise Denied(code,status)

def digest(x: bytes) -> str:
    return hashlib.sha256(x).hexdigest()

def canonical(x) -> bytes:
    return json.dumps(x, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode('utf-8')

def unique_pairs(pairs):
    out = {}
    for k,v in pairs:
        if k in out:
            raise Denied('DUPLICATE_JSON_KEYS',422)
        out[k]=v
    return out

def strict_json(data: bytes):
    require(type(data) is bytes and 0 < len(data) <= MAX_BODY,
            'MALFORMED_JSON_SIZE',422)
    try:
        return json.loads(data.decode('utf-8'), object_pairs_hook=unique_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite')))
    except (ValueError,UnicodeError,RecursionError):
        raise Denied('INVALID_JSON',422)

def b64_decode(s: str, size: int) -> bytes:
    require(type(s) is str and len(s) < 160,'INVALID_SIGNATURE_ENCODING')
    try:
        raw = base64.b64decode(s, validate=True)
    except (ValueError,base64.binascii.Error):
        raise Denied('INVALID_SIGNATURE_ENCODING')
    require(len(raw)==size and base64.b64encode(raw).decode()==s,
            'INVALID_SIGNATURE_ENCODING')
    return raw

def encode(x: bytes) -> str:
    return base64.b64encode(x).decode('ascii')

def public_key(priv:Ed25519PrivateKey) -> str:
    return encode(priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))

def save_private(path: Path):
    key=Ed25519PrivateKey.generate()
    path.write_bytes(key.private_bytes(
        serialization.Encoding.Raw,serialization.PrivateFormat.Raw,
        serialization.NoEncryption()))
    os.chmod(path,0o600)
    return public_key(key)

def private_from_file(path: Path):
    require(path.is_file() and not path.is_symlink() and
            (path.stat().st_mode & 0o077)==0 and path.stat().st_uid==os.geteuid(),
            'PRIVATE_KEY_NOT_CONTROLLED_BY_OWN_UID')
    return Ed25519PrivateKey.from_private_bytes(path.read_bytes())

def verify_signature(pub_b64, sig_b64, message, code):
    try:
        Ed25519PublicKey.from_public_bytes(b64_decode(pub_b64,32)).verify(
            b64_decode(sig_b64,64), message)
    except (InvalidSignature,ValueError):
        raise Denied(code)

def validate_grant(p):
    require(type(p) is dict and set(p)=={'schema','audience','issuer','resource',
        'subject_public_key','method','expected_pre_sha256','desired_sha256',
        'nonce','not_before','expires_at','url_path'},'INVALID_SIGNED_GRANT_SHAPE')
    require(p['schema']==GRANT_SCHEMA and p['audience']==AUDIENCE and
            p['issuer']==ISSUER and p['resource'] in RESOURCE_IDS and
            p['method']=='REPLACE' and p['url_path']=='/effect',
            'GRANT_WRONG_AUDIENCE_OR_SCOPE')
    for x in ('expected_pre_sha256','desired_sha256','nonce'):
        require(type(p[x]) is str and HEX64.fullmatch(p[x]) is not None,
                'INVALID_GRANT_DIGEST')
    b64_decode(p['subject_public_key'],32)
    require(type(p['not_before']) is int and type(p['expires_at']) is int and
            p['expires_at']>p['not_before'] and
            p['expires_at']-p['not_before']<=120,'INVALID_GRANT_WINDOW')
    return p

def issue(proposal: dict, key: Ed25519PrivateKey):
    grant=validate_grant(proposal)
    return {'policy':grant,'signature':encode(key.sign(GRANT_DOMAIN+canonical(grant)))}

def proof(grant: dict, request: dict, holder: Ed25519PrivateKey):
    return {'grant':grant,'request':request,'proof_signature':encode(
        holder.sign(PROOF_DOMAIN+canonical({'grant_sha256':digest(canonical(grant)),
                                             'request':request})))}

def validate_envelope(value, trusted_pub, now):
    require(type(value) is dict and set(value)=={'grant','request','proof_signature'},
            'INVALID_ENVELOPE_FIELDS',422)
    g=value['grant']
    require(type(g) is dict and set(g)=={'policy','signature'},
            'INVALID_GRANT_FIELDS',422)
    p=validate_grant(g['policy'])
    verify_signature(trusted_pub,g['signature'],GRANT_DOMAIN+canonical(p),
                     'INVALID_OWNER_ISSUER_SIGNATURE')
    require(p['not_before']<=now<=p['expires_at'],'OWNER_GRANT_EXPIRED_OR_FUTURE')
    q=value['request']
    require(type(q) is dict and set(q)=={'schema','resource','method','url_path',
        'desired_value','request_id','grant_sha256'},'INVALID_CLIENT_REQUEST_FIELDS',422)
    require(q['schema']==PROOF_SCHEMA and q['method']=='REPLACE' and
            q['url_path']=='/effect' and q['resource'] in RESOURCE_IDS,
            'UNSUPPORTED_CLIENT_ACTION')
    require(type(q['desired_value']) is str and
            0<len(q['desired_value'].encode('utf-8'))<=MAX_VALUE,
            'INVALID_DESIRED_VALUE',422)
    require(type(q['request_id']) is str and HEX64.fullmatch(q['request_id']) is not None,
            'INVALID_REQUEST_IDENTIFIER',422)
    require(q['grant_sha256']==digest(canonical(g)),
            'REQUEST_NOT_BOUND_TO_EXACT_GRANT')
    verify_signature(p['subject_public_key'],value['proof_signature'],
         PROOF_DOMAIN+canonical({'grant_sha256':digest(canonical(g)),
                                 'request':q}), 'INVALID_SUBJECT_PROOF')
    require(q['resource']==p['resource'] and q['method']==p['method'] and
            q['url_path']==p['url_path'], 'OBJECT_OR_METHOD_NOT_AUTHORIZED')
    require(digest(q['desired_value'].encode())==p['desired_sha256'],
            'CONTENT_NOT_AUTHORIZED_BY_OWNER')
    return p,q

def conn(db:Path):
    db.parent.mkdir(parents=True,exist_ok=True)
    c=sqlite3.connect(str(db),timeout=8,isolation_level=None)
    c.execute('PRAGMA busy_timeout=8000')
    c.execute('PRAGMA journal_mode=DELETE')
    return c

def setup_db(db:Path):
    c=conn(db)
    c.execute('CREATE TABLE IF NOT EXISTS resources (resource TEXT PRIMARY KEY, value TEXT NOT NULL)')
    c.execute('CREATE TABLE IF NOT EXISTS used (nonce TEXT PRIMARY KEY, request_id TEXT NOT NULL)')
    if c.execute('SELECT count(*) FROM resources').fetchone()[0]==0:
        c.executemany('INSERT INTO resources(resource,value) VALUES (?,?)',
                      [('alpha','alpha-original'),('beta','beta-protected')])
    c.close()
    os.chmod(db,0o600)

def apply(db:Path, env, trusted_pub, now=None):
    p,q=validate_envelope(env,trusted_pub,int(time.time() if now is None else now))
    c=conn(db)
    try:
        c.execute('BEGIN IMMEDIATE')
        row=c.execute('SELECT value FROM resources WHERE resource=?',(q['resource'],)).fetchone()
        require(row is not None,'TARGET_RESOURCE_NOT_FOUND',404)
        before=digest(row[0].encode('utf-8'))
        require(c.execute('SELECT count(*) FROM used WHERE nonce=?',(p['nonce'],)).fetchone()[0]==0,
                'OWNER_NONCE_ALREADY_CONSUMED',409)
        require(before==p['expected_pre_sha256'],'OWNER_EXPECTED_PRESTATE_MISMATCH',409)
        c.execute('INSERT INTO used(nonce,request_id) VALUES (?,?)',(p['nonce'],q['request_id']))
        c.execute('UPDATE resources SET value=? WHERE resource=?',(q['desired_value'],q['resource']))
        c.execute('COMMIT')
        return {'status':'APPLIED','resource':q['resource'],
                'before_sha256':before,'after_sha256':digest(q['desired_value'].encode()),
                'nonce':p['nonce'],'request_id':q['request_id']}
    except Exception:
        c.rollback()
        raise
    finally:
        c.close()

def audit_state(db:Path):
    c=conn(db)
    try:
        return {'resources':dict(c.execute('SELECT resource,value FROM resources ORDER BY resource')),
                'used_nonces':[x[0] for x in c.execute('SELECT nonce FROM used ORDER BY nonce')]}
    finally:c.close()

def http_service(db:Path, trust_pub: str, port: int):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,fmt,*args):
            sys.stderr.write('B26 owner service: '+fmt%args+'\n')
        def send_json(self,status,value):
            b=canonical(value)
            self.send_response(status)
            self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(b)))
            self.send_header('Cache-Control','no-store')
            self.end_headers()
            self.wfile.write(b)
        def do_GET(self):
            if self.path!='/state':
                self.send_json(404,{'status':'NOT_FOUND'})
            else:
                self.send_json(200,audit_state(db))
        def do_POST(self):
            if self.path!='/effect':
                self.send_json(404,{'status':'NOT_FOUND'})
                return
            try:
                size=int(self.headers.get('Content-Length','-1'))
                require(0<size<=MAX_BODY,'UNBOUNDED_POST_BODY',422)
                inp=strict_json(self.rfile.read(size))
                self.send_json(200,apply(db,inp,trust_pub))
            except Denied as e:
                self.send_json(e.status,{'status':'DENIED','code':e.code})
            except (TypeError, ValueError, OverflowError):
                self.send_json(422,{'status':'DENIED','code':'MALFORMED_REQUEST'})
    server=ThreadingHTTPServer(('127.0.0.1',port),Handler)
    print('RISU_B26_OWNER_RESOURCE_SERVICE_READY',flush=True)
    server.serve_forever(poll_interval=0.1)

def send(url, payload):
    data=canonical(payload)
    req=urllib.request.Request(url+'/effect',method='POST',data=data,
            headers={'Content-Type':'application/json','User-Agent':'RISU-B26-research-fixture'})
    try:
        with urllib.request.urlopen(req,timeout=8) as resp:
            return {'http_status':resp.status,'body':strict_json(resp.read(MAX_BODY))}
    except urllib.error.HTTPError as e:
        return {'http_status':e.code,'body':strict_json(e.read(MAX_BODY))}

def cli(argv=None):
    a=argparse.ArgumentParser()
    a.add_argument('command',choices=['genkey','issue','make-proof','serve','send'])
    a.add_argument('--key-file')
    a.add_argument('--public-file')
    a.add_argument('--input')
    a.add_argument('--output')
    a.add_argument('--grant')
    a.add_argument('--db')
    a.add_argument('--port',type=int)
    a.add_argument('--url')
    n=a.parse_args(argv)
    if n.command=='genkey':
        public=save_private(Path(n.key_file))
        Path(n.public_file).write_text(public+'\n')
    elif n.command=='issue':
        policy=strict_json(Path(n.input).read_bytes())
        Path(n.output).write_bytes(canonical(issue(policy,private_from_file(Path(n.key_file))))+b'\n')
    elif n.command=='make-proof':
        g=strict_json(Path(n.grant).read_bytes())
        request=strict_json(Path(n.input).read_bytes())
        Path(n.output).write_bytes(canonical(proof(g,request,private_from_file(Path(n.key_file))))+b'\n')
    elif n.command=='serve':
        pub=Path(n.public_file).read_text().strip()
        b64_decode(pub,32)
        db=Path(n.db)
        setup_db(db)
        http_service(db,pub,n.port)
    elif n.command=='send':
        result=send(n.url,strict_json(Path(n.input).read_bytes()))
        Path(n.output).write_bytes(canonical(result)+b'\n')
        print('RISU_B26_HTTP_EFFECT',result['http_status'],result['body'].get('code',result['body'].get('status')),flush=True)

if __name__=='__main__':cli()
