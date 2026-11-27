"""B58 destination broker: exact child authorization and atomic receipt."""
import datetime, json, os, pathlib, socket, socketserver, sqlite3, struct, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
DOMAIN=b'RISU-B58-child-v1\0'
INTENT=b'RISU-B59-intent-v1\0'
PATH=b'RISU-B59-path-v1\0'
import hashlib

def digest(x):return hashlib.sha256(enc(x)).hexdigest()
def verify(pub,domain,signed):
    if not isinstance(signed,dict) or set(signed)!={'body','signature'}:raise ValueError('MISSING_PROOF')
    try:Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).verify(bytes.fromhex(signed['signature']),domain+enc(signed['body']))
    except (InvalidSignature,TypeError,KeyError,ValueError):raise ValueError('INVALID_PROOF_SIGNATURE')
    return signed['body']
def check_path(c,p,proof,b):
    q=verify(c['path_pub'],PATH,proof)
    if set(q)!={'permit_sha256','intent','connection','native_id','selected','child','phase'}:raise ValueError('PATH_FIELDS')
    i=verify(c['actor_pub'],INTENT,q['intent'])
    if i!=dict(call=b['attempt'],run=c['run'],permit_sha256=digest(p),parent=b['parent']):raise ValueError('INTENT_BINDING')
    if q['permit_sha256']!=digest(p) or q['child']!=b['child'] or q['selected']!=b['child']['book_id'] or q['phase']!='ORIGINAL_PLAN_SEARCH_THEN_SAVE' or b['parent']['tool']!='plan_reading':raise ValueError('PATH_BINDING')
    if not isinstance(q['connection'],str) or not q['connection'] or type(q['native_id']) not in (int,str):raise ValueError('NATIVE_ID')
    return q
def enc(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def parse(b):
    def pairs(seq):
        d={}
        for k,v in seq:
            if k in d:raise ValueError('duplicate key')
            d[k]=v
        return d
    return json.loads(b,object_pairs_hook=pairs,parse_constant=lambda s: (_ for _ in ()).throw(ValueError(s)))
def connect(p):
    db=sqlite3.connect(p,timeout=15)
    db.execute('PRAGMA foreign_keys=ON')
    db.execute('PRAGMA synchronous=FULL')
    return db
def init(c):
    with connect(c['db']) as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.executescript("""
          CREATE TABLE IF NOT EXISTS identity(scope TEXT PRIMARY KEY);
          CREATE TABLE IF NOT EXISTS reading_items(list_name TEXT NOT NULL,book_id TEXT NOT NULL,saved_at TEXT NOT NULL,PRIMARY KEY(list_name,book_id));
          CREATE TABLE IF NOT EXISTS operations(op TEXT PRIMARY KEY,binding BLOB NOT NULL,winner TEXT NOT NULL,created INTEGER NOT NULL CHECK(created IN(0,1)),saved_at TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS receipts(seq INTEGER PRIMARY KEY,attempt TEXT UNIQUE NOT NULL,op TEXT NOT NULL REFERENCES operations(op),permit BLOB NOT NULL,proof BLOB NOT NULL,result BLOB NOT NULL);
        """)
        db.execute('INSERT OR IGNORE INTO identity VALUES(?)',(c['scope'],))
        if db.execute('SELECT scope FROM identity').fetchall()!=[(c['scope'],)]:raise ValueError('wrong destination identity')
def validate(c,req):
    if set(req)!={'permit','child','proof'}:raise ValueError('MALFORMED')
    p=req['permit']
    if not isinstance(p,dict) or set(p)!={'body','signature'}:raise ValueError('MISSING_CHILD_PERMIT')
    b=p['body']
    try:Ed25519PublicKey.from_public_bytes(bytes.fromhex(c['pub'])).verify(bytes.fromhex(p['signature']),DOMAIN+enc(b))
    except (InvalidSignature,ValueError,TypeError,KeyError):raise ValueError('INVALID_SIGNATURE')
    if not isinstance(b,dict) or set(b)!={'scope','op','attempt','parent','child'}:raise ValueError('MISSING_CHILD_PERMIT')
    if b['scope']!=c['scope']:raise ValueError('WRONG_SCOPE')
    if any(not isinstance(b[k],str) or not b[k] or len(b[k])>128 for k in ('op','attempt')):raise ValueError('INVALID_ID')
    par=b['parent'];child=b['child']
    if not isinstance(par,dict) or set(par)!={'tool','arguments'} or par['tool'] not in ('plan_reading','save_reading_item') or not isinstance(par['arguments'],dict):raise ValueError('INVALID_PARENT')
    if not isinstance(child,dict) or set(child)!={'book_id','list_name'} or any(not isinstance(v,str) or not v for v in child.values()):raise ValueError('INVALID_CHILD')
    if child!=req['child']:raise ValueError('CHILD_MISMATCH')
    if child['book_id'] not in c['books'] or child['list_name']!='demo':raise ValueError('DESTINATION_POLICY')
    if par['tool']=='save_reading_item' and par['arguments']!=child:raise ValueError('PARENT_CHILD_MISMATCH')
    if par['tool']=='plan_reading' and par['arguments'].get('list_name')!=child['list_name']:raise ValueError('PARENT_CHILD_MISMATCH')
    check_path(c,p,req['proof'],b)
    return b,p
def apply(c,req,peer):
    b,p=validate(c,req);child=b['child'];op=b['op'];attempt=b['attempt']
    binding=enc({k:v for k,v in b.items() if k!='attempt'})
    db=connect(c['db'])
    try:
        db.execute('BEGIN IMMEDIATE')
        if db.execute('SELECT scope FROM identity').fetchall()!=[(c['scope'],)]:raise ValueError('WRONG_SCOPE')
        prior=db.execute('SELECT permit,proof,result FROM receipts WHERE attempt=?',(attempt,)).fetchone()
        if prior:
            if prior[0]!=enc(p):raise ValueError('ATTEMPT_CONFLICT')
            if prior[1]!=enc(req['proof']):raise ValueError('ATTEMPT_PATH_CONFLICT')
            db.commit();return dict(ok=True,replay=True,receipt=parse(prior[2]))
        old=db.execute('SELECT binding,winner,created,saved_at FROM operations WHERE op=?',(op,)).fetchone()
        if old:
            if old[0]!=binding:raise ValueError('OP_CONFLICT')
            winner,created,stamp=old[1:]
            status='OTHER_ATTEMPT_WON' if created else 'ALREADY_PRESENT'
        else:
            stamp=datetime.datetime.now(datetime.timezone.utc).isoformat()
            cur=db.execute('INSERT OR IGNORE INTO reading_items VALUES(?,?,?)',(child['list_name'],child['book_id'],stamp))
            created=int(cur.rowcount==1)
            stamp=db.execute('SELECT saved_at FROM reading_items WHERE list_name=? AND book_id=?',(child['list_name'],child['book_id'])).fetchone()[0]
            winner=attempt if created else ''
            status='EFFECT_ATTRIBUTED' if created else 'ALREADY_PRESENT'
            db.execute('INSERT INTO operations VALUES(?,?,?,?,?)',(op,binding,winner,created,stamp))
        r=dict(scope=c['scope'],op=op,attempt=attempt,child=child,status=status,winner=winner or None,saved_at=stamp,peer_uid=peer)
        db.execute('INSERT INTO receipts(attempt,op,permit,proof,result) VALUES(?,?,?,?,?)',(attempt,op,enc(p),enc(req['proof']),enc(r)))
        if c['crash']=='before':os._exit(81)
        db.commit()
        if c['crash']=='after':os._exit(82)
        return dict(ok=True,replay=False,receipt=r)
    finally:db.close()
def serve(config):
    c=parse(pathlib.Path(config).read_bytes());os.umask(0o077);init(c)
    path=pathlib.Path(c['socket']);path.unlink(missing_ok=True)
    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.request.settimeout(10)
            peer=struct.unpack('3i',self.request.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))[1]
            try:
                if peer!=c['client_uid']:raise ValueError('PEER_DENIED')
                raw=self.rfile.readline(65537)
                if len(raw)>65536 or not raw.endswith(b'\n'):raise ValueError('MALFORMED')
                out=apply(c,parse(raw),peer)
            except (ValueError,TypeError,KeyError,sqlite3.Error) as e:out=dict(ok=False,error=str(e))
            self.wfile.write(enc(out)+b'\n')
    class Server(socketserver.ThreadingUnixStreamServer):
        daemon_threads=True
    with Server(str(path),Handler) as s:
        path.chmod(0o666)
        s.serve_forever(poll_interval=.05)
def call(path,permit,child,proof):
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
        s.settimeout(15);s.connect(path);s.sendall(enc(dict(permit=permit,child=child,proof=proof))+b'\n')
        with s.makefile('rb') as f:raw=f.readline(65537)
        if not raw:return dict(ok=False,error='TRANSPORT_UNKNOWN')
        return parse(raw)
if __name__=='__main__':serve(sys.argv[1])
