"""B60 controlled destination lifecycle. Signed events are not SDK wire attestations."""
import hashlib,json,sqlite3,sys,os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
DOMAIN=b'RISU-B60-event-v1\0'
ROLES={'OPEN':'owner','START':'handler','STEP':'handler','FINISH':'handler','ABANDON':'owner','REVOKE':'owner','ACK':'actor'}
FIELDS={'OPEN':{'steps'},'START':{'attempt','connection','native_id','model_call'},'STEP':{'attempt','start','index','child'},'FINISH':{'attempt','start','output'},'ABANDON':{'attempt','start'},'REVOKE':set(),'ACK':{'attempt','finish','output_hash'}}
def enc(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def parse(x):return json.loads(x)
def digest(x):return hashlib.sha256(enc(x)).hexdigest()
def require(test,error):
    if not test:raise ValueError(error)
def textid(x):return type(x) is str and 0<len(x)<=128
def verify(trust,e):
    require(type(e) is dict and set(e)=={'body','signature'},'ENVELOPE')
    b=e['body'];require(type(b) is dict and b.get('kind') in ROLES,'KIND');k=b['kind']
    require(set(b)=={'scope','op','kind'}|FIELDS[k],'FIELDS')
    require(b['scope']==trust['scope'] and textid(b['op']),'SCOPE')
    try:Ed25519PublicKey.from_public_bytes(bytes.fromhex(trust[ROLES[k]])).verify(bytes.fromhex(e['signature']),DOMAIN+enc(b))
    except (InvalidSignature,ValueError,TypeError,KeyError):raise ValueError('SIGNATURE')
    return b
SCHEMA='''
CREATE TABLE IF NOT EXISTS trust(data BLOB PRIMARY KEY);
CREATE TABLE IF NOT EXISTS ops(op TEXT PRIMARY KEY, steps BLOB NOT NULL,state TEXT NOT NULL,winner TEXT);
CREATE TABLE IF NOT EXISTS attempts(attempt TEXT PRIMARY KEY,op TEXT NOT NULL REFERENCES ops,connection TEXT NOT NULL,native BLOB NOT NULL,model TEXT UNIQUE NOT NULL,start TEXT UNIQUE NOT NULL,state TEXT NOT NULL,finish TEXT,output BLOB,ack TEXT,UNIQUE(connection,native));
CREATE TABLE IF NOT EXISTS reading_items(list_name TEXT,book_id TEXT,PRIMARY KEY(list_name,book_id));
CREATE TABLE IF NOT EXISTS effects(op TEXT REFERENCES ops,idx INTEGER,child BLOB NOT NULL,winner TEXT REFERENCES attempts,created INTEGER NOT NULL,PRIMARY KEY(op,idx));
CREATE TABLE IF NOT EXISTS progress(attempt TEXT REFERENCES attempts,idx INTEGER,receipt BLOB NOT NULL,PRIMARY KEY(attempt,idx));
CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY,hash TEXT UNIQUE NOT NULL,envelope BLOB NOT NULL,result BLOB NOT NULL);
'''
def connect(path):
    db=sqlite3.connect(path,timeout=15);db.execute('PRAGMA foreign_keys=ON');db.execute('PRAGMA synchronous=FULL');return db
def init(path,trust):
    with connect(path) as db:
        db.execute('PRAGMA journal_mode=WAL');db.executescript(SCHEMA);db.execute('INSERT OR IGNORE INTO trust VALUES (?)',(enc(trust),));require(db.execute('SELECT data FROM trust').fetchall()==[(enc(trust),)],'TRUST')
def execute(path,trust,e,crash=None):
    b=verify(trust,e);h=digest(e);k=b['kind'];op=b['op'];db=connect(path)
    try:
        db.execute('BEGIN IMMEDIATE');require(db.execute('SELECT data FROM trust').fetchall()==[(enc(trust),)],'TRUST')
        prior=db.execute('SELECT result FROM events WHERE hash=?',(h,)).fetchone()
        if prior:return {'replay':True,'result':parse(prior[0])}
        current=db.execute('SELECT steps,state,winner FROM ops WHERE op=?',(op,)).fetchone()
        if k=='OPEN':
            require(current is None,'OP_EXISTS');steps=b['steps'];require(type(steps) is list and 1<=len(steps)<=16,'STEPS')
            require(all(type(c) is dict and set(c)=={'list_name','book_id'} and c['list_name']=='demo' and c['book_id'] in trust['books'] for c in steps),'CHILD')
            require(len({enc(c) for c in steps})==len(steps),'DUPLICATE_CHILD')
            db.execute('INSERT INTO ops VALUES(?,?,?,NULL)',(op,enc(steps),'OPEN'));r={'state':'OPEN'}
        else:
            require(current is not None,'UNKNOWN_OP');steps,state,winner=current;steps=parse(steps)
            if k=='REVOKE':
                require(state!='REVOKED','ALREADY_REVOKED')
                if state=='COMPLETE':r={'state':'COMPLETE','late':True,'winner':winner}
                else:db.execute("UPDATE ops SET state='REVOKED' WHERE op=?",(op,));r={'state':'REVOKED','late':False}
            elif k=='START':
                require(state=='OPEN','OP_CLOSED');a=b['attempt'];require(all(textid(b[x]) for x in ('attempt','connection','model_call')) and type(b['native_id']) in (int,str) and (type(b['native_id']) is int or textid(b['native_id'])),'IDENTITY')
                try:db.execute('INSERT INTO attempts VALUES(?,?,?,?,?,?,?,NULL,NULL,NULL)',(a,op,b['connection'],enc(b['native_id']),b['model_call'],h,'STARTED'))
                except sqlite3.IntegrityError:raise ValueError('IDENTITY_CONFLICT')
                r={'state':'STARTED','start':h}
            else:
                a=b['attempt'];ar=db.execute('SELECT op,start,state,finish,output,ack FROM attempts WHERE attempt=?',(a,)).fetchone();require(ar is not None and ar[0]==op,'UNKNOWN_ATTEMPT');_,start,ast,finish,output,ack=ar
                if k=='ACK':
                    require(ast=='COMPLETE' and b['finish']==finish and b['output_hash']==digest(parse(output)),'ACK_BINDING');require(ack is None,'ACK_EXISTS');db.execute('UPDATE attempts SET ack=? WHERE attempt=?',(h,a));r={'state':'ACKNOWLEDGED','finish':finish}
                else:
                    require(b['start']==start,'START_BINDING');require(ast=='STARTED','ATTEMPT_CLOSED')
                    if k=='ABANDON':
                        db.execute("UPDATE attempts SET state='ABANDONED' WHERE attempt=?",(a,));r={'state':'ABANDONED'}
                    else:
                        require(state=='OPEN','OP_CLOSED')
                        progress=[parse(x[0]) for x in db.execute('SELECT receipt FROM progress WHERE attempt=? ORDER BY idx',(a,))]
                        if k=='STEP':
                            idx=b['index'];require(type(idx) is int and idx==len(progress) and idx<len(steps),'STEP_ORDER');child=b['child'];require(child==steps[idx],'CHILD_MISMATCH')
                            eff=db.execute('SELECT child,winner,created FROM effects WHERE op=? AND idx=?',(op,idx)).fetchone()
                            if eff:
                                require(eff[0]==enc(child),'EFFECT_BINDING');w,created=eff[1:];status='OTHER_ATTEMPT_WON' if created else 'ALREADY_PRESENT'
                            else:
                                created=int(db.execute('INSERT OR IGNORE INTO reading_items VALUES(?,?)',(child['list_name'],child['book_id'])).rowcount==1);w=a if created else None;status='EFFECT_ATTRIBUTED' if created else 'ALREADY_PRESENT'
                                db.execute('INSERT INTO effects VALUES(?,?,?,?,?)',(op,idx,enc(child),w,created))
                            r={'attempt':a,'index':idx,'child':child,'status':status,'winner':w,'event':h};db.execute('INSERT INTO progress VALUES(?,?,?)',(a,idx,enc(r)))
                        elif k=='FINISH':
                            require(len(progress)==len(steps),'INCOMPLETE_CHILDREN');expected={'saved':steps,'receipts':[digest(x) for x in progress]};require(b['output']==expected,'RETURN_BINDING')
                            db.execute("UPDATE attempts SET state='COMPLETE',finish=?,output=? WHERE attempt=?",(h,enc(expected),a));db.execute("UPDATE ops SET state='COMPLETE',winner=? WHERE op=?",(a,op));r={'state':'COMPLETE','finish':h,'output':expected}
        db.execute('INSERT INTO events(hash,envelope,result) VALUES(?,?,?)',(h,enc(e),enc(r)))
        if crash=='before':os._exit(81)
        db.commit()
        if crash=='after':os._exit(82)
        return {'replay':False,'result':r}
    finally:db.close()
def snapshot(path):
    with connect(path) as d:
        return {'ops':d.execute('SELECT op,state,winner FROM ops ORDER BY op').fetchall(),'attempts':d.execute('SELECT attempt,op,state,ack IS NOT NULL FROM attempts ORDER BY attempt').fetchall(),'rows':d.execute('SELECT list_name,book_id FROM reading_items ORDER BY list_name,book_id').fetchall(),'effects':d.execute('SELECT op,idx,winner,created FROM effects ORDER BY op,idx').fetchall(),'progress':d.execute('SELECT attempt,idx FROM progress ORDER BY attempt,idx').fetchall(),'events':d.execute('SELECT count(*) FROM events').fetchone()[0]}
if __name__=='__main__':
    p,t,crash=sys.argv[1:];trust=parse(open(t,'rb').read());e=parse(sys.stdin.buffer.read())
    try:print(enc({'ok':True,**execute(p,trust,e,crash)}).decode(),flush=True)
    except ValueError as err:print(enc({'ok':False,'error':str(err)}).decode(),flush=True)
