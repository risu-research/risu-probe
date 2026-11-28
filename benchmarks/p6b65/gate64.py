"""B62 cooperative destination gate; frozen B60 executes lifecycle transactions.
All callers must enter this gate. Root/DB writer and the observed-context source are trusted.
"""
import os, sqlite3, fcntl, contextlib, pathlib, json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
import lifecycle as L
POL=b'RISU-B62-policy-v1\0'; INT=b'RISU-B62-admission-v1\0'; SEAL=b'RISU-B62-seal-v1\0'; QUERY=b'RISU-B62-query-v1\0'; RESPONSE=b'RISU-B62-observation-v1\0'
SCHEMA='''CREATE TABLE IF NOT EXISTS gate_trust(data BLOB PRIMARY KEY);
CREATE TABLE IF NOT EXISTS claims(attempt TEXT PRIMARY KEY,op TEXT NOT NULL,model TEXT UNIQUE NOT NULL,connection TEXT NOT NULL,native BLOB NOT NULL,request_hash TEXT UNIQUE NOT NULL,decision TEXT NOT NULL,UNIQUE(connection,native));
CREATE TABLE IF NOT EXISTS admissions(attempt TEXT PRIMARY KEY,op TEXT NOT NULL,model TEXT UNIQUE NOT NULL,connection TEXT NOT NULL,native BLOB NOT NULL,policy BLOB NOT NULL,intent BLOB NOT NULL,observed BLOB NOT NULL,admission_hash TEXT UNIQUE NOT NULL,seal BLOB,UNIQUE(connection,native));
CREATE TABLE IF NOT EXISTS admission_log(seq INTEGER PRIMARY KEY,request BLOB NOT NULL,observed BLOB NOT NULL,authenticated INTEGER NOT NULL,decision TEXT NOT NULL,admission_hash TEXT);
CREATE TABLE IF NOT EXISTS gate_timeline(seq INTEGER PRIMARY KEY,kind TEXT NOT NULL,ref TEXT NOT NULL,engine_count INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS observations(nonce TEXT PRIMARY KEY,query BLOB NOT NULL,response BLOB NOT NULL);
'''
enc=L.enc; digest=L.digest

def sign(key,domain,b):return {'body':b,'signature':key.sign(domain+enc(b)).hex()}
def verify(pub,domain,e):
    if type(e) is not dict or set(e)!={'body','signature'} or type(e['body']) is not dict:raise ValueError('SIGNATURE')
    try:Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).verify(bytes.fromhex(e['signature']),domain+enc(e['body']))
    except (InvalidSignature,ValueError,TypeError,KeyError):raise ValueError('SIGNATURE')
    return e['body']
def req(test,error):
    if not test:raise ValueError(error)
def ident(x):return type(x) is str and 0<len(x)<=128
def native(x):return (type(x) is int and -(2**53-1)<=x<=2**53-1) or ident(x)
def parse(x):return json.loads(x)

RETRY=b'RISU-B64-retry-authorization-v1\0'
RETRY_SCHEMA="""CREATE TABLE IF NOT EXISTS gate64_version(version TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS retry_log(admission_seq INTEGER PRIMARY KEY REFERENCES admission_log(seq),ticket BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS consumed_retry(nonce TEXT PRIMARY KEY,attempt TEXT UNIQUE NOT NULL REFERENCES admissions(attempt),authorization_hash TEXT UNIQUE NOT NULL);"""

class Gate:
    def __init__(self,path,trust,observer_key):
        self.path=str(path);self.trust=trust;self.key=observer_key
        from cryptography.hazmat.primitives import serialization
        p=observer_key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()
        req(p==trust['observer'],'OBSERVER_KEY')
        self.lt={k:v for k,v in trust.items() if k!='observer'}
        with self.lock():
            L.init(self.path,self.lt)
            with self.db() as d:
                tables={x[0] for x in d.execute('SELECT name FROM sqlite_master WHERE type="table"')}
                req('gate64_version' in tables or ('gate_trust' not in tables and d.execute('SELECT count(*) FROM events').fetchone()[0]==0),'LEGACY_GATE_REQUIRES_MIGRATION')
                d.executescript(SCHEMA+RETRY_SCHEMA);
                d.execute("INSERT OR IGNORE INTO gate64_version VALUES ('B64-v1')");
                req(d.execute('SELECT version FROM gate64_version').fetchall()==[('B64-v1',)],'GATE_VERSION');
                req(d.execute('SELECT count(*) FROM admission_log').fetchone()==d.execute('SELECT count(*) FROM retry_log').fetchone(),'RETRY_HISTORY_INCOMPLETE');d.execute('INSERT OR IGNORE INTO gate_trust VALUES(?)',(enc(trust),));self.check(d)
    @contextlib.contextmanager
    def lock(self):
        with open(self.path+'.gate.lock','ab') as f:
            fcntl.flock(f,fcntl.LOCK_EX)
            try:yield
            finally:fcntl.flock(f,fcntl.LOCK_UN)
    def db(self):return L.connect(self.path)
    def check(self,d):
        req(d.execute('SELECT data FROM gate_trust').fetchall()==[(enc(self.trust),)],'TRUST')
        req(d.execute('SELECT data FROM trust').fetchall()==[(enc(self.lt),)],'TRUST')
    def mark(self,d,kind,ref):
        n=d.execute('SELECT count(*) FROM events').fetchone()[0]
        return d.execute('INSERT INTO gate_timeline(kind,ref,engine_count) VALUES(?,?,?)',(kind,str(ref),n)).lastrowid
    def admit(self,envelope,observed,ticket=None,crash=None):
        """Persist signed denial/admission before returning. A duplicate never dispatches."""
        with self.lock(),self.db() as d:
            d.execute('BEGIN IMMEDIATE');self.check(d);authenticated=0;h=None;reserved=None;consume=None
            try:
                req(type(envelope) is dict and set(envelope)=={'policy','intent'},'ENVELOPE')
                i=verify(self.trust['actor'],INT,envelope['intent']);authenticated=1
                p=verify(self.trust['owner'],POL,envelope['policy'])
                req(set(p)=={'scope','op','actor','parent','steps'} and p['scope']==self.trust['scope'] and p['actor']==self.trust['actor'] and ident(p['op']),'POLICY')
                req(set(i)=={'scope','op','attempt','model','connection','native','parent','policy_hash'} and i['scope']==p['scope'] and i['op']==p['op'] and i['policy_hash']==digest(envelope['policy']),'INTENT_BINDING')
                req(all(ident(i[k]) for k in ('attempt','model','connection')) and native(i['native']),'IDENTITY')
                req(type(observed) is dict and enc(observed)==enc({k:i[k] for k in ('connection','native','parent','model')}),'OBSERVED_BINDING')
                h=digest({'envelope':envelope,'observed':observed})
                old=d.execute('SELECT request_hash,decision FROM claims WHERE attempt=? OR model=? OR (connection=? AND native=?)',(i['attempt'],i['model'],i['connection'],enc(i['native']))).fetchone()
                if old:raise ValueError(('ADMISSION_REPLAY' if old[1]=='ADMITTED' else 'DENIAL_REPLAY') if old[0]==h else 'IDENTITY_CONFLICT')
                d.execute('INSERT INTO claims VALUES(?,?,?,?,?,?,?)',(i['attempt'],i['op'],i['model'],i['connection'],enc(i['native']),h,'PENDING'));reserved=i['attempt']
                req(i['parent']==p['parent'],'PARENT_BINDING')
                op=d.execute('SELECT steps,state FROM ops WHERE op=?',(p['op'],)).fetchone()
                req(op is not None and parse(op[0])==p['steps'],'POLICY_STEPS')
                req(op[1]=='OPEN','OP_CLOSED')
                active=d.execute("SELECT a.attempt FROM admissions a LEFT JOIN attempts t ON t.attempt=a.attempt WHERE a.op=? AND a.seal IS NULL AND (t.state IS NULL OR t.state='STARTED')",(p['op'],)).fetchone()
                req(active is None,'ACTIVE_ATTEMPT')
                previous=d.execute('SELECT 1 FROM admissions WHERE op=? LIMIT 1',(p['op'],)).fetchone()
                if previous:consume=self.check_retry(d,ticket,p,i,h)
                else:req(ticket is None,'UNEXPECTED_RETRY')
                d.execute('INSERT INTO admissions VALUES(?,?,?,?,?,?,?,?,?,NULL)',(i['attempt'],i['op'],i['model'],i['connection'],enc(i['native']),enc(envelope['policy']),enc(envelope['intent']),enc(observed),h));decision='ADMITTED'
                if consume is not None:d.execute('INSERT INTO consumed_retry VALUES(?,?,?)',(consume[0],i['attempt'],consume[1]))
            except (ValueError,KeyError,TypeError) as e:decision=str(e)
            if reserved is not None:d.execute('UPDATE claims SET decision=? WHERE attempt=?',(decision,reserved))
            seq=d.execute('INSERT INTO admission_log(request,observed,authenticated,decision,admission_hash) VALUES(?,?,?,?,?)',(enc(envelope),enc(observed),authenticated,decision,h)).lastrowid;d.execute('INSERT INTO retry_log VALUES(?,?)',(seq,enc(ticket)));self.mark(d,'ADMISSION',seq)
            if crash=='before':os._exit(94)
            d.commit()
            if crash=='after':os._exit(95)
            return {'decision':decision,'dispatch':decision=='ADMITTED','admission_hash':h if decision=='ADMITTED' else None}
    def check_retry(self,d,ticket,p,i,h):
        req(isinstance(ticket,dict) and set(ticket)=={'query','response','authorization'},'RETRY_REQUIRED')
        q=ticket['query'];r=ticket['response'];auth=ticket['authorization']
        b=verify(self.trust['actor'],QUERY,q);v=validate_response(self.trust['observer'],q,r)
        a=verify(self.trust['owner'],RETRY,auth)
        expected=dict(scope=self.trust['scope'],op=p['op'],prior_attempt=b['attempt'],next_attempt=i['attempt'],request_hash=h,query_hash=digest(q),response_hash=digest(r))
        req(a==expected and b['scope']==p['scope'] and b['op']==p['op'],'RETRY_BINDING')
        req(v['action']=='NEW_AUTHORIZED_ATTEMPT_ONLY' and v['operation_state']=='OPEN' and v['attempt_state'] in ('ABANDONED','SEALED_BEFORE_START'),'RETRY_ACTION')
        row=d.execute('SELECT query,response FROM observations WHERE nonce=?',(b['nonce'],)).fetchone()
        req(row==(enc(q),enc(r)),'OBSERVATION_NOT_STORED')
        req(not d.execute('SELECT 1 FROM consumed_retry WHERE nonce=?',(b['nonce'],)).fetchone(),'RETRY_CONSUMED')
        count,head=d.execute('SELECT count(*),(SELECT hash FROM events ORDER BY seq DESC LIMIT 1) FROM events').fetchone()
        seq=d.execute('SELECT coalesce(max(seq),0) FROM gate_timeline').fetchone()[0]
        req((count,head,seq)==(v['event_count'],v['last_event'],v['gate_seq']),'STALE_OBSERVATION')
        return b['nonce'],digest(auth)
    def event(self,e,crash=None):
        """All lifecycle events use the same lock. No pre-start gap is replayed implicitly."""
        with self.lock():
            b=L.verify(self.lt,e);k=b['kind'];op=b['op']
            with self.db() as d:
                self.check(d)
                if k in ('START','STEP','FINISH'):
                    a=d.execute('SELECT op,model,connection,native,seal FROM admissions WHERE attempt=?',(b['attempt'],)).fetchone();req(a is not None and a[0]==op,'NO_ADMISSION');req(a[4] is None,'SEALED')
                    current=d.execute('SELECT state FROM ops WHERE op=?',(op,)).fetchone();req(current and current[0]=='OPEN','OP_CLOSED')
                    prior=d.execute('SELECT state FROM attempts WHERE attempt=?',(b['attempt'],)).fetchone()
                    if k=='START':
                        req(prior is None,'START_ALREADY_RECORDED');req((b['model_call'],b['connection'],enc(b['native_id']))==a[1:4],'START_BINDING')
                    else:req(prior and prior[0]=='STARTED','ATTEMPT_CLOSED')
            return L.execute(self.path,self.lt,e,crash)
    def seal(self,e):
        """Explicit owner fence for an admitted request that has never STARTed."""
        with self.lock(),self.db() as d:
            d.execute('BEGIN IMMEDIATE');self.check(d);b=verify(self.trust['owner'],SEAL,e)
            req(set(b)=={'scope','op','attempt','admission_hash'} and b['scope']==self.trust['scope'],'SCOPE')
            a=d.execute('SELECT op,admission_hash,seal FROM admissions WHERE attempt=?',(b['attempt'],)).fetchone();req(a and a[:2]==(b['op'],b['admission_hash']),'SEAL_BINDING')
            req(d.execute('SELECT 1 FROM attempts WHERE attempt=?',(b['attempt'],)).fetchone() is None,'START_EXISTS')
            if a[2] is not None:req(a[2]==enc(e),'SEAL_CONFLICT')
            else:
                d.execute('UPDATE admissions SET seal=? WHERE attempt=?',(enc(e),b['attempt']));self.mark(d,'SEAL',b['attempt'])
            d.commit();return {'state':'SEALED_BEFORE_START'}
    def recover(self,e,crash=None):
        """Authenticated observation, not execution. The nonce and response commit together."""
        with self.lock(),self.db() as d:
            d.execute('BEGIN IMMEDIATE');self.check(d)
            try:
                b=verify(self.trust['actor'],QUERY,e);req(set(b)=={'scope','op','attempt','nonce'} and b['scope']==self.trust['scope'] and all(ident(b[k]) for k in ('op','attempt','nonce')),'DENIED')
                claim=d.execute('SELECT op,request_hash,decision FROM claims WHERE attempt=?',(b['attempt'],)).fetchone();req(claim is not None and claim[0]==b['op'],'DENIED')
                a=d.execute('SELECT op,admission_hash,seal FROM admissions WHERE attempt=?',(b['attempt'],)).fetchone()
            except (ValueError,KeyError,TypeError):raise ValueError('DENIED')
            req(d.execute('SELECT 1 FROM observations WHERE nonce=?',(b['nonce'],)).fetchone() is None,'NONCE_USED')
            op=d.execute('SELECT state,winner FROM ops WHERE op=?',(b['op'],)).fetchone();ar=d.execute('SELECT state,finish,output,ack FROM attempts WHERE attempt=?',(b['attempt'],)).fetchone()
            ast='DENIED' if claim[2]!='ADMITTED' else (ar[0] if ar else ('SEALED_BEFORE_START' if a[2] else 'ADMITTED_NO_START'))
            receipts=[parse(x[0]) for x in d.execute('SELECT receipt FROM progress WHERE attempt=? ORDER BY idx',(b['attempt'],))]
            effects=[{'index':x[0],'child':parse(x[1]),'winner':x[2],'created':bool(x[3])} for x in d.execute('SELECT idx,child,winner,created FROM effects WHERE op=? ORDER BY idx',(b['op'],))]
            completion=None
            if ast=='DENIED':
                action='DENIED_NO_DISPATCH';effects=[];receipts=[];ar=None
            elif op[0]=='COMPLETE':
                w=d.execute('SELECT finish,output,ack FROM attempts WHERE attempt=?',(op[1],)).fetchone();completion={'attempt':op[1],'finish':w[0],'output':parse(w[1]),'ack':w[2]}
                action='RETURN_STORED_COMPLETION'
            elif op[0]=='REVOKED':action='NO_FURTHER_EXECUTION'
            elif ast in ('ABANDONED','SEALED_BEFORE_START'):action='NEW_AUTHORIZED_ATTEMPT_ONLY'
            else:action='HOLD_UNRESOLVED'
            n=d.execute('SELECT count(*) FROM events').fetchone()[0];last=d.execute('SELECT hash FROM events ORDER BY seq DESC LIMIT 1').fetchone()
            out=dict(scope=b['scope'],op=b['op'],attempt=b['attempt'],nonce=b['nonce'],query_hash=digest(e),admission_hash=a[1] if a else None,claim_hash=claim[1],admission_decision=claim[2],operation_state=op[0] if op and ast!='DENIED' else None,attempt_state=ast,attempt_finish=ar[1] if ar else None,attempt_ack=ar[3] if ar else None,attempt_receipts=receipts,effects=effects,completion=completion,action=action,event_count=n,last_event=last[0] if last else None,original_delivery='NOT_PROVEN')
            out['gate_seq']=self.mark(d,'OBSERVATION',b['nonce'])
            response=sign(self.key,RESPONSE,out);d.execute('INSERT INTO observations VALUES(?,?,?)',(b['nonce'],enc(e),enc(response)))
            if crash=='before':os._exit(92)
            d.commit()
            if crash=='after':os._exit(93)
            return response

def validate_response(observer,query,response):
    r=verify(observer,RESPONSE,response);q=query['body'];req(r['query_hash']==digest(query) and all(r[k]==q[k] for k in ('scope','op','attempt','nonce')),'RESPONSE_BINDING');return r
