"""Trusted owner-side issuer. Accepting a recovery observation alone issues nothing."""
import sqlite3
from gate64 import RETRY,enc,digest,sign,req,validate_response

def issue(client_path,scope,observer,owner,q,r,envelope,observed):
    v=validate_response(observer,q,r); b=q['body'];i=envelope['intent']['body']
    req(v['action']=='NEW_AUTHORIZED_ATTEMPT_ONLY','RETRY_ACTION')
    req(b['scope']==scope==i['scope'] and b['op']==i['op'],'RETRY_BINDING')
    with sqlite3.connect(client_path) as c:
        row=c.execute('SELECT query,state,response FROM queries WHERE nonce=?',(b['nonce'],)).fetchone()
        req(row==(enc(q),'ACCEPTED',enc(r)),'CLIENT_NOT_ACCEPTED')
    # Owner decision is separate from client acceptance. Caller must be authorized to sign.
    auth=sign(owner,RETRY,dict(scope=scope,op=b['op'],prior_attempt=b['attempt'],next_attempt=i['attempt'],request_hash=digest(dict(envelope=envelope,observed=observed)),query_hash=digest(q),response_hash=digest(r)))
    return dict(query=q,response=r,authorization=auth)
