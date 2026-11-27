"""B57 external app integration. Test-only policy and ephemeral signing key."""
import asyncio, json, os, pathlib, sqlite3, subprocess, sys, threading
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from agents.tool_context import ToolContext
DOMAIN=b'RISU-B57-intent-v1\0'
META='risu_b57'
CONFIG=None;KEY=None;CACHE={}

def enc(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def append(path,x):
    with open(path,'ab') as f:f.write(enc(x)+b'\n')
def raw(path,b):
    with open(path,'ab') as f:f.write(b)
def snapshot(path):
    p=pathlib.Path(path)
    if not p.exists():return []
    with sqlite3.connect(p.as_uri()+'?mode=ro',uri=True) as db:
        if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='reading_items'").fetchone():return []
        return [list(row) for row in db.execute('SELECT list_name,book_id,saved_at FROM reading_items ORDER BY list_name,book_id')]
def body(c,call,tool,args):
    return dict(run=c['run'],destination=c['destination'],call=call,tool=tool,arguments=args)
def envelope(b):
    return dict(body=b,signature=KEY.sign(DOMAIN+enc(b)).hex())
def resolver(ctx):
    rc=ctx.run_context
    if not isinstance(rc,ToolContext) or not isinstance(rc.tool_call_id,str) or not rc.tool_call_id:return None
    cid=rc.tool_call_id;b=body(CONFIG,cid,ctx.tool_name,ctx.arguments)
    if cid=='missing':out=None
    elif cid=='replay':out={META:CACHE['save']}
    elif cid=='wrong-scope':out={META:envelope(dict(b,destination='other-destination'))}
    elif cid=='rebind':out={META:envelope(dict(b,arguments=dict(b['arguments'],list_name='other-list')))}
    else:
        out={META:envelope(b)};CACHE[cid]=out[META]
    append(CONFIG['dir']+'/resolver.jsonl',dict(call=cid,tool=ctx.tool_name,arguments=ctx.arguments,meta=out,context=type(rc).__name__))
    return out

def decide(c,params,used):
    md=(params.get('_meta') or {}).get(META)
    if not isinstance(md,dict):return 'MISSING_IDENTITY',None
    try:
        b=md['body'];cid=b['call']
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(c['public'])).verify(bytes.fromhex(md['signature']),DOMAIN+enc(b))
        if not isinstance(cid,str) or not cid:return 'INVALID_IDENTITY',None
        if b.get('destination')!=c['destination'] or b.get('run')!=c['run']:return 'WRONG_SCOPE',cid
        expected=body(c,cid,params['name'],params.get('arguments',{}))
        if b!=expected:return 'ARGUMENT_REBIND',cid
        if cid in used:return 'REUSED_IDENTITY',cid
        if {'tool':b['tool'],'arguments':b['arguments']} not in c['allow']:return 'UNAUTHORIZED',cid
        return 'FORWARD',cid
    except (KeyError,TypeError,ValueError,InvalidSignature):return 'INVALID_IDENTITY',None

def proxy():
    c=json.loads(pathlib.Path(os.environ['RISU_B57_CONFIG']).read_text());d=pathlib.Path(c['dir'])
    assert str(pathlib.Path(os.environ['LIBRARY_DB_PATH']).resolve())==c['db']
    p=subprocess.Popen([sys.executable,'-m','library_toolkit.server'],stdin=subprocess.PIPE,stdout=subprocess.PIPE)
    lock=threading.Lock();used=set();pending={};errors=[]
    def send(frame):
        with lock:
            raw(d/'delivered.jsonl',frame);sys.stdout.buffer.write(frame);sys.stdout.buffer.flush()
    def pump():
        try:
            for frame in sys.stdin.buffer:
                raw(d/'ingress.jsonl',frame);m=json.loads(frame)
                if m.get('method')=='tools/call':
                    params=m['params'];rid=m['id'];key=enc(rid)
                    before=snapshot(c['db'])
                    decision,cid=decide(c,params,used)
                    append(d/'decisions.jsonl',dict(id=rid,decision=decision,call=cid,tool=params['name'],arguments=params.get('arguments',{})))
                    if decision!='FORWARD':
                        result=dict(isError=True,content=[dict(type='text',text='RISU_DENIED:'+decision)])
                        if (params.get('_meta') or {}).get('io.modelcontextprotocol/protocolVersion')=='2026-07-28':
                            result.update(resultType='complete',_meta={'io.modelcontextprotocol/serverInfo':{'name':'risu-b57','version':'0.1'}})
                        append(d/'effects.jsonl',dict(id=rid,before=before,after=snapshot(c['db']),decision=decision))
                        send(enc(dict(jsonrpc='2.0',id=rid,result=result))+b'\n');continue
                    assert not pending,'B57 fixture expects sequential calls'
                    used.add(cid);pending[key]=before
                    params['_meta']={k:v for k,v in params['_meta'].items() if k!=META}
                    frame=enc(m)+b'\n'
                raw(d/'forwarded.jsonl',frame);p.stdin.write(frame);p.stdin.flush()
        except Exception as e:
            errors.append(repr(e));append(d/'proxy_error.jsonl',dict(error=repr(e)))
        finally:
            try:p.stdin.close()
            except OSError:pass
    threading.Thread(target=pump,daemon=True).start()
    for frame in p.stdout:
        raw(d/'original_reply.jsonl',frame);m=json.loads(frame)
        key=enc(m['id']) if 'id'in m else None
        if key in pending:
            before=pending.pop(key)
            append(d/'effects.jsonl',dict(id=m['id'],before=before,after=snapshot(c['db']),decision='FORWARD'))
        send(frame)
    code=p.wait(timeout=5);append(d/'exit.jsonl',dict(server_exit=code,errors=errors,unsettled=len(pending)))
    os._exit(code if not errors and not pending and 0<=code<=255 else 1)

if __name__=='__main__':
    assert sys.argv[1]=='proxy';proxy()
