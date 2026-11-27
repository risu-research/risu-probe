"""Independent-style offline B57 evidence audit; no SDK or external app imports."""
import hashlib,json,pathlib,sqlite3,sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
DOMAIN=b'RISU-B57-intent-v1\0'
META='risu_b57'
def enc(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def read(p):return json.loads(p.read_bytes())
def frames(p):return [(json.loads(b),b) for b in p.read_bytes().splitlines(keepends=True)]
def audit(d):
    d=pathlib.Path(d);c=read(d/'config.json');s=read(d/'summary.json')
    cases=s['cases'];assert len(cases)==11
    expected=['FORWARD']*6+['MISSING_IDENTITY','WRONG_SCOPE','REUSED_IDENTITY','ARGUMENT_REBIND','UNAUTHORIZED']
    assert [x[3] for x in cases]==expected
    def byid(xs):return {enc(x['id']):x for x in xs}
    ingress=[m for m,_ in frames(d/'ingress.jsonl') if m.get('method')=='tools/call']
    egress=[m for m,_ in frames(d/'forwarded.jsonl') if m.get('method')=='tools/call']
    assert len(ingress)==11 and len(egress)==6
    ids=[enc(m['id']) for m in ingress];assert len(set(ids))==11
    f=byid(egress);dec=byid([m for m,_ in frames(d/'decisions.jsonl')]);eff=byid([m for m,_ in frames(d/'effects.jsonl')])
    assert set(dec)==set(eff)==set(ids)
    def replies(name):return {enc(m['id']):(m,b) for m,b in frames(d/name) if 'id'in m and enc(m['id']) in ids}
    orig=replies('original_reply.jsonl');out=replies('delivered.jsonl');assert len(orig)==6 and len(out)==11 and set(orig)==set(f)
    assert all(orig[k][1]==out[k][1] for k in orig)
    assert [m for m,_ in frames(d/'original_reply.jsonl') if isinstance(m.get('result'),dict) and 'tools'in m['result']]==[m for m,_ in frames(d/'delivered.jsonl') if isinstance(m.get('result'),dict) and 'tools'in m['result']]
    models=read(d/'outputs.json');assert [m['call_id'] for m in models]==[x[0] for x in cases]
    resolver=[m for m,_ in frames(d/'resolver.jsonl')];assert [m['call'] for m in resolver]==[x[0] for x in cases]
    used=set();previous=[];pub=Ed25519PublicKey.from_public_bytes(bytes.fromhex(c['public']))
    expected_counts=[0,1,2,2,2,2,2,2,2,2,2]
    for i,(cid,tool,args,status) in enumerate(cases):
        m=ingress[i];k=ids[i];p=m['params'];assert p['name']==tool and p['arguments']==args
        md=(p.get('_meta') or {}).get(META)
        assert resolver[i]['tool']==tool and resolver[i]['arguments']==args and resolver[i]['context']=='ToolContext'
        assert md==(resolver[i]['meta'] or {}).get(META)
        if md is None:verdict='MISSING_IDENTITY'
        else:
            b=md['body'];pub.verify(bytes.fromhex(md['signature']),DOMAIN+enc(b))
            if b['run']!=c['run'] or b['destination']!=c['destination']:verdict='WRONG_SCOPE'
            elif b!={'run':c['run'],'destination':c['destination'],'call':b['call'],'tool':tool,'arguments':args}:verdict='ARGUMENT_REBIND'
            elif b['call'] in used:verdict='REUSED_IDENTITY'
            elif {'tool':tool,'arguments':args} not in c['allow']:verdict='UNAUTHORIZED'
            else:verdict='FORWARD';used.add(b['call']);assert b['call']==cid
        assert verdict==status==dec[k]['decision']==eff[k]['decision']
        assert eff[k]['before']==previous and len(eff[k]['after'])==expected_counts[i]
        current=eff[k]['after'];assert all(row in current for row in previous)
        previous=current
        r=out[k][0]['result'];model=models[i]['output']
        text=' '.join(item.get('text','') for item in r.get('content',[]) if item.get('type')=='text')
        rendered=json.dumps(model,ensure_ascii=False)
        if status=='FORWARD':
            assert k in f and f[k]['params']['arguments']==args and f[k]['params']['name']==tool
            assert f[k]['params'].get('_meta')=={a:b for a,b in (p.get('_meta') or {}).items() if a!=META}
            if i in (4,5):
                assert r['isError'];token=['NO_MATCHES','BOOK_NOT_FOUND'][i-4];assert token in text and token in rendered
            else:
                assert not r.get('isError',False)
                if i in (1,2,3):
                    token='already_saved' if i==3 else 'created';assert token in text and token in rendered
                # Compare actual server text, or structured content if SDK chose it.
                if isinstance(model,str) and r.get('structuredContent') is not None:
                    try: assert json.loads(model)==r['structuredContent']
                    except json.JSONDecodeError:assert model==text
                elif isinstance(model,list):
                    assert [x.get('text') for x in model if x.get('type') in ('input_text','text')]==[x.get('text') for x in r['content'] if x.get('type')=='text']
        else:
            assert k not in f and r['isError'] and text=='RISU_DENIED:'+status and text in rendered and eff[k]['before']==current
        print('B57_CASE',cid,m['id'],verdict,'rows',len(current),flush=True)
    with sqlite3.connect((d/'demo.sqlite3').resolve().as_uri()+'?mode=ro',uri=True) as db:
        assert db.execute('PRAGMA integrity_check').fetchone()==('ok',)
        final=[list(r) for r in db.execute('SELECT list_name,book_id,saved_at FROM reading_items ORDER BY list_name,book_id')]
    assert final==previous==s['final_rows'] and [(r[0],r[1]) for r in final]==[('demo','B001'),('demo','B004')]
    assert s['host_added_lines']==3 and s['host_removed_lines']==1
    print('B57_AUDIT_PASS 11 scenarios; 6 original tool calls, 5 gateway denials; 2 rows')
if __name__=='__main__':audit(sys.argv[1])
