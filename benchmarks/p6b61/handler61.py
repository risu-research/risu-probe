"""Actual SDK parent handler; original CampusReads plan and search."""
import os,sys,pathlib,uuid
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey
from lifecycle import enc,parse,digest,DOMAIN
from broker61 import call
from mcp.server import MCPServer
from mcp.server.mcpserver import Context
from mcp.server.mcpserver.exceptions import ToolError
POL=b'RISU-B61-parent-policy-v1\0'
INT=b'RISU-B61-actor-intent-v1\0'
c=parse(pathlib.Path(sys.argv[1]).read_bytes())
sys.path.insert(0,c['upstream'])
from library_toolkit.service import LibraryService,LibraryError,SaveResult,clean_text
key=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(c['key']))
conn=uuid.uuid4().hex
def log(x):
    with open(c['log'],'ab') as f:f.write(enc(x)+b'\n');f.flush();os.fsync(f.fileno())
def verified(pub,domain,e):
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).verify(bytes.fromhex(e['signature']),domain+enc(e['body']))
    return e['body']
def event(op,kind,**kw):
    b=dict(scope=c['trust']['scope'],op=op,kind=kind,**kw)
    e=dict(body=b,signature=key.sign(DOMAIN+enc(b)).hex())
    r=call(c['socket'],e);log(dict(stage=kind,event=e,response=r))
    if not r['ok']:raise LibraryError(r['error'])
    return r['result']
def crash(stage):
    if c['mode']==stage:os._exit({'START':81,'STEP':82,'FINISH':83}[stage])
class Bound(LibraryService):
    def __init__(self,op,a,start,steps):
        super().__init__(pathlib.Path('/nonexistent/b61'))
        self.op=op;self.a=a;self.start=start;self.steps=steps;self.progress=[];self.active=False;self.selected=None
    def plan_reading(self,query,list_name):
        self.active=True
        try:return super().plan_reading(query,list_name)
        finally:self.active=False
    def search_catalog(self,query,limit=5):
        if not self.active:raise LibraryError('NO_PARENT')
        x=super().search_catalog(query,limit);self.selected=x.books[0].book_id if x.books else None
        log(dict(stage='SEARCH',attempt=self.a,selected=self.selected,query=query))
        return x
    def save_reading_item(self,book_id,list_name):
        if not self.active or self.selected!=book_id:raise LibraryError('NO_PARENT_PATH')
        child=dict(book_id=clean_text(book_id,'book_id',30).upper(),list_name=clean_text(list_name,'list_name',60).casefold())
        r=event(self.op,'STEP',attempt=self.a,start=self.start,index=len(self.progress),child=child)
        self.progress.append(r);crash('STEP')
        book=next(b for b in self._catalog() if b.book_id==child['book_id'])
        return SaveResult(status='created' if r['status']=='EFFECT_ATTRIBUTED' else 'already_saved',list_name=child['list_name'],book=book,saved_at='not-recorded-by-B60')
mcp=MCPServer('risu-b61')
@mcp.tool()
def plan_reading(query:str,list_name:str,ctx:Context)->dict:
    """Search the original catalog and save the approved selection."""
    try:
        rid=ctx.request_context.request_id
        if type(rid) not in (int,str):raise ValueError('NATIVE_ID')
        meta=ctx.request_context.meta;md=meta if isinstance(meta,dict) else (meta.model_dump(by_alias=True,exclude_none=True) if meta else {})
        env=md.get('risu_b61')
        log(dict(stage='PARENT',connection=conn,id=rid,args=dict(query=query,list_name=list_name),envelope=env))
        if not isinstance(env,dict):raise ValueError('MISSING_INTENT')
        pol=verified(c['trust']['owner'],POL,env['policy']);intent=verified(c['trust']['actor'],INT,env['intent'])
        if pol['scope']!=c['trust']['scope'] or pol['args']!=dict(query=query,list_name=list_name):raise ValueError('PARENT_BINDING')
        a=intent['call']
        if intent!=dict(run=c['run'],call=a,policy=digest(env['policy'])):raise ValueError('INTENT_BINDING')
        op=pol['op'];start=event(op,'START',attempt=a,connection=conn,native_id=rid,model_call=a)['start'];crash('START')
        svc=Bound(op,a,start,pol['steps']);actual=svc.plan_reading(query,list_name)
        log(dict(stage='ORIGINAL_RETURN',attempt=a,result=actual.model_dump()))
        if len(svc.progress)!=1 or pol['steps']!=[dict(book_id=actual.saved.book.book_id,list_name=actual.saved.list_name)]:raise ValueError('ORIGINAL_RETURN_BINDING')
        output=dict(saved=pol['steps'],receipts=[digest(r) for r in svc.progress])
        result=event(op,'FINISH',attempt=a,start=start,output=output);crash('FINISH')
        return result
    except Exception as exc:
        log(dict(stage='ERROR',error=type(exc).__name__+':'+str(exc)))
        raise ToolError('RISU:'+str(exc)) from exc
if __name__=='__main__':mcp.run(transport='stdio')
