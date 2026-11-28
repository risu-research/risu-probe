"""B63 trusted handler, original CampusReads methods and frozen gate."""
import os,sys,pathlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mcp.server import MCPServer
from mcp.server.mcpserver import Context
from mcp.server.mcpserver.exceptions import ToolError
from broker63 import call
import gate62 as G
import lifecycle as L
c=G.parse(pathlib.Path(sys.argv[1]).read_bytes());sys.path.insert(0,c['upstream'])
from library_toolkit.service import LibraryService,LibraryError,SaveResult,clean_text
key=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(c['handler_key']))
def log(x):
    with open(c['log'],'ab') as f:f.write(G.enc(x)+b'\n');f.flush();os.fsync(f.fileno())
def ask(req):
    r=call(c['socket'],req);log(dict(stage=req['kind'],request=req,result=r))
    if not r['ok']:raise ValueError(r['error'])
    return r['result']
def event(op,kind,**kw):
    return ask(dict(kind='event',event=G.sign(key,L.DOMAIN,dict(scope=c['scope'],op=op,kind=kind,**kw))))['result']
def crash(stage):
    if c['mode']==stage:os._exit({'ADMISSION':91,'STEP':82,'FINISH':83}[stage])
class Bound(LibraryService):
    def __init__(self,op,a,start):
        super().__init__(pathlib.Path('/nonexistent/b63'));self.op=op;self.a=a;self.start=start;self.progress=[];self.active=False;self.selected=None
    def plan_reading(self,query,list_name):
        self.active=True
        try:return super().plan_reading(query,list_name)
        finally:self.active=False
    def search_catalog(self,query,limit=5):
        if not self.active:raise LibraryError('NO_PARENT')
        x=super().search_catalog(query,limit);self.selected=x.books[0].book_id if x.books else None
        log(dict(stage='SEARCH',attempt=self.a,selected=self.selected));return x
    def save_reading_item(self,book_id,list_name):
        if not self.active or self.selected!=book_id:raise LibraryError('NO_PARENT_PATH')
        child=dict(book_id=clean_text(book_id,'book_id',30).upper(),list_name=clean_text(list_name,'list_name',60).casefold())
        r=event(self.op,'STEP',attempt=self.a,start=self.start,index=len(self.progress),child=child)
        self.progress.append(r);crash('STEP')
        book=next(b for b in self._catalog() if b.book_id==child['book_id'])
        return SaveResult(status='created' if r['status']=='EFFECT_ATTRIBUTED' else 'already_saved',list_name=child['list_name'],book=book,saved_at='not-recorded-by-B60')
mcp=MCPServer('risu-b63')
@mcp.tool()
def plan_reading(query:str,list_name:str,ctx:Context)->dict:
    """Search and save the authorized catalog item."""
    try:
        rid=ctx.request_context.request_id;meta=ctx.request_context.meta
        md=meta if isinstance(meta,dict) else (meta.model_dump(by_alias=True,exclude_none=True) if meta else {})
        env=md['risu_b63_signed'];model=md['risu_b63']['model']
        observed=dict(connection=c['connection'],native=rid,model=model,parent=dict(tool='plan_reading',arguments=dict(query=query,list_name=list_name)))
        log(dict(stage='NATIVE_PARENT',observed=observed,envelope=env))
        r=ask(dict(kind='admit',envelope=env,observed=observed))
        if not r['dispatch']:raise ValueError(r['decision'])
        crash('ADMISSION')
        i=env['intent']['body'];op=i['op'];a=i['attempt']
        start=event(op,'START',attempt=a,connection=c['connection'],native_id=rid,model_call=model)['start']
        svc=Bound(op,a,start);actual=svc.plan_reading(query,list_name)
        log(dict(stage='ORIGINAL_RETURN',result=actual.model_dump()))
        steps=env['policy']['body']['steps']
        if len(svc.progress)!=1 or steps!=[dict(book_id=actual.saved.book.book_id,list_name=actual.saved.list_name)]:raise ValueError('ORIGINAL_RETURN_BINDING')
        r=event(op,'FINISH',attempt=a,start=start,output=dict(saved=steps,receipts=[G.digest(x) for x in svc.progress]))
        crash('FINISH');return r
    except Exception as e:raise ToolError('RISU:'+str(e)) from e
@mcp.tool()
def recover_signed(query:dict,ctx:Context)->dict:
    """Read an authenticated operation observation; never dispatch an effect."""
    try:
        log(dict(stage='NATIVE_QUERY',native=ctx.request_context.request_id,connection=c['connection'],query=query))
        return ask(dict(kind='recover',query=query))
    except Exception as e:raise ToolError('RISU:'+str(e)) from e
if __name__=='__main__':mcp.run(transport='stdio')
