"""Trusted MCP handler wraps the actual original composite service."""
import json,os,pathlib,sys,uuid
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from broker59 import enc,parse,verify,digest,DOMAIN,INTENT,PATH,call
from mcp.server import MCPServer
from mcp.server.mcpserver import Context
c=parse(pathlib.Path(sys.argv[1]).read_bytes())
sys.path.insert(0,c['upstream'])
from library_toolkit.service import LibraryService,LibraryError,SaveResult,clean_text
key=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(c['path_key']))
conn=uuid.uuid4().hex
def signed(domain,b):return dict(body=b,signature=key.sign(domain+enc(b)).hex())
def log(x):
    with open(c['log'],'ab') as f:f.write(enc(x)+b'\n');f.flush();os.fsync(f.fileno())
class BoundService(LibraryService):
    def __init__(self,p,i,rid):
        super().__init__(pathlib.Path('/nonexistent/risu-no-db'))
        self.p=p;self.i=i;self.rid=rid;self.selected=None;self.active=False
    def plan_reading(self,query,list_name):
        if self.active:raise LibraryError('NESTED_PARENT')
        self.active=True
        try:return super().plan_reading(query,list_name)
        finally:self.active=False
    def search_catalog(self,query,limit=5):
        if not self.active:raise LibraryError('NO_PARENT')
        found=super().search_catalog(query,limit)
        self.selected=found.books[0].book_id if found.books else None
        log(dict(event='SEARCH',id=self.rid,connection=conn,selected=self.selected,call=self.p['body']['attempt']))
        return found
    def save_reading_item(self,book_id,list_name):
        if not self.active or self.selected!=book_id:raise LibraryError('NO_PARENT_PATH')
        child=dict(book_id=clean_text(book_id,'book_id',30).upper(),list_name=clean_text(list_name,'list_name',60).casefold())
        proof=signed(PATH,dict(permit_sha256=digest(self.p),intent=self.i,connection=conn,native_id=self.rid,selected=self.selected,child=child,phase='ORIGINAL_PLAN_SEARCH_THEN_SAVE'))
        log(dict(event='CHILD',id=self.rid,connection=conn,permit=self.p,proof=proof,child=child))
        out=call(c['socket'],self.p,child,proof)
        log(dict(event='BROKER',id=self.rid,connection=conn,result=out))
        if not out['ok']:raise LibraryError(out['error'])
        r=out['receipt'];book=next(b for b in self._catalog() if b.book_id==child['book_id'])
        return SaveResult(status='created' if r['status']=='EFFECT_ATTRIBUTED' and not out['replay'] else 'already_saved',list_name=child['list_name'],book=book,saved_at=r['saved_at'])
mcp=MCPServer('risu-b59')
@mcp.tool()
def plan_reading(query:str,list_name:str,ctx:Context)->dict:
    """Search the original catalog and save the first matching book with exact authorization."""
    rid=ctx.request_context.request_id
    if type(rid) not in (int,str):raise ValueError('NATIVE_ID')
    meta=ctx.request_context.meta
    md=meta if isinstance(meta,dict) else (meta.model_dump(by_alias=True,exclude_none=True) if meta is not None else {})
    env=md.get('risu_b59')
    log(dict(event='PARENT',id=rid,connection=conn,arguments=dict(query=query,list_name=list_name),envelope=env))
    if not isinstance(env,dict):raise ValueError('MISSING_INTENT')
    p=env['permit'];i=env['intent'];b=verify(c['owner_pub'],DOMAIN,p)
    parent=dict(tool='plan_reading',arguments=dict(query=query,list_name=list_name))
    if b['scope']!=c['scope'] or b['parent']!=parent:raise ValueError('PARENT_BINDING')
    if verify(c['actor_pub'],INTENT,i)!=dict(call=b['attempt'],run=c['run'],permit_sha256=digest(p),parent=parent):raise ValueError('INTENT_BINDING')
    result=BoundService(p,i,rid).plan_reading(query,list_name)
    return result.model_dump()
if __name__=='__main__':mcp.run(transport='stdio')
