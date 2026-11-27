"""Run original external service and original FastMCP tool through the broker."""
import asyncio,json,os,pathlib,sys,sqlite3
from broker import call,enc,parse
sys.path.insert(0,os.environ['B58_UPSTREAM'])
from library_toolkit.service import LibraryService,LibraryError,SaveResult,clean_text
def child_args(book_id,list_name):return dict(book_id=clean_text(book_id,'book_id',30).upper(),list_name=clean_text(list_name,'list_name',60).casefold())
class GuardedService(LibraryService):
    def save_reading_item(self,book_id,list_name):
        child=child_args(book_id,list_name)
        book=next((b for b in self._catalog() if b.book_id==child['book_id']),None)
        if book is None:raise LibraryError('BOOK_NOT_FOUND')
        outcome=call(os.environ['B58_SOCKET'],parse(os.environ['B58_PERMIT']),child)
        if not outcome['ok']:raise LibraryError('RISU_DENIED:'+outcome['error'])
        r=outcome['receipt']
        return SaveResult(status='created' if r['status']=='EFFECT_ATTRIBUTED' and not outcome['replay'] else 'already_saved',list_name=child['list_name'],book=book,saved_at=r['saved_at'])
def server():
    from library_toolkit import server as mod
    mod.LibraryService=GuardedService
    mod.create_server(pathlib.Path(os.environ['B58_DB'])).run(transport='stdio',show_banner=False)
async def mcp(req):
    from mcp import Client,StdioServerParameters
    async with Client(StdioServerParameters(command=sys.executable,args=[__file__,'server'],env=dict(os.environ))) as cl:
        tools=await cl.list_tools();assert {t.name for t in tools.tools}=={'search_catalog','save_reading_item','plan_reading'}
        res=await asyncio.wait_for(cl.call_tool(req['tool'],req['arguments']),20)
        return dict(ok=not res.is_error,structured=res.structured_content,text=[x.text for x in res.content if x.type=='text'])
def work(req):
    db=pathlib.Path(os.environ['B58_DB']);mode=req['mode']
    if mode=='broker':return call(os.environ['B58_SOCKET'],req['permit'],req['child'])
    if mode=='raw':
        with sqlite3.connect(db) as c:c.execute("INSERT INTO reading_items VALUES('demo','B006','bypass')")
        return dict(ok=True)
    if mode=='read':
        with sqlite3.connect(db.as_uri()+'?mode=ro',uri=True) as c:return dict(ok=True,rows=c.execute('SELECT * FROM reading_items').fetchall())
    if mode=='mcp':return asyncio.run(mcp(req))
    s=(LibraryService if mode=='original' else GuardedService)(db)
    if req['tool']=='plan_reading':res=s.plan_reading(**req['arguments'])
    else:res=s.save_reading_item(**req['arguments'])
    return dict(ok=True,structured=res.model_dump())
if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='server':server()
    else:
        try:r=work(parse(sys.stdin.buffer.readline()))
        except Exception as e:r=dict(ok=False,error=type(e).__name__+':'+str(e))
        print(enc(r).decode(),flush=True)
