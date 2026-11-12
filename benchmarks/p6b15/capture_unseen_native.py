"""B15 heldout native MCP capture with independently observed state snapshots.

Read-only product analyzer is frozen separately. This harness launches only
three explicitly pinned public upstreams in synthetic disposable CI fixtures.
"""
from __future__ import annotations
import argparse,asyncio,hashlib,json,os,sqlite3,tempfile
from pathlib import Path

def dump(obj):
    return json.dumps(obj,ensure_ascii=False,sort_keys=True,separators=(',',':'))

def digest(obj):
    return hashlib.sha256(dump(obj).encode('utf-8')).hexdigest()

def snapshot(root,case):
    db=root/('.mcp_memory/memories.db' if case=='FM' else 'b15.sqlite')
    state={'exists':db.is_file(),'schema':[],'tables':{}}
    if db.is_file():
        with sqlite3.connect('file:'+str(db)+'?mode=ro',uri=True,timeout=3) as con:
            state['user_version']=con.execute('PRAGMA user_version').fetchone()[0]
            state['schema']=[list(x) for x in con.execute(
                "SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name")]
            names=[x[0] for x in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
            if case=='FM':names=[x for x in names if x=='memories']
            for name in names[:40]:
                if not all(c.isalnum() or c=='_' for c in name):raise ValueError('Unsafe fixture table name')
                rows=con.execute('SELECT * FROM "'+name+'" LIMIT 200').fetchall()
                def atom(x):return {'blob':hashlib.sha256(x).hexdigest()} if type(x) is bytes else x
                state['tables'][name]=sorted([[atom(v) for v in row] for row in rows],key=dump)
    if case=='FM':
        tree=root/'memory'
        state['okf']={}
        if tree.is_dir():
            files=sorted(f for f in tree.rglob('*') if f.is_file() and not f.is_symlink())
            if len(files)>64:raise ValueError('Excessive original OKF files')
            for f in files:
                raw=f.read_bytes()
                if len(raw)>32768:raise ValueError('Oversized test memory')
                state['okf'][f.relative_to(tree).as_posix()]=hashlib.sha256(raw).hexdigest()
    return state

def fixture(root,source,case):
    if case=='PA':
        with sqlite3.connect(root/'b15.sqlite') as c:
            c.execute('CREATE TABLE records (id INTEGER PRIMARY KEY,label TEXT NOT NULL)')
            c.executemany('INSERT INTO records VALUES (?,?)',
                [(1,'RISU_B15_ONE'),(2,'RISU_B15_TWO'),(3,'RISU_B15_Ω')])
    if case=='ZM':
        sql=(source/'create_sources_db.sql').read_text('utf-8')
        if len(sql)>120000:raise ValueError('Unbounded schema file')
        with sqlite3.connect(root/'b15.sqlite') as c:
            c.executescript(sql)
            c.execute('PRAGMA user_version=3')

def args_for(case,source,root):
    if case=='PA':return ['-m','mcp_sqlite.server',str(root/'b15.sqlite')]
    if case=='ZM':return [str(source/'sqlite-paper-fastmcp-server.py')]
    if case=='FM':return [str(source/'memory_server.py')]
    raise ValueError('Unknown case')

def contracts(selected,calls,raw):
    rule_set={}
    witnesses=[]
    for index,planned in enumerate(selected['calls']):
        match=next((x for x in calls if x['index']==index),None)
        all_args=match['args'] if match and match['status']=='CAPTURED' else planned['args']
        selector={k:v for k,v in all_args.items()
            if type(v) in (str,int,float,bool,type(None))
            and len(str(v))<=1024 and not str(v).startswith(chr(36)+'{')}
        spec={'tool':planned['name'],'kind':planned['expect'],'when':selector}
        unique=dump(spec)
        if unique not in rule_set:
            rule_set[unique]={'id':planned['label'],**spec}
        if match and match['status']=='CAPTURED':
            witnesses.append({'session':'default',
                'request_line':match['request_line'],'response_line':match['response_line'],
                'tool':planned['name'],'before_sha256':digest(match['before']),
                'after_sha256':digest(match['after'])})
    return (
        {'schema':'risu-mcp-observation-contract-v1','rules':list(rule_set.values())},
        {'schema':'risu-mcp-state-witness-v1',
         'trace_sha256':hashlib.sha256(raw).hexdigest(),'records':witnesses})

async def capture(case,source,exe,manifest,out):
    doc=json.loads(manifest.read_text('utf-8'))
    assert doc['schema']=='risu-p6b15-untouched-external-cohort-v1'
    assert doc['frozen_analyzer']=='4314e9bf92e2ec75c421bab25eae3b43f1424a08'
    selected=next(x for x in doc['cases'] if x['id']==case)
    if out.exists() or not source.is_dir() or not exe.is_file():
        raise ValueError('No original source, or refusing overwrite')
    out.mkdir(parents=True)
    origin={'schema':'risu-b15-source-native-v1','case':case,
            'repository':selected['repository'],'source_commit':selected['commit'],
            'locked_calls':len(selected['calls']),'status':'UNVERIFIED'}
    calls=[]
    raw_lines=[]
    proc=None
    with tempfile.TemporaryDirectory(prefix='risu-b15-unseen-') as temp:
        root=Path(temp).resolve()
        fixture(root,source,case)
        orig_before=snapshot(root,case)
        origin['initial_state_sha256']=digest(orig_before)
        env={'PATH':os.environ.get('PATH',''),'HOME':str(root),
             'PYTHONPATH':str(source),'PYTHONDONTWRITEBYTECODE':'1','CI':'true',
             'LANG':'C.UTF-8','LC_ALL':'C.UTF-8','NO_COLOR':'1',
             'SQLITE_DB_PATH':str(root/'b15.sqlite'),
             'MCP_MEMORY_PROJECT_ROOT':str(root),
             'MCP_MEMORY_DB_PATH':'.mcp_memory/memories.db','MCP_MEMORY_DIR':'memory'}
        async def send(request):
            assert proc and proc.stdin and proc.stdout
            message=(json.dumps(request,separators=(',',':'),ensure_ascii=False)+'\n').encode()
            proc.stdin.write(message)
            await asyncio.wait_for(proc.stdin.drain(),15)
            raw_lines.append(message)
            start=len(raw_lines)
            if 'id' not in request:return None,start,None
            for _ in range(18):
                reply=await asyncio.wait_for(proc.stdout.readline(),35)
                if not reply or not reply.endswith(b'\n') or len(reply)>524288:
                    raise RuntimeError('Missing or oversized original native stdio line')
                raw_lines.append(reply)
                value=json.loads(reply)
                if type(value) is not dict or value.get('jsonrpc')!='2.0':
                    raise RuntimeError('Original server wrote non-protocol stdout')
                if value.get('id')==request['id']:return value,start,len(raw_lines)
                if 'id' not in value:continue
                raise RuntimeError('Unexpected server-initiated request')
            raise RuntimeError('Excess unmatched server messages')
        try:
            proc=await asyncio.create_subprocess_exec(str(exe),*args_for(case,source,root),
                cwd=str(root),env=env,stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,limit=524290)
            init,_,_=await send({'jsonrpc':'2.0','id':1,'method':'initialize',
                'params':{'protocolVersion':'2025-11-25','capabilities':{},
                'clientInfo':{'name':'risu-b15-unseen-test','version':'1'}}})
            if type(init.get('result')) is not dict:raise RuntimeError('Original MCP initialize rejected')
            origin['protocol']=init['result'].get('protocolVersion')
            await send({'jsonrpc':'2.0','method':'notifications/initialized'})
            tools=set()
            cursor=None
            for page in range(8):
                page_resp,_,_=await send({'jsonrpc':'2.0','id':2+page,
                    'method':'tools/list','params':({'cursor':cursor} if cursor else {})})
                result=page_resp.get('result')
                if type(result) is not dict or type(result.get('tools')) is not list:
                    raise RuntimeError('Native MCP tool catalog unavailable')
                tools.update(x.get('name') for x in result['tools'] if type(x) is dict)
                cursor=result.get('nextCursor')
                if not cursor:break
                if type(cursor) is not str or len(cursor)>256:raise RuntimeError('Invalid catalog cursor')
            else:raise RuntimeError('Tool catalog pagination incomplete')
            origin['advertised_tools']=len(tools)
            for i,spec in enumerate(selected['calls']):
                args=json.loads(json.dumps(spec['args'],ensure_ascii=False)
                    .replace(chr(36)+'{ROOT}',str(root))
                    .replace(chr(36)+'{DB}',str(root/'b15.sqlite')))
                before=snapshot(root,case)
                if spec['name'] not in tools:
                    calls.append({'index':i,'status':'UNVERIFIED_TOOL_ABSENT',
                        'tool':spec['name'],'before':before,'after':snapshot(root,case)})
                    continue
                reply,start,end=await send({'jsonrpc':'2.0','id':20+i,'method':'tools/call',
                    'params':{'name':spec['name'],'arguments':args}})
                after=snapshot(root,case)
                calls.append({'index':i,'status':'CAPTURED','tool':spec['name'],
                    'args':args,'request_line':start,'response_line':end,'response':reply,
                    'before':before,'after':after})
            origin['status']='CAPTURED_NATIVE' if len(calls)==len(selected['calls']) else 'UNVERIFIED_PARTIAL'
        except Exception as error:
            origin['status']='UNVERIFIED_CAPTURE_ERROR'
            origin['error_kind']=type(error).__name__
            origin['error_detail']=str(error)[:280]
        finally:
            if proc and proc.returncode is None:
                proc.terminate()
                try:await asyncio.wait_for(proc.wait(),7)
                except asyncio.TimeoutError:
                    proc.kill();await proc.wait()
            if proc and proc.stderr:
                try:
                    stderr=(await asyncio.wait_for(proc.stderr.read(4096),3)).decode('utf-8','replace')
                    origin['stderr_tail']=stderr[-800:]
                except (OSError,asyncio.TimeoutError):pass
            origin['final_state_sha256']=digest(snapshot(root,case))
    raw=b''.join(raw_lines)
    origin['trace_sha256']=hashlib.sha256(raw).hexdigest()
    origin['lines']=len(raw_lines)
    origin['calls_recorded']=len(calls)
    (out/'original_stdio.jsonl').write_bytes(raw)
    (out/'origin.json').write_text(json.dumps(origin,indent=2,ensure_ascii=False,sort_keys=True)+'\n')
    (out/'per_call_state.json').write_text(json.dumps(calls,indent=2,ensure_ascii=False,sort_keys=True)+'\n')
    if raw and len(raw)<=4194304 and len(raw_lines)<=4096:
        contract,witness=contracts(selected,calls,raw)
        (out/'contract.json').write_text(json.dumps(contract,indent=2,ensure_ascii=False,sort_keys=True)+'\n')
        (out/'witness.json').write_text(json.dumps(witness,indent=2,ensure_ascii=False,sort_keys=True)+'\n')
    print('B15_HELDOUT_NATIVE_SOURCE',json.dumps({k:origin.get(k) for k in
        ('case','status','source_commit','calls_recorded','locked_calls','trace_sha256','error_kind')},
        sort_keys=True))

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--case',choices=['PA','ZM','FM'],required=True)
    p.add_argument('--source',type=Path,required=True)
    p.add_argument('--executable',type=Path,required=True)
    p.add_argument('--manifest',type=Path,default=Path('benchmarks/p6b15/FROZEN_UNSEEN_ORIGINAL_SERVERS.json'))
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    asyncio.run(capture(a.case,a.source.resolve(),a.executable.resolve(),a.manifest,a.out))
if __name__=='__main__':
    main()
