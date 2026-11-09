"""P6-B12: genuine unmodified upstream stdio survey and immutable original lines.

Runner accepts only predeclared case names and synthetic local data, never arbitrary
remote MCP URLs or target-provided commands. No source evaluation by RISU itself.
"""
from __future__ import annotations
import argparse,asyncio,hashlib,json,os,sqlite3,sys,tempfile
from pathlib import Path

MAX_LINE=524288
MAX_TRACE=4194304
MAX_MSGS=128
CASES={'FS','MEM','ALCHEMY','GO','SQLITE'}

def new_fixture(root:Path):
    root.mkdir(parents=True,exist_ok=True)
    con=sqlite3.connect(root/'b12.db')
    con.executescript("""
    CREATE TABLE records(id INTEGER PRIMARY KEY,label TEXT,limit_hint TEXT);
    INSERT INTO records(label,limit_hint) VALUES ('row_one','hint_01');
    INSERT INTO records(label,limit_hint) VALUES ('row_two','hint_02');
    INSERT INTO records(label,limit_hint) VALUES ('row_three','hint_03');
    INSERT INTO records(label,limit_hint) VALUES ('row_four','hint_04');
    INSERT INTO records(label,limit_hint) VALUES ('row_five','hint_05');
    INSERT INTO records(label,limit_hint) VALUES ('row_six','hint_06');
    INSERT INTO records(label,limit_hint) VALUES ('row_seven','hint_07');
    INSERT INTO records(label,limit_hint) VALUES ('row_eight','hint_08');
    """)
    con.close()
    return {'db':root/'b12.db','memory':root/'graph.jsonl','fs':root/'files'}

def source_plan(case:str,root:Path,manifest:dict):
    item=next(c for c in manifest['cases'] if c['id']==case)
    def subst(value):
        if isinstance(value,str):return value.replace('${ROOT}',str(root/'files'))
        if isinstance(value,dict):return {k:subst(v) for k,v in value.items()}
        if isinstance(value,list):return [subst(v) for v in value]
        return value
    probes=[{'name':p['name'],'arguments':subst(p['args'])} for p in item['tools']]
    assert 1<=len(probes)<=8
    for p in probes:
        assert len(json.dumps(p,ensure_ascii=False))<8192
    return probes

async def run(case:str,exe:Path,argv:list[str],manifest:Path,output:Path):
    if case not in CASES or output.exists() or output.is_symlink():
        raise ValueError('Unknown case or refusing to overwrite existing evidence')
    assert exe.exists() and exe.is_file()
    declarations=json.loads(manifest.read_text())
    assert declarations['schema']=='risu-b12-20261108-blind-source-first-protocol-qualification-v1'
    entry=next((x for x in declarations['cases'] if x['id']==case),None)
    assert entry is not None
    with tempfile.TemporaryDirectory(prefix='risu-b12-real-server-') as td:
        root=Path(td).resolve()
        fixture=new_fixture(root)
        fixture['fs'].mkdir()
        probes=source_plan(case,root,declarations)
        env={'HOME':str(root),'PATH':os.environ.get('PATH',''),
             'LANG':'C.UTF-8','LC_ALL':'C.UTF-8',
             'NO_COLOR':'1','PYTHONDONTWRITEBYTECODE':'1',
             'CI':'true','MEMORY_FILE_PATH':str(fixture['memory']),
             'DB_URL':'sqlite:///'+str(fixture['db']),
             'SQLITE_DB_PATH':str(fixture['db'])}
        # Only allow case's own locally built or Git checked-out file imports.
        if case=='SQLITE':
            assert len(argv)==2 and argv[0]=='-c' and argv[1]=='import sqlite_explorer; sqlite_explorer.mcp.run()'
            env['PYTHONPATH']=str(exe.parent.parent/'sqlite-source')
        assert len(argv)<=6
        if case=='FS':
            argv=[*argv,str(fixture['fs'])]
        proc=await asyncio.create_subprocess_exec(str(exe),*argv,
            cwd=str(root),env=env,stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,
            limit=MAX_LINE+2)
        lines=[]
        async def transact(req):
            assert proc.stdin and proc.stdout
            raw=(json.dumps(req,ensure_ascii=False,separators=(',',':'))+'\n').encode()
            proc.stdin.write(raw)
            await asyncio.wait_for(proc.stdin.drain(),15)
            lines.append(raw)
            if 'id' not in req:return None
            for attempt in range(18):
                reply=await asyncio.wait_for(proc.stdout.readline(),35)
                if not reply or len(reply)>MAX_LINE or not reply.endswith(b'\n'):
                    details=''
                    if proc.returncode is not None and proc.stderr:
                        details=(await proc.stderr.read(700)).decode('utf-8','replace')
                    raise RuntimeError('Invalid or missing genuine MCP stdout response '+details[:500])
                lines.append(reply)
                msg=json.loads(reply)
                if not isinstance(msg,dict) or msg.get('jsonrpc')!='2.0':
                    raise RuntimeError('Native stdout contains a non-JSON-RPC message')
                if msg.get('id')==req['id']:
                    return msg
                # Genuine MCP notifications and server-to-client requests get
                # captured unchanged but cannot count as the matching response.
                if 'id' not in msg:
                    continue
                raise RuntimeError('Server-to-client requests are outside prelocked safe-client capabilities')
            raise RuntimeError('Excessive unmatched notifications')
        try:
            initialized=await transact({'jsonrpc':'2.0','id':1,'method':'initialize',
                'params':{'protocolVersion':'2025-11-25','capabilities':{},
                          'clientInfo':{'name':'risu-b12-frozen-public-synthetic','version':'1'}}})
            if not isinstance(initialized.get('result'),dict):
                raise RuntimeError('Real upstream MCP initialize returned error')
            negotiated=initialized['result'].get('protocolVersion')
            await transact({'jsonrpc':'2.0','method':'notifications/initialized'})
            all_tools=[]
            cursor=None
            for page in range(8):
                param={'cursor':cursor} if cursor else {}
                listing=await transact({'jsonrpc':'2.0','id':2+page,'method':'tools/list','params':param})
                result=listing.get('result')
                if not isinstance(result,dict) or not isinstance(result.get('tools'),list):
                    raise RuntimeError('Real upstream MCP tools/list failed')
                all_tools+=result['tools']
                cursor=result.get('nextCursor')
                if not cursor:break
                if not isinstance(cursor,str) or len(cursor)>256:
                    raise RuntimeError('Invalid catalog cursor')
            else:raise RuntimeError('Catalog exceeded eight genuine pages')
            available={p.get('name') for p in all_tools if isinstance(p,dict)}
            missing=[p['name'] for p in probes if p['name'] not in available]
            if missing:
                raise RuntimeError('Predeclared tools unavailable in pinned source: '+repr(missing))
            calls=[]
            for ix,p in enumerate(probes,20):
                response=await transact({'jsonrpc':'2.0','id':ix,'method':'tools/call',
                    'params':p})
                calls.append({'tool':p['name'],'response':response,
                              'call_id':ix,'input':p['arguments']})
            captured=b''.join(lines)
            if len(captured)>MAX_TRACE or len(lines)>MAX_MSGS:
                raise RuntimeError('Captured original stdio output exceeds product limits')
            # Primary evidence is unmodified OS bytes. Derived results are for
            # independently checking the declared fixture/oracle only.
            output.mkdir(parents=True)
            (output/'original_stdio.jsonl').write_bytes(captured)
            (output/'unmodified_responses.json').write_text(json.dumps(calls,ensure_ascii=False,indent=2)+'\n')
            after=sqlite3.connect(fixture['db'])
            db_rows=after.execute('SELECT COUNT(*) FROM records').fetchone()[0]
            after.close()
            info={'schema':'risu-b12-real-native-upstream-stdio-capture-v1',
                'case':case,'source_repo':entry['repository'],'source_commit':entry['commit'],
                'selected_protocol':'2025-11-25','negotiated_protocol':negotiated,
                'native_upstream_stdio':True,'no_test_wrapper':True,
                'source_executable_sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),
                'raw_original_stdio_sha256':hashlib.sha256(captured).hexdigest(),
                'source_stdout_unmodified':True,'total_messages':len(lines),
                'advertised_tools':len(all_tools),'selected_call_count':len(calls),
                'synthetic_rows_after':db_rows,
                'real_tool_results':[
                    {'name':v['tool'],'is_error':v['response'].get('result',{}).get('isError',False)
                         if isinstance(v['response'].get('result'),dict) else True,
                     'structured_present':isinstance(v['response'].get('result'),dict)
                           and 'structuredContent' in v['response']['result']}
                    for v in calls]
            }
            (output/'origin.json').write_text(json.dumps(info,indent=2,sort_keys=True)+'\n')
            print('B12_GENUINE_PINNED_NATIVE_STDIO_CAPTURED',
                  json.dumps({k:info[k] for k in ('case','advertised_tools','selected_call_count',
                          'synthetic_rows_after','raw_original_stdio_sha256')},sort_keys=True))
        finally:
            if proc.returncode is None:
                proc.terminate()
                try:await asyncio.wait_for(proc.wait(),7)
                except asyncio.TimeoutError:
                    proc.kill();await proc.wait()

def main():
    a=argparse.ArgumentParser()
    a.add_argument('--case',choices=sorted(CASES),required=True)
    a.add_argument('--executable',type=Path,required=True)
    a.add_argument('--arg',action='append',default=[])
    a.add_argument('--manifest',type=Path,default=Path('benchmarks/p6b12/prelocked_blind_servers.json'))
    a.add_argument('--out',type=Path,required=True)
    q=a.parse_args()
    asyncio.run(run(q.case,q.executable.expanduser().absolute(),q.arg,
                    q.manifest,q.out))
if __name__=='__main__':main()
