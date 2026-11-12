"""Run two pinned public native MCP servers on disposable synthetic fixtures.

Does not download/install sources, execute target-provided command strings, or
claim novelty from anomalous output. Original stdout bytes are preserved.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import sqlite3
import tempfile
from pathlib import Path

MANIFEST_SCHEMA = 'risu-p6b13-public-native-cross-publisher-metamorphic-v1'
MAX_REPLY = 512 * 1024
MAX_CAPTURE = 4 * 1024 * 1024


def select_case(path: Path, name: str) -> dict:
    data = json.loads(path.read_text('utf-8'))
    assert data['schema'] == MANIFEST_SCHEMA
    assert [(x['id'], x['repo'], x['sha']) for x in data['cohort']] == [
        ('FS2', 'j0hanz/filesystem-mcp', 'ff783caf6191eb41f5a3de0e5f924dcc18f770ce'),
        ('SQL2', 'rusq/mcp-sqlite', '455a196ac2b2783f7a4250ba4ad6d736ddc6437b')]
    return next(x for x in data['cohort'] if x['id'] == name)


def fixture(tmp: Path) -> dict:
    work = tmp / 'workspace'
    work.mkdir()
    file = work / 'b13.txt'
    file.write_text('RISU_B13_FIRST\nΩ unicode literal [x]\nRISU_B13_LAST\n', encoding='utf-8')
    db = tmp / 'b13.sqlite'
    con = sqlite3.connect(db)
    con.executescript('''CREATE TABLE records(id INTEGER PRIMARY KEY,label TEXT NOT NULL);
    INSERT INTO records VALUES (1,'RISU_B13_ONE');
    INSERT INTO records VALUES (2,'RISU_B13_TWO');
    INSERT INTO records VALUES (3,'RISU_B13_Ω');
    INSERT INTO records VALUES (4,'RISU_B13_FOUR');
    INSERT INTO records VALUES (5,'RISU_B13_FIVE');
    INSERT INTO records VALUES (6,'RISU_B13_SIX');''')
    con.close()
    return {'ROOT': str(work), 'FILE': str(file), 'DB': str(db)}


def sub(value, mapping):
    if isinstance(value,str):
        for k,v in mapping.items(): value=value.replace('${'+k+'}', v)
        return value
    if isinstance(value,list): return [sub(x,mapping) for x in value]
    if isinstance(value,dict): return {k:sub(v,mapping) for k,v in value.items()}
    return value


async def run(name: str, exe: Path, source: Path | None, manifest: Path, out: Path) -> None:
    item=select_case(manifest,name)
    if not exe.is_file() or out.exists(): raise ValueError('Executable absent or evidence overwrite denied')
    with tempfile.TemporaryDirectory(prefix='risu-b13-local-') as d:
        root=Path(d).resolve()
        paths=fixture(root)
        inputs=[{'name':t['name'],'arguments':sub(t['args'],paths)} for t in item['tool_calls']]
        env={'PATH':os.environ.get('PATH',''),'HOME':str(root),'LANG':'C.UTF-8',
             'LC_ALL':'C.UTF-8','CI':'true','NO_COLOR':'1'}
        argv=[]
        if name=='FS2':
            if source is None or not (source/'dist/index.js').is_file():
                raise ValueError('Pinned compiled upstream Node entrypoint required')
            argv=[str((source/'dist/index.js').resolve()),'--read-only',paths['ROOT']]
        elif name=='SQL2':
            if source is not None: raise ValueError('Go executable needs no source arg')
        else: raise ValueError('Unknown pinned case')
        proc=await asyncio.create_subprocess_exec(str(exe),*argv,cwd=str(root),env=env,
            stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,limit=MAX_REPLY+2)
        transcript=[]
        async def transact(msg):
            sent=(json.dumps(msg,ensure_ascii=False,separators=(',',':'))+'\n').encode()
            assert proc.stdin and proc.stdout
            proc.stdin.write(sent)
            await asyncio.wait_for(proc.stdin.drain(),15)
            transcript.append(sent)
            if 'id' not in msg:return None
            for _ in range(15):
                raw=await asyncio.wait_for(proc.stdout.readline(),40)
                if not raw or len(raw)>MAX_REPLY or not raw.endswith(b'\n'):
                    raise ValueError('Original server produced no bounded JSON-RPC line')
                transcript.append(raw)
                parsed=json.loads(raw)
                if not isinstance(parsed,dict) or parsed.get('jsonrpc')!='2.0':
                    raise ValueError('Non-JSON-RPC bytes on original stdout')
                if parsed.get('id')==msg['id']:return parsed
                if 'id' not in parsed:continue
                raise ValueError('Unsupported server-to-client request in safe offline probe')
            raise ValueError('Too many unmatched original stdout notifications')
        try:
            init=await transact({'jsonrpc':'2.0','id':1,'method':'initialize',
              'params':{'protocolVersion':'2025-11-25','capabilities':{},
                        'clientInfo':{'name':'risu-b13-synthetic-audit','version':'1'}}})
            if not isinstance(init.get('result'),dict):raise ValueError('Initialize failed')
            await transact({'jsonrpc':'2.0','method':'notifications/initialized'})
            listed=[];cursor=None
            for i in range(8):
                resp=await transact({'jsonrpc':'2.0','id':2+i,'method':'tools/list',
                    'params':({'cursor':cursor} if cursor else {})})
                obj=resp.get('result',{})
                if not isinstance(obj.get('tools'),list): raise ValueError('Unusable tool catalog')
                listed.extend(obj['tools'])
                cursor=obj.get('nextCursor')
                if not cursor:break
                if not isinstance(cursor,str) or len(cursor)>256:raise ValueError('Invalid pagination cursor')
            else:raise ValueError('More than 8 pages')
            available={v.get('name') for v in listed if isinstance(v,dict)}
            absent=[x['name'] for x in inputs if x['name'] not in available]
            if absent:raise ValueError('Predeclared tool absent: '+repr(absent))
            results=[]
            for i,call in enumerate(inputs,20):
                obj=await transact({'jsonrpc':'2.0','id':i,'method':'tools/call','params':call})
                results.append({'tool':call['name'],'input':call['arguments'], 'response':obj,'call_id':i})
            original=b''.join(transcript)
            if len(original)>MAX_CAPTURE or len(transcript)>128:raise ValueError('Capture limit exceeded')
            con=sqlite3.connect(paths['DB'])
            db_snapshot=con.execute('SELECT id,label FROM records ORDER BY id').fetchall()
            con.close()
            meta={'schema':'risu-b13-original-native-stdio-v1','case':name,
                'repository':item['repo'],'source_commit':item['sha'],
                'native_upstream_process':True,'source_stdout_unmodified':True,
                'protocol':init['result'].get('protocolVersion'),
                'executable_sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),
                'original_stdio_sha256':hashlib.sha256(original).hexdigest(),
                'selected_calls':len(inputs),'tools_discovered':len(listed),
                'known_fixture':{'file_sha256':hashlib.sha256(Path(paths['FILE']).read_bytes()).hexdigest(),
                                'file_bytes':Path(paths['FILE']).stat().st_size,'db_rows':db_snapshot}}
            out.mkdir(parents=True)
            (out/'original_stdio.jsonl').write_bytes(original)
            (out/'unmodified_calls.json').write_text(json.dumps(results,ensure_ascii=False,indent=2)+'\n')
            (out/'origin.json').write_text(json.dumps(meta,ensure_ascii=False,indent=2,sort_keys=True)+'\n')
            print('B13_ORIGINAL_NATIVE_CAPTURE',json.dumps({k:meta[k] for k in ('case','source_commit','selected_calls','tools_discovered','original_stdio_sha256')},sort_keys=True))
        finally:
            if proc.returncode is None:
                proc.terminate()
                try:await asyncio.wait_for(proc.wait(),5)
                except asyncio.TimeoutError:
                    proc.kill();await proc.wait()


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--case',choices=('FS2','SQL2'),required=True)
    p.add_argument('--executable',type=Path,required=True)
    p.add_argument('--source',type=Path)
    p.add_argument('--manifest',type=Path,default=Path('benchmarks/p6b13/prelocked_native_cases.json'))
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    asyncio.run(run(a.case,a.executable.resolve(),a.source.resolve() if a.source else None,a.manifest,a.out))

if __name__=='__main__': main()