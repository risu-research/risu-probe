"""Real stdio reproduction of an official public MCP Memory Server bug/fix.

Only compiled code at two fixed public Git commits is executed. The memory JSONL
is synthetic and temporary. No live MCP endpoints or customer data are used.
"""
from __future__ import annotations
import argparse,asyncio,hashlib,json,os
from pathlib import Path
import tempfile

UPSTREAM={
 'old':'861c11b786b3efbc87eb2e878a4039d33846a031',
 'fixed':'72e11113edff5919e74de1d69b71203991fe2f05',
}
SEED=[
 {'type':'entity','name':'Alice','entityType':'person','observations':['works at Acme']},
 {'type':'entity','name':'Bob','entityType':'person','observations':['knows Alice']},
 {'type':'relation','from':'Alice','to':'Bob','relationType':'knows'},
]

async def capture(repo:Path,mode:str,scenario:str,out:Path)->dict:
    server=(repo/'src/memory/dist/index.js').resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix='risu-public-memory-') as tmp:
        store=Path(tmp)/'synthetic.jsonl'
        store.write_text(''.join(json.dumps(x,separators=(',',':'))+'\n' for x in SEED) if scenario=='seeded' else '')
        env={'HOME':tmp,'PATH':os.environ['PATH'],'MEMORY_FILE_PATH':str(store),
             'NODE_ENV':'production','CI':'true'}
        process=await asyncio.create_subprocess_exec('node',str(server),
            cwd=str(server.parent),env=env,stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.DEVNULL)
        lines=[]
        async def send(message:dict)->dict:
            assert process.stdin and process.stdout
            data=(json.dumps(message,separators=(',',':'))+'\n').encode()
            assert len(data)<8192
            lines.append(data);process.stdin.write(data)
            await asyncio.wait_for(process.stdin.drain(),15)
            if 'id' not in message:return {}
            raw=await asyncio.wait_for(process.stdout.readline(),15)
            if not raw or len(raw)>524288:raise RuntimeError('Missing/oversized MCP response')
            value=json.loads(raw)
            if value.get('jsonrpc')!='2.0' or value.get('id')!=message['id']:
                raise RuntimeError('Unexpected MCP response ID')
            lines.append(raw)
            return value
        try:
            init=await send({'jsonrpc':'2.0','id':1,'method':'initialize','params':{
                'protocolVersion':'2025-11-25','capabilities':{},
                'clientInfo':{'name':'risu-public-reproduction','version':'1.0'}}})
            assert 'result' in init, 'MCP initialize failed'
            await send({'jsonrpc':'2.0','method':'notifications/initialized'})
            catalog=await send({'jsonrpc':'2.0','id':2,'method':'tools/list','params':{}})
            assert 'result' in catalog,'MCP tools/list failed'
            names={x['name'] for x in catalog['result']['tools']}
            assert {'read_graph','search_nodes','open_nodes'}<=names,names
            tests=[('read_graph',{}),('search_nodes',{'query':'Alice'}),
                   ('open_nodes',{'names':['Alice']})] if scenario=='seeded' else [('read_graph',{})]
            outcomes={}
            for id_,(name,args) in enumerate(tests,10):
                response=await send({'jsonrpc':'2.0','id':id_,'method':'tools/call',
                         'params':{'name':name,'arguments':args}})
                if 'error' in response:
                    error=response['error']
                    detail=str(error.get('message','')) if isinstance(error,dict) else ''
                    outcomes[name]={'kind':'JSONRPC_ERROR',
                        'code':error.get('code') if isinstance(error,dict) else None,
                        'reported_output_schema_rejection':'schema' in detail.lower() and
                                   ('structured' in detail.lower() or 'content' in detail.lower())}
                else:
                    r=response['result'];structured=r.get('structuredContent')
                    outcomes[name]={'kind':'MCP_RESULT','is_error':r.get('isError',False),
                       'structured_content_present':'structuredContent' in r,
                       'entities':len(structured.get('entities',[])) if isinstance(structured,dict) else None}
            raw=b''.join(lines)
            assert len(raw)<524288
            out.mkdir(parents=True,exist_ok=True)
            (out/'raw_stdio.jsonl').write_bytes(raw)
            pack=json.loads((repo/'src/memory/package.json').read_text())
            origin={'schema':'risu-p6b6-upstream-memory-raw-stdio-v1',
                'repository':'https://github.com/modelcontextprotocol/servers',
                'commit':UPSTREAM[mode],'package':pack['name'],'package_version':pack['version'],
                'lock_sha256':hashlib.sha256((repo/'package-lock.json').read_bytes()).hexdigest(),
                'mode':mode,'scenario':scenario,'synthetic_data_only':True,'actual_stdio':True,
                'negotiated_protocol':init['result']['protocolVersion'],
                'trace_sha256':hashlib.sha256(raw).hexdigest(),
                'message_count':len(lines),'tool_outcomes':outcomes}
            (out/'origin.json').write_text(json.dumps(origin,sort_keys=True,indent=2)+'\n')
            print('P6B6_REAL_PUBLIC_MEMORY_STDIO',mode,scenario,outcomes,flush=True)
            return origin
        finally:
            if process.returncode is None:
                process.terminate()
                try:await asyncio.wait_for(process.wait(),7)
                except asyncio.TimeoutError:process.kill();await process.wait()

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--repo',type=Path,required=True)
    parser.add_argument('--mode',choices=UPSTREAM,required=True)
    parser.add_argument('--scenario',choices=('seeded','empty'),required=True)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args()
    asyncio.run(capture(args.repo,args.mode,args.scenario,args.out))
