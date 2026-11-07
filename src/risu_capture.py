"""Bounded, fail-closed bridge from native HAR 1.2 + MCP JSON-RPC JSONL.

A small explicit pairs.json states which HTTP exchange corresponds to which
MCP tools/call request. This cannot infer causality, and never treats a
JSON-RPC protocol error as an MCP tool-level result. No network or code exec.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import urlsplit
from risu_recovery import reject_dupes, bounded

MAX_FILE=10_000_000
MAX_LINES=2000
IDENT=re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}\Z',re.ASCII)
FILES=('capture.har','mcp.jsonl','pairs.json')

def _reject_constant(s):raise ValueError('nonfinite JSON token forbidden')

def loads(s):
    try:
        return json.loads(s,object_pairs_hook=reject_dupes,parse_constant=_reject_constant)
    except (UnicodeError,RecursionError) as e:raise ValueError('invalid JSON encoding or depth') from e

def _read(path):
    if path.is_symlink() or not path.is_file() or not (0 < path.stat().st_size <= MAX_FILE):
        raise ValueError('capture input must be a nonsymlink regular file within 10 MB: '+path.name)
    return path.read_bytes()

def _jsonfile(root,name):return loads(_read(root/name).decode('utf-8'))

def _jsonl(root,name,required=True):
    path=root/name
    if not required and not path.exists():return []
    raw=_read(path).decode('utf-8')
    lines=raw.splitlines()
    if not 1<=len(lines)<=MAX_LINES:raise ValueError('JSONL line count out of bounds')
    values=[]
    for idx,line in enumerate(lines):
        if len(line)>1_000_000 or not line.strip():raise ValueError('invalid JSONL line '+str(idx+1))
        obj=loads(line)
        if not isinstance(obj,dict) or not bounded(obj):raise ValueError('oversized/invalid JSONL object')
        values.append(obj)
    return values

def _id(value):
    # JSON-RPC IDs can be strings or integers; bool is not an integer request ID.
    if isinstance(value,bool) or not (isinstance(value,str) and 0<len(value)<=100 or
                                     type(value) is int and 0<=value<=2**53):
        raise ValueError('invalid JSON-RPC id')
    return (type(value).__name__,value)

def _parse_rpc(rows):
    calls={};results={}
    for row in rows:
        if row.get('jsonrpc')!='2.0':raise ValueError('expected native JSON-RPC 2.0 frames')
        if 'id' not in row:
            if str(row.get('method','')).startswith('notifications/'):continue
            raise ValueError('unexpected JSON-RPC notification frame')
        ident=_id(row['id'])
        if row.get('method')=='tools/call':
            if ident in calls:raise ValueError('duplicate tools/call request id')
            params=row.get('params',{})
            if not isinstance(params,dict) or not isinstance(params.get('name'),str) or not IDENT.fullmatch(params['name']):
                raise ValueError('invalid tools/call params')
            calls[ident]=params['name']
        elif 'result' in row or 'error' in row:
            if ident in results:raise ValueError('duplicate JSON-RPC result id')
            if 'error' in row:
                results[ident]=('RPC_ERROR',row['error'])
            else:
                result=row['result']
                if not isinstance(result,dict):raise ValueError('invalid MCP result object')
                results[ident]=('RESULT',result)
        elif row.get('method') in ('initialize','tools/list','server/discover'):
            # Ignore only known, benign non-call requests.
            continue
        else:raise ValueError('unsupported message in MCP call capture')
    return calls,results

def _http(har,index):
    try:
        if har.get('log',{}).get('version')!='1.2':raise ValueError('expected HAR 1.2')
        entries=har['log']['entries']
        if not isinstance(entries,list) or len(entries)>1000:raise ValueError('invalid HAR entries')
        if type(index) is not int or not 0<=index<len(entries):raise ValueError('http entry index out of bounds')
        e=entries[index];req=e['request'];resp=e['response']
        if req.get('method')!='GET':raise ValueError('only recorded HTTP GET supported')
        url=req.get('url','')
        p=urlsplit(url)
        if p.scheme not in ('http','https') or not p.netloc or p.username or p.password or p.fragment:
            raise ValueError('invalid HTTP capture request URL')
        status=resp['status']
        if type(status) is not int or not 100<=status<=599:raise ValueError('invalid HTTP response status')
        ct=resp.get('content',{})
        if ct.get('encoding') not in (None,''):
            raise ValueError('encoded HAR response requires explicit safe decoding; unsupported')
        mime=ct.get('mimeType')
        hdrs=resp.get('headers',[])
        if not isinstance(hdrs,list):raise ValueError('invalid HAR headers')
        headerct=[x['value'] for x in hdrs if isinstance(x,dict) and str(x.get('name','')).lower()=='content-type']
        if len(headerct)>1:raise ValueError('conflicting HAR content types')
        if headerct and mime and headerct[0].split(';')[0].strip().lower()!=mime.split(';')[0].strip().lower():
            raise ValueError('HTTP Content-Type headers and HAR mimeType disagree')
        mime=headerct[0] if headerct else mime
        if not isinstance(mime,str) or mime.split(';')[0].strip().lower() not in ('application/json','application/problem+json'):
            raise ValueError('only captured JSON HTTP responses supported')
        raw=ct.get('text')
        if not isinstance(raw,str) or len(raw)>1_000_000:raise ValueError('missing or oversized HAR response body text')
        body=loads(raw)
        if not isinstance(body,dict) or not bounded(body):raise ValueError('HTTP source JSON must be a bounded object')
        return {'status':status,'content_type':mime,'body':body}
    except (KeyError,IndexError,AttributeError,TypeError) as exc:
        raise ValueError('malformed native HAR 1.2 response') from exc

def load_capture_directory(directory):
    directory=Path(directory)
    if directory.is_symlink() or not directory.is_dir():raise ValueError('capture root must be a nonsymlink directory')
    for n in FILES:
        if not (directory/n).exists():raise ValueError('capture requires '+', '.join(FILES))
    har=_jsonfile(directory,'capture.har')
    calls,results=_parse_rpc(_jsonl(directory,'mcp.jsonl'))
    pairfile=_jsonfile(directory,'pairs.json')
    if not isinstance(pairfile,dict) or pairfile.get('schema')!='risu-explicit-capture-pairing-v1':
        raise ValueError('explicit capture pairing manifest v1 required; no guessed links')
    pairs=pairfile.get('pairs')
    if not isinstance(pairs,list) or not 1<=len(pairs)<=50:
        raise ValueError('expected 1-50 explicit HTTP to MCP pairings')
    consumers={}
    if (directory/'consumer.jsonl').exists():
        for row in _jsonl(directory,'consumer.jsonl',required=False):
            if 'call_id' not in row:raise ValueError('consumer capture missing call_id')
            rid=_id(row['call_id'])
            if rid in consumers:raise ValueError('duplicate consumer call_id')
            kind=row.get('kind')
            if kind!='langchain_toolmessage':
                raise ValueError('consumer format unsupported; never infer consumer mapping')
            message=row.get('message')
            if not isinstance(message,dict) or message.get('type')!='tool' or not isinstance(message.get('content'),(str,list)):
                raise ValueError('invalid LangChain ToolMessage serialized record')
            if message.get('status') not in (None,'success','error'):
                raise ValueError('invalid LangChain ToolMessage status')
            consumers[rid]={'consumer':{
                'type':'ToolMessage','status':message.get('status'),
                'content':message['content'],'artifact':message.get('artifact')},
                'execution_kind':'CAPTURED_LANGCHAIN_TOOLMESSAGE_ORIGIN_UNVERIFIED'}
    used_http=set();used_rpc=set();out=[]
    for p in pairs:
        if not isinstance(p,dict):raise ValueError('invalid pair')
        ident=p.get('case_id');target=p.get('target')
        if not (isinstance(ident,str) and IDENT.fullmatch(ident) and
                isinstance(target,str) and IDENT.fullmatch(target)):
            raise ValueError('invalid pair identity')
        idx=p.get('http_entry');rid=_id(p.get('mcp_call_id'))
        if idx in used_http or rid in used_rpc:raise ValueError('HAR or JSON-RPC evidence reused across cases')
        used_http.add(idx);used_rpc.add(rid)
        if rid not in calls or rid not in results:
            raise ValueError('paired MCP request/response id is missing')
        state,result=results[rid]
        if state!='RESULT':
            raise ValueError('JSON-RPC protocol error is not a tools/call result; outcome inconclusive')
        if result.get('resultType')=='input_required':
            raise ValueError('MCP input_required is unfinished; cannot certify field loss')
        if not isinstance(result.get('content'),list) or len(result['content'])>16 or not bounded(result):
            raise ValueError('invalid bounded MCP result')
        if 'isError' in result and type(result['isError']) is not bool:
            raise ValueError('invalid MCP isError type')
        if result.get('structuredContent') is not None and not isinstance(result['structuredContent'],dict):
            raise ValueError('invalid structuredContent type')
        if p.get('tool')!=calls[rid]:raise ValueError('tool name and MCP request disagree')
        source=_http(har,idx)
        entry={'id':ident,'translator':target,'source':source,'mcp':result,
               'provenance':'EXPLICIT_HAR_MCP_PAIRING_UNATTESTED'}
        if rid in consumers:entry['observed_consumer']=consumers[rid]
        out.append(entry)
    digest={n:hashlib.sha256(_read(directory/n)).hexdigest() for n in FILES}
    if (directory/'consumer.jsonl').exists():digest['consumer.jsonl']=hashlib.sha256(_read(directory/'consumer.jsonl')).hexdigest()
    return {'cases':out}, {'input_kind':'EXTERNAL_HAR_1_2_AND_NATIVE_MCP_JSONRPC_JSONL',
                             'join_kind':'EXPLICIT_UNVERIFIED_DEVELOPER_PAIRS',
                             'capture_files_sha256':digest,
                             'source_inference':False,'live_execution':False,
                             'disclaimer':'The pairing manifest identifies claimed correspondence; file hashes prove byte identity, not source provenance or real-world causality.'}