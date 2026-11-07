"""Deterministic Consumer Witness: real captured MCP results, two explicit readers.

No LLM, no model claims, no HTTP or subprocess execution, no raw response
contents in reports. Demonstrates whether a *declared consumer contract*
can read the expected typed values from two different MCP data channels.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

from risu_contract import resolve, validate_paths, ContractError
from risu_diagnostics import _strict_same
from risu_evidence import _parse_json, _json_text_candidates, MAX_TEXT_PARTS, MAX_TEXT_CHARS

READERS=('structured-only','json-text-data')
STATUS_KEYS=('observed_http_status','httpStatus','http_status','statusCode','status_code')

def _strict_status(root,expected):
    if not isinstance(root,dict):return False
    observed=[root[k] for k in STATUS_KEYS if k in root and type(root[k]) is int]
    return bool(observed) and all(x==expected for x in observed)

def _json_reader_candidates(mcp):
    """First parseable JSON text, chosen without consulting source values.

    A documented status_code + data wrapper is the only envelope this
    simulated consumer unwraps. No oracle-guided search over responses.
    """
    chunks=mcp.get('content')
    if not isinstance(chunks,list):return
    for chunk in chunks[:MAX_TEXT_PARTS]:
        if not isinstance(chunk,dict) or chunk.get('type')!='text':continue
        txt=chunk.get('text')
        if not isinstance(txt,str) or len(txt)>MAX_TEXT_CHARS:continue
        for _,candidate in _json_text_candidates(txt):
            try:root=_parse_json(candidate)
            except (ValueError,TypeError):continue
            if (isinstance(root,dict) and
                type(root.get('status_code')) is int and
                isinstance(root.get('data'),(dict,list))):
                yield root['data'],root,'json-text:data'
            else:
                yield root,root,'json-text:direct'
            return

def _evaluate(src,mcp,paths,reader,require_error_flag,require_http_status):
    status=src['status']
    body=src['body']
    if reader=='structured-only':
        candidates=([(mcp['structuredContent'],mcp.get('_meta'),'structuredContent')]
                    if 'structuredContent' in mcp else [])
    else:
        candidates=list(_json_reader_candidates(mcp))
    if len(candidates)>MAX_TEXT_PARTS*3+2:
        candidates=candidates[:MAX_TEXT_PARTS*3+2]
    flag_ok=(mcp.get('isError') is True if status>=400 else
             mcp.get('isError') is not True)
    valid=[]
    for payload,root,channel in candidates:
        match=0
        for path in paths:
            _,expected=resolve(body,path)
            found,got=resolve(payload,path)
            if found and _strict_same(expected,got):
                match+=1
        status_ok=(not require_http_status or
                   _strict_status(root,status))
        valid.append((match,channel,status_ok))
    best=max(valid,key=lambda x:(x[0],bool(x[2]))) if valid else (0,'NONE',False)
    success=(best[0]==len(paths) and
             (not require_error_flag or flag_ok) and
             (not require_http_status or best[2]))
    reason=('CONTRACT_SATISFIED' if success else
            'REQUIRED_FIELDS_UNAVAILABLE' if best[0]<len(paths) else
            'ERROR_FLAG_MISMATCH' if require_error_flag and not flag_ok else
            'HTTP_STATUS_UNAVAILABLE')
    return {'outcome':'PASS' if success else 'FAIL',
            'reason':reason,'channel':best[1],
            'required_fields':len(paths),'exact_fields':best[0],
            'error_flag_checked':bool(require_error_flag),
            'error_flag_match':flag_ok if require_error_flag else None,
            'http_status_checked':bool(require_http_status),
            'http_status_match':best[2] if require_http_status else None}

def witness(source:dict,mcp:dict,required_paths:list[str],*,
            require_error_flag:bool=True,require_http_status:bool=False)->dict:
    if not isinstance(source,dict) or not isinstance(mcp,dict):
        raise ValueError('source and MCP response must be objects')
    validate_paths(required_paths)
    status=source.get('status')
    if type(status) is not int or status<100 or status>599:
        raise ValueError('invalid source HTTP status')
    if 'body' not in source:
        raise ValueError('missing source body')
    for path in required_paths:
        found,_=resolve(source['body'],path)
        if not found:raise ValueError('declared path missing from source body')
    readers={r:_evaluate(source,mcp,required_paths,r,require_error_flag,require_http_status)
             for r in READERS}
    return {'schema':'risu-consumer-witness-v1',
            'source_status':status,'required_fields':len(required_paths),
            'models':readers,
            'divergent_outcomes':len({v['outcome'] for v in readers.values()})>1,
            'claim_boundary':'Two deterministic simulated consumer policies on observed MCP data; no LLM behavior inferred'}

def _entries(payload):
    from risu_analyze import _entries as entries
    return entries(payload)

def main(argv=None):
    p=argparse.ArgumentParser(description='Deterministic consumer contract against saved HTTP/MCP pairs, no network')
    p.add_argument('matrix',type=Path)
    p.add_argument('--path',action='append',required=True,
                   help='required RFC 6901 JSON Pointer; repeat for each required field')
    p.add_argument('--require-http-status',action='store_true')
    p.add_argument('--ignore-error-flag',action='store_true')
    p.add_argument('--fail-on-consumer',choices=READERS)
    p.add_argument('--out',type=Path)
    args=p.parse_args(argv)
    try:
        if args.matrix.stat().st_size>10_000_000:raise ValueError('matrix exceeds 10 MiB')
        payload=json.loads(args.matrix.read_text(encoding='utf-8'))
        results=[]
        for target,case_id,src,mcp in _entries(payload):
            proof=witness(src,mcp,args.path,
                          require_error_flag=not args.ignore_error_flag,
                          require_http_status=args.require_http_status)
            results.append({'target':target,'id':case_id,**proof})
        if not 1<=len(results)<=5000:raise ValueError('expected 1-5000 observations')
        report={'tool':'RISU Probe','mode':'consumer-witness','version':'0.9.4-experimental',
                'results':results,
                'summary':{'cases':len(results),'divergent':sum(x['divergent_outcomes'] for x in results)}}
        output=json.dumps(report,ensure_ascii=False,indent=2)+'\n'
        if args.out:
            args.out.parent.mkdir(parents=True,exist_ok=True)
            args.out.write_text(output,encoding='utf-8')
        else:print(output,end='')
        return int(bool(args.fail_on_consumer) and
                   any(x['models'][args.fail_on_consumer]['outcome']!='PASS' for x in results))
    except (OSError,ValueError,KeyError,TypeError,ContractError) as e:
        print('RISU Probe witness: '+str(e),file=sys.stderr)
        return 2

if __name__=='__main__':
    raise SystemExit(main())
