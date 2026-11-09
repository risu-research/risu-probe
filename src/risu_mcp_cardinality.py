"""Offline opt-in cardinality checks for real recorded MCP tools/call results.

This is a *post-B12-blind* development rule. It is not credited as a first-pass
blind detection, and does not call or execute servers. Only an explicit local
contract permits comparing the tool's integer limit argument to one of three
unambiguous result carriers. Parser refuses uncertain representations.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
from typing import Any
from risu_mcp_trace import _read_trace, TraceError

SCHEMA='risu-mcp-cardinality-contract-v1'
MODES={'json-objects-per-text-block','json-array-text','structured-array'}
MAX_CONTRACT=32_768
MAX_RULES=32
MAX_BLOCKS=128
MAX_SCALAR_TEXT=8192
MAX_LIMIT=1000

class CardinalityContractError(ValueError):
    pass

def _unique(pairs):
    out={}
    for k,v in pairs:
        if k in out:
            raise CardinalityContractError('Duplicate contract/result JSON member')
        out[k]=v
    return out

def validate(doc:Any)->list[dict]:
    if type(doc) is not dict or set(doc)!={'schema','rules'} or doc['schema']!=SCHEMA:
        raise CardinalityContractError('Unsupported explicit cardinality contract')
    rs=doc['rules']
    if type(rs) is not list or not 1<=len(rs)<=MAX_RULES:
        raise CardinalityContractError('Expected 1 to 32 explicit cardinality rules')
    used=set()
    for r in rs:
        if type(r) is not dict or set(r)!={'id','tool','limit_argument','mode'}:
            raise CardinalityContractError('Unexpected or missing cardinality rule fields')
        if (type(r['id']) is not str or
            not re.fullmatch('[a-zA-Z0-9_-]{1,40}',r['id']) or
            r['id'] in used):
            raise CardinalityContractError('Invalid or duplicate cardinality rule ID')
        used.add(r['id'])
        if type(r['tool']) is not str or not 1<=len(r['tool'])<=128:
            raise CardinalityContractError('Invalid explicit tool name')
        if (type(r['limit_argument']) is not str or
            not re.fullmatch('[a-zA-Z][a-zA-Z0-9_]{0,63}',r['limit_argument'])):
            raise CardinalityContractError('Limit must be a declared top-level integer argument')
        if type(r['mode']) is not str or r['mode'] not in MODES:
            raise CardinalityContractError('Unsupported or ambiguous result carrier')
    return rs

def load(path:Path)->dict:
    path=path.expanduser().absolute()
    if path.is_symlink() or not path.is_file() or path.stat().st_size>MAX_CONTRACT:
        raise CardinalityContractError('Contract must be a bounded, regular local file')
    try:
        doc=json.loads(path.read_text('utf-8'),object_pairs_hook=_unique)
    except (ValueError,UnicodeError,RecursionError) as e:
        raise CardinalityContractError('Invalid/duplicate-key cardinality JSON') from e
    validate(doc)
    return doc

def _parse(text:str):
    if len(text)>MAX_SCALAR_TEXT:return None
    try:
        return json.loads(text,object_pairs_hook=_unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite')))
    except (ValueError,RecursionError):
        return None

def _size(result:dict,mode:str)->tuple[int|None,str]:
    if mode=='structured-array':
        value=result.get('structuredContent')
        if type(value) is not list or len(value)>MAX_BLOCKS:
            return None,'STRUCTURED_ARRAY_UNSUPPORTED'
        return len(value),''
    blocks=result.get('content')
    if type(blocks) is not list or not (1<=len(blocks)<=MAX_BLOCKS):
        return None,'CARDINALITY_CONTENT_UNAVAILABLE'
    if any(type(x) is not dict or x.get('type')!='text'
           or type(x.get('text')) is not str for x in blocks):
        return None,'CARDINALITY_NON_TEXT_OR_UNSUPPORTED_BLOCK'
    texts=[x['text'] for x in blocks]
    if mode=='json-array-text':
        if len(texts)!=1:
            return None,'JSON_ARRAY_TEXT_NOT_UNIQUE'
        v=_parse(texts[0])
        if type(v) is not list or len(v)>MAX_BLOCKS:
            return None,'JSON_ARRAY_TEXT_UNSUPPORTED'
        return len(v),''
    # In this mode a block must be an entire JSON object describing one row;
    # no human summaries or other content blocks can be silently discarded.
    for text in texts:
        if type(_parse(text)) is not dict:
            return None,'MIXED_OR_INVALID_PER_ROW_JSON_TEXT'
    return len(texts),''

def check(result:dict, args:dict, rule:dict)->tuple[str,str]:
    if type(args) is not dict:
        return 'UNVERIFIED','TOOL_ARGUMENTS_UNAVAILABLE'
    v=args.get(rule['limit_argument'])
    if type(v) is not int or not 0<=v<=MAX_LIMIT:
        return 'UNVERIFIED','EXPLICIT_INTEGER_LIMIT_UNAVAILABLE'
    if type(result) is not dict:
        return 'UNVERIFIED','TOOL_RESULT_UNAVAILABLE'
    if result.get('isError',False) is not False:
        return 'UNVERIFIED','TOOL_CALL_REPORTED_ERROR'
    n,why=_size(result,rule['mode'])
    if why:return 'UNVERIFIED',why
    assert n is not None
    return ('MISMATCH' if n>v else 'PASS'),''

def verify(trace:Path,contract:dict)->dict:
    rules=validate(contract)
    records,digest=_read_trace(trace)
    pending={}
    matched=checked=passed=0
    findings=[];unverified=[]
    for line,session,msg in records:
        method=msg.get('method')
        rid=msg.get('id')
        key=(session,type(rid).__name__,rid) if rid is not None else None
        if method=='tools/call' and key is not None:
            params=msg.get('params')
            if type(params) is dict and type(params.get('name')) is str:
                if key in pending:
                    unverified.append({'line':line,'reason':'DUPLICATE_PENDING_REQUEST_ID'})
                else:
                    pending[key]=(params['name'],params.get('arguments'),line)
            continue
        if method is not None or key is None or key not in pending:
            continue
        name,arguments,request_line=pending.pop(key)
        for rule in rules:
            if rule['tool']!=name:continue
            matched+=1
            value=msg.get('result')
            status,why=check(value,arguments,rule)
            if status=='UNVERIFIED':
                if len(unverified)<256:
                    unverified.append({'line':line,'reason':why,
                        'rule_hash':hashlib.sha256(rule['id'].encode()).hexdigest()[:12]})
            else:
                checked+=1
                if status=='PASS':passed+=1
                elif len(findings)<256:
                    findings.append({'rule_id':'RMC510',
                        'verdict':'OBSERVED_IN_UNATTESTED_CAPTURE',
                        'message':'Declared maximum returned-item count is exceeded; explicit rule '+hashlib.sha256(rule['id'].encode()).hexdigest()[:12],
                        'tool':'tool_sha256:'+hashlib.sha256(name.encode()).hexdigest()[:16],
                        'line':line})
    for (session,_,rid),(_,__,line) in pending.items():
        if len(unverified)<256:
            unverified.append({'line':line,'reason':'MISSING_TOOL_RESPONSE'})
    return {
        'schema':'risu-mcp-cardinality-evidence-v1',
        'capture_origin':'UNATTESTED_USER_SUPPLIED_LOCAL_BYTES',
        'trace_sha256':digest,
        'summary':{
            'explicit_rules_declared':len(rules),'matched':matched,
            'checked':checked,'passed':passed,'observed_mismatches':len(findings),
            'unverified':len(unverified)},
        'findings':findings,'unverified':unverified,
        'claim_limits':'Only exact caller-declared tool/limit argument and unambiguous JSON array or JSON object-per-text-block carrier are verified. No inference of result shape, output completeness, native source authenticity or global bug prevalence.',
        'safety':'Offline, no subprocess/network, no result or argument values in diagnostic output.'
    }

def cli(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser(prog='risu-probe check-mcp-cardinality')
    p.add_argument('trace',type=Path)
    p.add_argument('--contract',type=Path,required=True)
    p.add_argument('--format',choices=('json','text'),default='text')
    p.add_argument('--out',type=Path)
    p.add_argument('--fail-on-observed',action='store_true')
    p.add_argument('--strict-incomplete',action='store_true')
    a=p.parse_args(argv)
    try:
        report=verify(a.trace,load(a.contract))
        output=json.dumps(report,ensure_ascii=False,sort_keys=True,indent=2) if a.format=='json' else (
            'RISU MCP cardinality | matched='+str(report['summary']['matched'])+
            ' checked='+str(report['summary']['checked'])+
            ' mismatches='+str(report['summary']['observed_mismatches'])+
            ' unverified='+str(report['summary']['unverified'])+'\n')
        if a.out:
            target=a.out.expanduser().absolute()
            with target.open('x',encoding='utf-8') as f:f.write(output+'\n')
        else:
            print(output)
        if a.strict_incomplete and report['summary']['unverified']:
            return 2
        return 1 if a.fail_on_observed and report['summary']['observed_mismatches'] else 0
    except (TraceError,CardinalityContractError,OSError) as e:
        print('Cardinality assessment unavailable: '+type(e).__name__,file=__import__('sys').stderr)
        return 2

if __name__=='__main__':
    raise SystemExit(cli())
