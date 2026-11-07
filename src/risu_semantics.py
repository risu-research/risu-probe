"""Opt-in, bounded and conservative semantic mapping of observed HTTP/MCP fields.

This module verifies value equivalence and a tightly specified lookup
transition under an *operator-declared* contract. It proves neither the
contract's legal/domain correctness, source exhaustiveness, independent
causality, nor full semantic preservation. It can NEVER promote P4-J
CONFIRMED_LOSS or declare that all source information survived.

No network, code execution, imports of the tested application, mapping
expressions, arbitrary transform functions or attacker-provided globbing.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from risu_capture import _jsonfile, _jsonl, _read, _id, bounded, loads

SCHEMA='risu-observed-semantic-mapping-v1'
OUTPUT='risu-observed-semantic-mapping-results-v1'
IDENT=re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z',re.ASCII)
ARG=re.compile(r'[A-Za-z0-9_][A-Za-z0-9_]{0,79}\Z',re.ASCII)
URL_ID=re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,79}\Z',re.ASCII)
INDEX=re.compile(r'(0|[1-9][0-9]{0,7})\Z',re.ASCII)
VALID_RULES={'equal_paths','lookup_transition'}
MAX_FILE=300_000


def _read_contract(path):
    path=Path(path)
    if path.is_symlink() or not path.is_file() or not 0<path.stat().st_size<=MAX_FILE:
        raise ValueError('semantic mapping must be a regular nonsymlink JSON file <= 300 KB')
    try: value=loads(_read(path).decode('utf-8'))
    except (UnicodeError,RecursionError) as exc:raise ValueError('invalid semantic map encoding') from exc
    if not isinstance(value,dict) or set(value)!={'schema','cases'} or value['schema']!=SCHEMA:
        raise ValueError('semantic mapping schema v1 must have exactly schema and cases')
    return value,hashlib.sha256(_read(path)).hexdigest()


def _pointer(value,path):
    """Read RFC6901 pointer; reject ambiguous or malformed pointer segments."""
    if not isinstance(path,str) or not 1<=len(path)<=280 or not path.startswith('/'):
        raise ValueError('invalid semantic mapping JSON pointer')
    raw=path[1:].split('/')
    if not 1<=len(raw)<=18:
        raise ValueError('semantic mapping pointer depth limit exceeded')
    obj=value
    for seg in raw:
        if not seg or re.search(r'~(?![01])',seg):
            raise ValueError('ambiguous semantic mapping JSON pointer')
        token=seg.replace('~1','/').replace('~0','~')
        if len(token)>80:raise ValueError('semantic mapping pointer segment too long')
        if isinstance(obj,dict):
            if token not in obj:return False,None
            obj=obj[token]
        elif isinstance(obj,list):
            if not INDEX.fullmatch(token):return False,None
            i=int(token)
            if i>=len(obj):return False,None
            obj=obj[i]
        else:return False,None
    return True,obj


def _equals(left,right):
    """Strict recursive JSON equality; never conflate True and 1."""
    stack=[(left,right,0)]
    visited=0
    while stack:
        l,r,depth=stack.pop();visited+=1
        if visited>20000 or depth>64 or type(l) is not type(r):return False
        if isinstance(l,dict):
            if l.keys()!=r.keys():return False
            stack.extend((l[k],r[k],depth+1) for k in l)
        elif isinstance(l,list):
            if len(l)!=len(r):return False
            stack.extend((a,b,depth+1) for a,b in zip(l,r))
        elif l!=r:return False
    return True


def _rule_keys(rule):
    kind=rule.get('kind')
    if kind=='equal_paths':return {'id','kind','source_path','target_path'}
    if kind=='lookup_transition':
        return {'id','kind','status_path','source_data_path','expected_status',
                'outcome','argument','source_id_path','target_id_path',
                'target_items_path','target_not_found_path'} if rule.get('outcome')=='found' else {
                'id','kind','status_path','source_data_path','expected_status',
                'outcome','argument','target_items_path','target_not_found_path'}
    raise ValueError('unsupported semantic mapping rule kind')


def _check_spec(value):
    cases=value['cases']
    if not isinstance(cases,list) or not 1<=len(cases)<=50:raise ValueError('semantic mapping requires 1-50 cases')
    ids=set();count=0
    for c in cases:
        if not isinstance(c,dict) or set(c)!={'case_id','rules'}:
            raise ValueError('semantic mapping case requires only case_id and rules')
        ident=c['case_id']
        if not isinstance(ident,str) or not IDENT.fullmatch(ident) or ident in ids:
            raise ValueError('semantic mapping case identity invalid or duplicated')
        ids.add(ident)
        rules=c['rules']
        if not isinstance(rules,list) or not 1<=len(rules)<=30:
            raise ValueError('semantic mapping case requires 1-30 rules')
        check_ids=set()
        for item in rules:
            if not isinstance(item,dict) or set(item)!=_rule_keys(item):
                raise ValueError('semantic mapping rule has unsupported/missing keys')
            rid=item['id']
            if not isinstance(rid,str) or not IDENT.fullmatch(rid) or rid in check_ids:
                raise ValueError('semantic mapping check ID invalid or duplicated')
            check_ids.add(rid)
            if item['kind']=='equal_paths':
                for k in ('source_path','target_path'):_pointer({},item[k])
            else:
                for k in ('status_path','source_data_path','target_items_path','target_not_found_path'):
                    _pointer({},item[k])
                if item['outcome']=='found':
                    for k in ('source_id_path','target_id_path'):_pointer({},item[k])
                if item['outcome'] not in ('found','not_found'):
                    raise ValueError('semantic mapping lookup outcome invalid')
                if not isinstance(item['expected_status'],str) or not re.fullmatch('[0-9]{1,4}',item['expected_status']):
                    raise ValueError('lookup requires an exact application status string')
                if not isinstance(item['argument'],str) or not ARG.fullmatch(item['argument']):
                    raise ValueError('lookup requires valid named MCP argument')
            count+=1
    if count>120:raise ValueError('semantic mapping aggregate rule limit exceeded')


def _native_metadata(directory):
    har=_jsonfile(directory,'capture.har')
    pairs=_jsonfile(directory,'pairs.json')
    frames=_jsonl(directory,'mcp.jsonl')
    requests={}
    for frame in frames:
        if frame.get('method')!='tools/call':continue
        ident=_id(frame.get('id'))
        if ident in requests:raise ValueError('duplicate MCP tools/call identity in semantic evidence')
        requests[ident]=frame.get('params')
    mapping={}
    for p in pairs.get('pairs',[]):
        ident=p['case_id']
        if ident in mapping:raise ValueError('duplicated native semantic pairing')
        rid=_id(p['mcp_call_id'])
        if rid not in requests or not isinstance(requests[rid],dict):
            raise ValueError('semantic mapping missing original MCP tool call')
        req=requests[rid]
        if req.get('name')!=p['tool'] or not isinstance(req.get('arguments'),dict):
            raise ValueError('semantic mapping tool/arguments disagree with actual wire')
        http=har['log']['entries'][p['http_entry']]['request']
        if http.get('method')!='GET':raise ValueError('semantic mapping requires recorded HTTP GET')
        url=http.get('url')
        if not isinstance(url,str):raise ValueError('missing original HTTP request URL')
        parts=urlsplit(url)
        if parts.scheme not in ('http','https') or not parts.netloc or parts.username or parts.password or parts.fragment:
            raise ValueError('untrusted original HTTP URL in semantic mapping')
        mapping[ident]={'request_arguments':req['arguments'], 'original_http_path':parts.path,'tool':req['name']}
    return mapping


def _equal(rule,source,mcp):
    present,actual=_pointer(source,rule['source_path'])
    if not present:return 'INSUFFICIENT','UNOBSERVED_SOURCE_PATH'
    present,target=_pointer(mcp,rule['target_path'])
    if not present:return 'CONTRADICTED','DECLARED_TARGET_PATH_MISSING'
    if not _equals(actual,target):return 'CONTRADICTED','EXACT_VALUE_OR_TYPE_MISMATCH'
    return 'OBSERVED_MATCH','EXACT_VALUE_AND_JSON_TYPE'


def _lookup(rule,source,mcp,context):
    # Domain mapping was explicitly asserted by caller. This validates a
    # concrete observable correspondence, never proves the asserted status
    # meaning for other APIs or that the source body is fully preserved.
    argument=context['request_arguments'].get(rule['argument'])
    if not isinstance(argument,str) or not URL_ID.fullmatch(argument):
        return 'INSUFFICIENT','MISSING_OR_INVALID_ORIGINAL_MCP_ARGUMENT'
    urlpath=context['original_http_path']
    if not urlpath.endswith('/'+argument):
        return 'CONTRADICTED','HTTP_PATH_DIFFERS_FROM_MCP_ARGUMENT'
    if type(source.get('status')) is not int or source['status']!=200:
        return 'CONTRADICTED','LOOKUP_REQUIRES_HTTP_200'
    if mcp.get('isError') is not False:
        return 'CONTRADICTED','LOOKUP_REQUIRES_EXPLICIT_MCP_ISERROR_FALSE'
    if not isinstance(mcp.get('structuredContent'),dict):
        return 'CONTRADICTED','LOOKUP_REQUIRES_STRUCTURED_MCP_OUTPUT'
    body=source.get('body')
    if not isinstance(body,dict):return 'INSUFFICIENT','MISSING_UPSTREAM_JSON'
    status_present,status=_pointer(body,rule['status_path'])
    if not status_present:return 'INSUFFICIENT','SOURCE_APPLICATION_STATUS_MISSING'
    if type(status) is not str or status!=rule['expected_status']:
        return 'CONTRADICTED','APPLICATION_STATUS_NOT_DECLARED_EXPECTATION'
    data_present,data=_pointer(body,rule['source_data_path'])
    if not data_present:return 'INSUFFICIENT','SOURCE_APPLICATION_DATA_MISSING'
    output=mcp['structuredContent']
    p1,items=_pointer(output,rule['target_items_path'])
    p2,missing=_pointer(output,rule['target_not_found_path'])
    if not (p1 and p2):return 'CONTRADICTED','MCP_LOOKUP_FIELDS_MISSING'
    if not isinstance(items,list) or not isinstance(missing,list):
        return 'CONTRADICTED','MCP_LOOKUP_FIELDS_WRONG_TYPES'
    if rule['outcome']=='found':
        if not isinstance(data,dict) or not data or len(items)!=1 or missing!=[]:
            return 'CONTRADICTED','FOUND_LOOKUP_SHAPE_CONTRADICTION'
        sf,source_id=_pointer(body,rule['source_id_path'])
        tf,target_id=_pointer(output,rule['target_id_path'])
        if not sf or not tf:return 'CONTRADICTED','FOUND_LOOKUP_IDENTIFIER_UNOBSERVED'
        if not (type(source_id) is str and type(target_id) is str and source_id==argument==target_id):
            return 'CONTRADICTED','FOUND_LOOKUP_IDENTIFIER_MISMATCH'
        return 'OBSERVED_MATCH','DECLARED_FOUND_LOOKUP_TRANSITION_VALIDATED'
    if not _equals(data,{}) or items!=[] or missing!=[argument]:
        return 'CONTRADICTED','NOT_FOUND_LOOKUP_SHAPE_CONTRADICTION'
    return 'OBSERVED_MATCH','DECLARED_NO_DATA_LOOKUP_TRANSITION_VALIDATED'


def assess(payload,report,capture_directory,mapping_path):
    if capture_directory is None:
        raise ValueError('--semantic-map requires an original HAR/MCP native capture directory')
    if not isinstance(payload,dict) or not isinstance(payload.get('cases'),list):
        raise ValueError('semantic mapping requires captured HTTP/MCP cases')
    resolved_capture=Path(capture_directory).resolve()
    resolved_mapping=Path(mapping_path).resolve()
    try:
        resolved_mapping.relative_to(resolved_capture)
    except ValueError:
        pass
    else:
        raise ValueError('operator semantic mapping must be chosen outside untrusted capture directory')
    contract,contract_hash=_read_contract(mapping_path)
    _check_spec(contract)
    by_case={x['id']:x for x in payload['cases']}
    if len(by_case)!=len(payload['cases']):raise ValueError('duplicate capture cases')
    mapping=_native_metadata(capture_directory)
    declared={c['case_id']:c for c in contract['cases']}
    if not set(declared).issubset(by_case):raise ValueError('semantic mapping references uncaptured case')
    rows=[]
    totals={x:0 for x in ('OBSERVED_MATCH','CONTRADICTED','INSUFFICIENT')}
    case_counts={x:0 for x in ('ALL_DECLARED_CHECKS_MATCH','DECLARED_MAPPING_CONTRADICTED','DECLARED_MAPPING_INSUFFICIENT','NOT_ASSESSED')}
    for case in payload['cases']:
        key=case['id']
        if key not in declared:
            rows.append({'case_id':key,'outcome':'NOT_ASSESSED','checks':[],'coverage':'NO_MAPPING_DECLARED'})
            case_counts['NOT_ASSESSED']+=1
            continue
        context=mapping[key]
        body=case['source'].get('body')
        if not isinstance(body,dict) or not bounded(body):
            raise ValueError('semantic mapping source must be bounded JSON object')
        mcp=case['mcp']
        if not isinstance(mcp,dict) or not bounded(mcp):
            raise ValueError('semantic mapping target must be bounded MCP result')
        checks=[]
        for rule in declared[key]['rules']:
            if rule['kind']=='equal_paths':
                if not isinstance(mcp.get('structuredContent'),dict):
                    status,reason='INSUFFICIENT','NO_MACHINE_STRUCTURED_OUTPUT'
                else:status,reason=_equal(rule,body,mcp['structuredContent'])
            else:
                status,reason=_lookup(rule,case['source'],mcp,context)
            totals[status]+=1
            checks.append({'id':rule['id'],'kind':rule['kind'],'outcome':status,'reason':reason})
        if any(x['outcome']=='CONTRADICTED' for x in checks):state='DECLARED_MAPPING_CONTRADICTED'
        elif any(x['outcome']=='INSUFFICIENT' for x in checks):state='DECLARED_MAPPING_INSUFFICIENT'
        else:state='ALL_DECLARED_CHECKS_MATCH'
        # IMPORTANT: independently preserve any upstream HTTP error flag
        # mismatch regardless of developer mapping claims; cannot whitewash it.
        if case['source'].get('status',0)>=400 and mcp.get('isError') is not True:
            state='DECLARED_MAPPING_CONTRADICTED'
            checks.append({'id':'BUILTIN_HTTP_ERROR_FLAG','kind':'non_overridable_safety_gate',
                           'outcome':'CONTRADICTED','reason':'UPSTREAM_HTTP_ERROR_NOT_MARKED_MCP_ERROR'})
            totals['CONTRADICTED']+=1
        case_counts[state]+=1
        rows.append({'case_id':key,'outcome':state,'checks':checks,
                     'coverage':'ONLY_DECLARED_RULES_SCOPED_NOT_FULL_SOURCE_FIELDS',
                     'underlying_causal_outcome':next((x['causal_v1']['outcome'] for x in report['results'] if x['id']==key),'UNKNOWN')})
    return {'schema':OUTPUT,'contract_sha256':contract_hash,'mapping_authority':'OPERATOR_DECLARED_NOT_INDEPENDENT_DOMAIN_PROOF',
            'comparison_scope':'EXPLICIT_OBSERVED_VALUE_CORRESPONDENCES_ONLY',
            'does_not_prove':['full information survival','undeclared source fields','domain rule correctness','independent HTTP-to-MCP causality','vendor production behavior'],
            'rules_summary':totals,'cases_summary':case_counts,'cases':rows,
            'unmodified_p4j_causal_gate':True,'all_passing_is_not_full_semantic_preservation':True}


def render(result):
    lines=['Observed Semantic Mapping Lens | operator-declared mappings, bounded observed values']
    for case in result['cases']:
        lines.append(f"{case['case_id']}: {case['outcome']} | checked={len(case['checks'])}")
        for r in case['checks']:
            lines.append(f"  {r['id']}: {r['outcome']} ({r['reason']})")
    lines.append('Rule outcomes: '+str(result['rules_summary']))
    lines.append('Only listed fields/lookup transitions were checked. P4-J causal and legacy verdicts unchanged.')
    return '\n'.join(lines)+'\n'
