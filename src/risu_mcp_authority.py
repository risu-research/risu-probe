"""P6-B16: catalog-bound authority gate for B15 offline MCP observations.

This module verifies what the SAME captured MCP session actually advertised
before each call. It does not treat human-language descriptions or untrusted
tool annotations as authenticated policy, nor claim upstream provenance.
A server-declared structured outputSchema is normative for structured results.
Existing B15 semantics are untouched and their raw findings remain visible as
quarantined observations when the caller's contract lacks support.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any
from risu_mcp_trace import _read_trace, TraceError
from risu_mcp_observations import (
    ObservationError, validate_contract, validate_witness,
    _check, _load, MAX_CONTRACT, MAX_WITNESS
)

MAX_CATALOG_PAGES = 16
MAX_CATALOG_TOOLS = 512
MAX_MATCHED = 256
MAX_OUTPUT_SCHEMA_NODES = 512
STRICT_SCHEMA_KEYS = frozenset((
    '$ref', '$dynamicRef', '$recursiveRef', 'oneOf', 'anyOf', 'allOf',
    'if', 'then', 'else', 'not', 'patternProperties', 'dependentSchemas',
    'unevaluatedProperties', 'propertiesRef', 'definitions', '$defs'
))


def _sha(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
        separators=(',',':')).encode('utf-8')).hexdigest()


def _request_key(session: str, msg: dict) -> tuple|None:
    if 'id' not in msg:
        return None
    rid = msg['id']
    if type(rid) not in (int, str):
        return None
    return session, type(rid).__name__, rid


def _new_state() -> dict:
    return {'snapshot':None,'building':None,'catalog_requests':{},
            'call_requests':{},'invalid_reason':'NO_COMPLETE_CATALOG'}


def _catalog_rejection(state: dict, reason: str) -> None:
    state['snapshot'] = None
    state['building'] = None
    state['invalid_reason'] = reason


def _descriptor(output: dict) -> tuple[dict | None,str]:
    if type(output) is not dict or type(output.get('name')) is not str:
        return None,'INVALID_TOOL_DESCRIPTOR'
    if not 1 <= len(output['name']) <= 128:
        return None,'INVALID_TOOL_NAME'
    if type(output.get('inputSchema')) is not dict:
        return None,'MISSING_DECLARED_INPUT_SCHEMA'
    return output,''


def _catalog_finish(state: dict, data: Any, requested_cursor: Any,
                    line: int) -> None:
    build=state['building']
    if build is None:
        _catalog_rejection(state,'UNTRACKED_CATALOG_RESPONSE')
        return
    if type(data) is not dict or type(data.get('tools')) is not list:
        _catalog_rejection(state,'MALFORMED_CATALOG_RESULT')
        return
    if requested_cursor != build['expected']:
        _catalog_rejection(state,'BROKEN_CATALOG_CURSOR_CHAIN')
        return
    if build['pages'] >= MAX_CATALOG_PAGES:
        _catalog_rejection(state,'CATALOG_PAGE_BUDGET_EXCEEDED')
        return
    build['pages'] += 1
    for item in data['tools']:
        descriptor,err=_descriptor(item)
        if err:
            _catalog_rejection(state,err)
            return
        name=descriptor['name']
        if name in build['tools'] or len(build['tools']) >= MAX_CATALOG_TOOLS:
            _catalog_rejection(state,'DUPLICATE_OR_EXCESS_TOOL_NAME')
            return
        build['tools'][name]=descriptor
    cursor=data.get('nextCursor')
    if cursor is not None:
        if type(cursor) is not str or not 1<=len(cursor)<=256:
            _catalog_rejection(state,'INVALID_NEXT_CURSOR')
            return
        if cursor in build['seen']:
            _catalog_rejection(state,'CYCLIC_NEXT_CURSOR')
            return
        build['seen'].add(cursor)
        build['expected']=cursor
        return
    tools=build['tools']
    state['snapshot']={'tools':tools,'complete_line':line,
                       'catalog_sha256':_sha(tools),'pages':build['pages']}
    state['invalid_reason']=''
    state['building']=None


def correlate(records: list[tuple[int,str,dict]]) -> tuple[list[dict], list[dict]]:
    """Correlate catalog snapshots with calls. Fail closed for incomplete pages."""
    sessions={}
    matched=[]
    anomalies=[]
    def current(name):
        return sessions.setdefault(name,_new_state())
    for line,session,msg in records:
        st=current(session)
        method=msg.get('method')
        key=_request_key(session,msg)
        if method == 'notifications/tools/list_changed':
            _catalog_rejection(st,'CATALOG_CHANGED_NOTIFICATION')
            st['catalog_requests'].clear()
            continue
        if method == 'tools/list':
            if key is None or key in st['catalog_requests'] or key in st['call_requests']:
                _catalog_rejection(st,'AMBIGUOUS_CATALOG_REQUEST')
                anomalies.append({'line':line,'reason':'AMBIGUOUS_CATALOG_REQUEST'})
                continue
            params=msg.get('params',{})
            if type(params) is not dict:
                _catalog_rejection(st,'INVALID_CATALOG_CURSOR_PARAMS')
                continue
            cursor=params.get('cursor')
            if cursor is None:
                st['snapshot']=None
                st['building']={'tools':{},'pages':0,'expected':None,
                                'seen':set()}
                st['invalid_reason']='CATALOG_IN_PROGRESS'
            elif (type(cursor) is not str or st['building'] is None or
                  st['building']['expected'] != cursor):
                _catalog_rejection(st,'INVALID_CATALOG_CONTINUATION')
                continue
            st['catalog_requests'][key]={'cursor':cursor,'line':line}
            continue
        if method == 'tools/call':
            if key is None or key in st['call_requests'] or key in st['catalog_requests']:
                anomalies.append({'line':line,'reason':'AMBIGUOUS_TOOL_CALL_ID'})
                st['call_requests'].pop(key,None)
                continue
            params=msg.get('params')
            if type(params) is not dict or type(params.get('name')) is not str:
                anomalies.append({'line':line,'reason':'MALFORMED_TOOL_CALL'})
                continue
            # A complete immutable snapshot must exist *before* the tool call.
            snap=st['snapshot'] if st['building'] is None else None
            st['call_requests'][key]={
                'request_line':line,'session':session,
                'name':params['name'],'args':params.get('arguments'),
                'snapshot':snap,'absent_reason':st['invalid_reason'] or
                    'CATALOG_NOT_STABLE'}
            continue
        if method is not None or key is None:
            continue
        if key in st['catalog_requests']:
            req=st['catalog_requests'].pop(key)
            _catalog_finish(st,msg.get('result'),req['cursor'],line)
            continue
        if key in st['call_requests']:
            req=st['call_requests'].pop(key)
            matched.append({**req,'response_line':line,
                            'response':msg.get('result'),
                            'jsonrpc_error':'error' in msg})
    for st in sessions.values():
        for item in st['call_requests'].values():
            anomalies.append({'line':item['request_line'],'reason':'MISSING_TOOL_CALL_RESPONSE'})
        if st['building'] is not None:
            anomalies.append({'reason':'INCOMPLETE_CATALOG_CHAIN'})
    return matched, anomalies


def _is_simple_schema(schema: Any) -> bool:
    if type(schema) is not dict:return False
    count=0
    stack=[(schema,0)]
    while stack:
        v,depth=stack.pop()
        count+=1
        if depth>16 or count>MAX_OUTPUT_SCHEMA_NODES:return False
        if type(v) is dict:
            if set(v)&STRICT_SCHEMA_KEYS:return False
            stack.extend((x,depth+1) for x in v.values())
        elif type(v) is list:
            stack.extend((x,depth+1) for x in v)
    return True


def _schema_implies_required_paths(schema: Any, required: dict) -> tuple[bool,str]:
    if not _is_simple_schema(schema):
        return False,'UNSUPPORTED_COMPLEX_OUTPUT_SCHEMA'
    root_dialect=schema.get('$schema',
       'https://json-schema.org/draft/2020-12/schema')
    if root_dialect not in (
       'https://json-schema.org/draft/2020-12/schema',
       'https://json-schema.org/draft/2020-12/schema#',
       'http://json-schema.org/draft-07/schema#',
       'http://json-schema.org/draft-07/schema',
       'https://json-schema.org/draft-07/schema#',
       'https://json-schema.org/draft-07/schema'):
        return False,'UNSUPPORTED_OUTPUT_SCHEMA_DIALECT'
    for ptr,kind in required.items():
        parts=ptr.split('/')[1:]
        current=schema
        for part in parts:
            if current.get('type')!='object':
                return False,'OUTPUT_PATH_PARENT_NOT_DECLARED_OBJECT'
            props=current.get('properties')
            mandatory=current.get('required')
            if type(props) is not dict or type(mandatory) is not list:
                return False,'OUTPUT_PATH_NOT_MANDATORY'
            if part not in mandatory or part not in props or type(props[part]) is not dict:
                return False,'OUTPUT_FIELD_NOT_DECLARED_REQUIRED'
            current=props[part]
        actual=current.get('type')
        if actual != kind and not (kind=='number' and actual=='integer'):
            return False,'OUTPUT_FIELD_TYPE_NOT_IMPLIED_BY_SCHEMA'
    return True,''


def assess_authority(rule: dict, descriptor: Any) -> tuple[str,str,bool]:
    """Distinct authority tiers: normative structure vs untrusted hint."""
    if descriptor is None:
        return 'UNVERIFIED','TOOL_NOT_IN_COMPLETE_CATALOG',False
    if rule['kind']=='json-object':
        if rule['carrier']!='structured-content':
            return 'UNVERIFIED','TEXT_CARRIER_NOT_STANDARD_OUTPUT_SCHEMA',False
        if 'outputSchema' not in descriptor:
            return 'UNVERIFIED','NO_DECLARED_OUTPUT_SCHEMA',False
        ok,reason=_schema_implies_required_paths(
            descriptor['outputSchema'],rule['required'])
        if ok:
            return 'CATALOG_NORMATIVE','STRUCTURED_OUTPUT_SCHEMA_SUPPORT',True
        return 'UNVERIFIED',reason,False
    ann=descriptor.get('annotations')
    if type(ann) is dict and type(ann.get('readOnlyHint')) is bool:
        hint=ann['readOnlyHint']
        if rule['kind']=='state-unchanged' and hint:
            return 'CATALOG_ADVISORY','UNTRUSTED_READONLY_HINT_SUPPORT',False
        if rule['kind']=='state-changed' and hint:
            return 'CONFLICT','DECLARED_CHANGE_CONTRADICTS_READONLY_HINT',False
    return 'UNVERIFIED','NO_AUTHENTICATED_EFFECT_OBLIGATION',False


def verify(trace:Path, contract:dict, witness:dict|None=None) -> dict:
    rules=validate_contract(contract)
    records,digest=_read_trace(trace)
    witnesses=validate_witness(witness,digest) if witness is not None else {}
    calls,anomalies=correlate(records)
    checks=[]
    seen=set()
    for call in calls:
        for rule in rules:
            if rule['tool']!=call['name']:continue
            args=call['args']
            if type(args) is not dict:
                continue
            if any(k not in args or type(args[k]) is not type(v) or args[k]!=v
                   for k,v in rule['when'].items()):
                continue
            if len(checks)>=MAX_MATCHED:
                raise ObservationError('Too many correlated explicit rule matches')
            key=(call['session'],call['request_line'],call['response_line'])
            wit=witnesses.get(key)
            if wit is not None and wit['tool']!=call['name']:
                status,why='UNVERIFIED','STATE_WITNESS_TOOL_MISMATCH'
            else:
                status,why=_check(rule,call['response'],wit)
            snap=call['snapshot']
            tool=snap['tools'].get(call['name']) if snap else None
            if not snap:
                grade,reason,qualified='UNVERIFIED',call['absent_reason'],False
            else:
                grade,reason,qualified=assess_authority(rule,tool)
            disposition=('QUALIFIED_MISMATCH' if qualified and status=='MISMATCH'
                else 'QUARANTINED_MISMATCH' if status=='MISMATCH'
                else 'QUALIFIED_PASS' if qualified and status=='PASS'
                else 'ADVISORY_PASS' if grade=='CATALOG_ADVISORY' and status=='PASS'
                else 'UNVERIFIED_OBSERVATION' if status=='UNVERIFIED'
                else 'UNQUALIFIED_PASS')
            checks.append({
                'request_line':call['request_line'],
                'response_line':call['response_line'],
                'tool_hash':hashlib.sha256(call['name'].encode()).hexdigest()[:16],
                'rule_hash':hashlib.sha256(rule['id'].encode()).hexdigest()[:12],
                'observed':status,'observed_reason':why,
                'authority_grade':grade,'authority_reason':reason,
                'catalog_sha256':snap['catalog_sha256'] if snap else None,
                'tool_descriptor_sha256':_sha(tool) if tool else None,
                'catalog_completed_line':snap['complete_line'] if snap else None,
                'disposition':disposition})
            seen.add(rule['id'])
    for r in rules:
        if r['id'] not in seen:
            anomalies.append({'reason':'UNMATCHED_DECLARED_RULE',
                  'rule_hash':hashlib.sha256(r['id'].encode()).hexdigest()[:12]})
    for key in witnesses:
        if not any((c['session'],c['request_line'],c['response_line'])==key
                   for c in calls):
            anomalies.append({'line':key[1],'reason':'UNMATCHED_INDEPENDENT_STATE_WITNESS'})
    return {
        'schema':'risu-mcp-catalog-authority-report-v1',
        'trace_sha256':digest,
        'contract_sha256':_sha(contract),
        'origin':'UNATTESTED_LOCAL_JSONRPC_CAPTURE_AND_LOCAL_WITNESSES',
        'summary':{
          'declared_rules':len(rules),
          'matched_obligations':len(checks),
          'observed_mismatches':sum(x['observed']=='MISMATCH' for x in checks),
          'qualified_mismatches':sum(x['disposition']=='QUALIFIED_MISMATCH' for x in checks),
          'quarantined_mismatches':sum(x['disposition']=='QUARANTINED_MISMATCH' for x in checks),
          'qualified_passes':sum(x['disposition']=='QUALIFIED_PASS' for x in checks),
          'advisory_passes':sum(x['disposition']=='ADVISORY_PASS' for x in checks),
          'unverified_observations':sum(x['observed']=='UNVERIFIED' for x in checks),
          'catalog_or_correlation_anomalies':len(anomalies)
        },
        'checks':checks,'unverified':anomalies,
        'claim_limits':'A catalog-bound outputSchema is a normative source declaration only for structured successful results. Tool annotations are untrusted hints and never justify a qualified read-only effect verdict. Missing, partial, outdated or changing catalogs withhold authority. Transcript and state witness provenance remain unverified.',
        'safety':'Offline and bounded; never executes upstream code or prints tool contents.'}


def cli(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser(prog='risu-probe qualify-mcp-observations')
    p.add_argument('trace',type=Path)
    p.add_argument('--contract',type=Path,required=True)
    p.add_argument('--witness',type=Path)
    p.add_argument('--format',choices=('json','text'),default='text')
    p.add_argument('--out',type=Path)
    p.add_argument('--fail-on-qualified',action='store_true')
    p.add_argument('--strict-incomplete',action='store_true')
    a=p.parse_args(argv)
    try:
        report=verify(a.trace,_load(a.contract,MAX_CONTRACT),
                      _load(a.witness,MAX_WITNESS) if a.witness else None)
        s=report['summary']
        body=json.dumps(report,indent=2,sort_keys=True,ensure_ascii=False)+'\n' if a.format=='json' else (
             f"RISU catalog authority | observed={s['observed_mismatches']} "+
             f"qualified={s['qualified_mismatches']} quarantined={s['quarantined_mismatches']} "+
             f"advisory_passes={s['advisory_passes']} anomalies={s['catalog_or_correlation_anomalies']}\n")
        if a.out:
            with a.out.expanduser().absolute().open('x',encoding='utf-8') as f:
                f.write(body)
        else:print(body,end='')
        if a.strict_incomplete and (s['unverified_observations'] or s['catalog_or_correlation_anomalies'] or
             any(x['authority_grade']=='UNVERIFIED' for x in report['checks'])):
            return 2
        return 1 if a.fail_on_qualified and s['qualified_mismatches'] else 0
    except (TraceError,ObservationError,ValueError,UnicodeError,TypeError,OSError,RecursionError) as e:
        print('RMA700 INVALID_OR_UNSUPPORTED_MCP_CATALOG_AUTHORITY: '+type(e).__name__,
              file=sys.stderr)
        return 2

if __name__=='__main__':
    raise SystemExit(cli())
