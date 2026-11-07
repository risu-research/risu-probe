"""Opt-in field-carrier analysis for RISU Probe 0.9.8 analyze --recovery.

Reads saved original HTTP / MCP / consumer observations. Never executes external
code, fetches vendor services or infers hidden runtime state. Source values are
compared in memory but are never copied to exported recovery reports. The main
product's calibrated decisions remain authoritative and unchanged.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

MAX_CASE_BYTES=1_000_000
MAX_BYTES=10_000_000
MAX_TEXT=60_000
MAX_FIELDS=40
MAX_DEPTH=32
MAX_NODES=1500


def bounded(obj):
    todo=[(obj,0)]
    seen=0
    while todo:
        node,depth=todo.pop()
        seen+=1
        if seen>MAX_NODES or depth>MAX_DEPTH:return False
        if isinstance(node,dict):
            if len(node)>MAX_FIELDS:return False
            todo.extend((v,depth+1) for v in node.values())
        elif isinstance(node,list):
            if len(node)>MAX_NODES:return False
            todo.extend((v,depth+1) for v in node)
        elif isinstance(node,str):
            if len(node)>MAX_TEXT:return False
        elif node is None or type(node) in (int,bool):pass
        elif type(node) is float:
            import math
            if not math.isfinite(node):return False
        else:return False
    return True


def reject_dupes(pairs):
    obj={}
    for k,v in pairs:
        if k in obj:raise ValueError('duplicate JSON key')
        obj[k]=v
    return obj

def parse_json(text):
    if not isinstance(text,str) or len(text)>MAX_TEXT:return None
    try:
        value=json.loads(text,object_pairs_hook=reject_dupes,
               parse_constant=lambda x: (_ for _ in ()).throw(ValueError('nonfinite')))
    except (ValueError,TypeError,RecursionError,UnicodeError):return None
    return value if bounded(value) else None

# This parser accepts known JSON-carrier syntax, never arbitrary prose or JSON
# fragments found by substring. A body is certified only after strict value
# equality with a public HTTP sample, including key names and Python types.
UPSTREAM_PREFIX=re.compile(r"^Error calling tool '[A-Za-z_][A-Za-z0-9_]{0,99}': HTTP error ([1-5][0-9][0-9]):  - (\{[^\n]*\})$",re.ASCII)

def text_candidates(text,expected_status):
    ret=[]
    if not isinstance(text,str) or len(text)>MAX_TEXT:return ret
    val=parse_json(text)
    if val is not None:ret.append(('PLAIN_JSON',val))
    matched=UPSTREAM_PREFIX.fullmatch(text)
    if matched and int(matched.group(1))==expected_status:
        val=parse_json(matched.group(2))
        if val is not None:ret.append(('STATUS_PREFIX_JSON',val))
    return ret

def stringify(data):
    return json.dumps(data,sort_keys=True,separators=(',',':'),ensure_ascii=False)

def equal(a,b):
    """Deep JSON equality including primitive types at every nested level.

    Python's built-in dict equality considers True == 1; a typed JSON
    preservation claim must reject that substitution even in nested fields.
    """
    stack=[(a,b)]
    seen=0
    while stack:
        left,right=stack.pop()
        seen+=1
        if seen>MAX_NODES:return False
        if type(left) is not type(right):return False
        if isinstance(left,dict):
            if left.keys()!=right.keys():return False
            stack.extend((v,right[k]) for k,v in left.items())
        elif isinstance(left,list):
            if len(left)!=len(right):return False
            stack.extend(zip(left,right))
        elif left!=right:return False
    return True

def paths(obj):
    if not isinstance(obj,dict):return []
    # Scope intentionally limited to immediate top-level field names. All
    # five frozen cases are flat JSON objects. No PII fields exported.
    if len(obj)>MAX_FIELDS:raise ValueError('field count budget')
    return [k for k in obj if isinstance(k,str) and len(k)<=90 and not k.startswith('_')]

def typed_roots(mcp):
    items=[]
    if isinstance(mcp,dict):
        sc=mcp.get('structuredContent')
        if isinstance(sc,dict):
            items.append(('MCP_STRUCTURED',sc))
            for key in ('data','result'):
                if isinstance(sc.get(key),dict):items.append(('MCP_STRUCTURED_ENVELOPE',sc[key]))
        # Typed embedded resource must declare JSON MIME, not free-form text.
        for part in mcp.get('content',[])[:16]:
            if isinstance(part,dict) and part.get('type')=='resource':
                res=part.get('resource')
                if isinstance(res,dict) and res.get('mimeType') in ('application/json','application/problem+json'):
                    parsed=parse_json(res.get('text'))
                    if isinstance(parsed,dict):items.append(('MCP_TYPED_RESOURCE',parsed))
    return items

def mcp_texts(mcp):
    if not isinstance(mcp,dict):return []
    return [p['text'] for p in mcp.get('content',[])[:16] if isinstance(p,dict)
            and p.get('type')=='text' and isinstance(p.get('text'),str) and len(p['text'])<=MAX_TEXT]

def consumer_roots(observation):
    if not isinstance(observation,dict):return ([],[])
    source=observation.get('consumer') or {}
    roots=[];texts=[]
    # Actual LangChain ToolMessage artifact from pinned original library.
    artifact=source.get('artifact')
    if isinstance(artifact,dict):
        sc=artifact.get('structured_content')
        if isinstance(sc,dict): roots.append(('CONSUMER_ARTIFACT',sc))
    # Actual PydanticAI mapper output from pinned original library.
    mapped=source.get('mapped')
    if isinstance(mapped,dict):roots.append(('CONSUMER_MAPPED',mapped))
    if isinstance(mapped,str):texts.append(mapped)
    content=source.get('content')
    if isinstance(content,str):texts.append(content)
    elif isinstance(content,list):
        texts.extend(p['text'] for p in content[:16] if isinstance(p,dict) and
                     p.get('type')=='text' and isinstance(p.get('text'),str))
    return roots,texts

def fields_at_stage(body,stage_typed,stage_text,status):
    source_fields=paths(body)
    exact_typed=[lbl for lbl,root in stage_typed if equal(root,body)]
    parsed=[]
    for t in stage_text[:16]:parsed.extend(text_candidates(t,status))
    exact_text=[lbl for lbl,root in parsed if equal(root,body)]
    entries=[]
    for key in source_fields:
        val=body[key]
        machine=next((lbl for lbl,root in stage_typed if
                      isinstance(root,dict) and key in root and equal(root[key],val)),None)
        text=next((lbl for lbl,root in parsed if
                   isinstance(root,dict) and key in root and equal(root[key],val)),None)
        if machine:category='TYPED_FIELD'
        elif text:category='PARSED_JSON_TEXT_FIELD'
        elif isinstance(val,str) and len(val)>=8 and any(val in t for t in stage_text):
            category='TEXT_VALUE_MENTION_ONLY'
        elif any(len(t)>MAX_TEXT for t in stage_text):
            category='UNVERIFIED'
        else:category='ABSENT_IN_OBSERVED_CARRIERS'
        # Field names can itself carry identifiers: mirror the product's
        # bounded field-path disclosure policy before export.
        public_key=key
        if len(key)>48 or any(ch in key for ch in ('@','\n','\r','\x00')) or (key.isdigit() and len(key)>=8):
            public_key='[key:'+hashlib.sha256(key.encode('utf-8')).hexdigest()[:12]+']'
        entries.append({'path':'/'+public_key.replace('~','~0').replace('/','~1'),
                        'category':category,'carrier':machine or text or 'NONE_CERTIFIED'})
    return {'full_body':('EXACT_MACHINE' if exact_typed else
                          'EXACT_JSON_TEXT' if exact_text else 'NO_EXACT_OBJECT_CARRIER'),
            'fields':entries}

def assess_cases(cases, baseline):
    if not isinstance(cases,dict) or not isinstance(cases.get('cases'),list):raise ValueError('cases array required')
    if len(cases['cases'])>50:raise ValueError('too many cases')
    if len(cases['cases'])!=len(baseline.get('results',[])):raise ValueError('baseline observation count mismatch')
    out=[]
    for case,old in zip(cases['cases'],baseline['results']):
        if not isinstance(case,dict):raise ValueError('case must be object')
        src=case.get('source');mcp=case.get('mcp')
        observation=case.get('observed_consumer')
        if (not isinstance(src,dict) or not isinstance(mcp,dict) or
            not bounded(src) or not bounded(mcp) or
            (observation is not None and not bounded(observation))):
            raise ValueError('invalid or oversized case')
        ident=case.get('id')
        if (ident!=old.get('id') or case.get('translator','unknown')!=old.get('target') or
            src.get('status')!=old.get('source_http_status') or
            old.get('verdict') not in ('PRESERVED','LOSS','LOSS_AND_INVENTED')):
            raise ValueError('baseline identity/status or verdict mismatch')
        status=src['status'];body=src.get('body')
        if str(src.get('content_type','')).split(';')[0].lower().strip()!='application/json' or not isinstance(body,dict):
            raise ValueError('recovery requires captured JSON object source')
        transport=fields_at_stage(body,typed_roots(mcp),mcp_texts(mcp),status)
        ct,xt=consumer_roots(observation)
        consumer=fields_at_stage(body,ct,xt,status) if observation else None
        flag=('ERROR_FLAG_LOST' if status>=400 and mcp.get('isError') is not True
              else 'SPURIOUS_ERROR_FLAG' if status<400 and mcp.get('isError') is True
              else 'MATCH')
        original_flag=old['evidence_v1'].get('error_flag')
        expected_flag='MATCH' if original_flag=='ERROR_FLAG_MATCH' else original_flag
        if flag!=expected_flag:raise ValueError('baseline error flag and evidence disagree')
        prov=case.get('provenance','UNKNOWN')
        if not isinstance(prov,str) or not re.fullmatch(r'[A-Za-z0-9_.;\-]{1,120}',prov):
            prov='UNVERIFIED_USER_PROVENANCE'
        info={'id':ident,'origin':case['translator'], 'upstream_status':status,
              'provenance':prov,
              'v097_verdict':old['verdict'],'v097_recovery':old['evidence_v1']['body_recovery'],
              'error_flag':flag,'mcp':transport,'consumer':consumer}
        if observation:
            # Diagnostic claims concern actual accessible data. A consumer may
            # expose text but cannot automatically be credited with typed JSON.
            info['consumer_execution_kind_claimed']=observation.get('execution_kind','UNVERIFIED')
            if isinstance(observation.get('consumer'),dict) and observation['consumer'].get('status') in ('success','error'):
                info['consumer_error_classification']=observation['consumer']['status']
        # Nonbinding diagnostic next step. Never present it as a tested patch.
        if flag=='ERROR_FLAG_LOST':
            info['suggested_inspection']='Inspect the generated MCP server error-flag mapping (isError); upstream failure was observed.'
        elif any(v['category']=='PARSED_JSON_TEXT_FIELD' for v in transport['fields']):
            info['suggested_inspection']='The exact JSON is recoverable from verified text; inspect where structuredContent can be retained.'
        elif any(v['category']=='ABSENT_IN_OBSERVED_CARRIERS' for v in transport['fields']):
            info['suggested_inspection']='Inspect the converter response path; source fields were absent from captured MCP carriers.'
        else:
            info['suggested_inspection']='No field-level error-carrier loss observed in this captured case.'
        out.append(info)
    summary={'error_flag_lost':sum(x['error_flag']=='ERROR_FLAG_LOST' for x in out),
             'full_body_exact_machine_mcp':sum(x['mcp']['full_body']=='EXACT_MACHINE' for x in out),
             'full_body_exact_json_text_mcp':sum(x['mcp']['full_body']=='EXACT_JSON_TEXT' for x in out),
             'full_body_no_exact_carrier_mcp':sum(x['mcp']['full_body']=='NO_EXACT_OBJECT_CARRIER' for x in out),
             'consumer_unverified':sum(x['consumer'] is None for x in out)}
    return {'schema' :'risu-p4f-readonly-recovery-lens-v1',
            'version':'0.9.10-experimental-opt-in; calibrated product decisions unchanged',
            'inputs':'previously captured archived external HTTP/MCP/consumer responses; no live execution',
            'case_count':len(out),'summary':summary,'cases':out}

def render(report):
    lines=['Recovery Lens | source -> MCP -> external consumer | captured evidence only']
    for x in report['cases']:
        safe_id=str(x['id']).replace('\n','\\n').replace('\r','\\r')[:120]
        lines.append(f"{safe_id} HTTP{x['upstream_status']} verdict={x['v097_verdict']} flag={x['error_flag']} MCP={x['mcp']['full_body']} CONSUMER={x['consumer']['full_body'] if x['consumer'] else 'UNTESTED'}")
        if x['upstream_status']>=400:
            for f in x['mcp']['fields']:
                name=f['path'];cm=next((y['category'] for y in (x['consumer'] or {}).get('fields',[]) if y['path']==name),'UNTESTED')
                lines.append(f'  {name}: MCP={f["category"]}; consumer={cm}')
            lines.append('  next inspection: '+x['suggested_inspection'])
    lines.append('Scope: recorded carriers only; unknown logs and unobserved executions are outside this finding.')
    return '\n'.join(lines)+'\n'

def _case_rows(payload):
    """Retain captured consumer data while normalizing supported analyze matrices.

    This deliberately mirrors risu_analyze._entries ordering and identities.
    """
    if not isinstance(payload,dict):raise ValueError('saved matrix must be an object')
    rows=[]
    if isinstance(payload.get('cases'),list):
        for r in payload['cases']:
            if not isinstance(r,dict):raise ValueError('saved case is not an object')
            rows.append({'id':str(r['id'])[:120],
                  'translator':str(r.get('translator','unknown'))[:120],
                  'source':r['source'],'mcp':r['mcp'],
                  'provenance':r.get('provenance','CAPTURED_NO_RAW_SOURCE_HASH'),
                  'observed_consumer':r.get('observed_consumer')})
    elif isinstance(payload.get('targets'),list):
        for t in payload['targets']:
            name=str(t.get('target','unknown'))[:120]
            if isinstance(t.get('cases'),list):
                for r in t['cases']:
                    rows.append({'id':str(r['case'])[:120], 'translator':name,
                          'source':r['upstream'],'mcp':r['mcp_wire'],
                          'observed_consumer':r.get('observed_consumer')})
            elif isinstance(t.get('checks'),list):
                for r in t['checks']:
                    rows.append({'id':str(r['check']['id'])[:120], 'translator':name,
                          'source':r['source_sample'],'mcp':r['mcp_sample'],
                          'observed_consumer':r.get('observed_consumer')})
            else:raise ValueError('target must contain cases or checks')
    else:raise ValueError('expected cases or targets')
    return rows


def analyze_saved(payload, baseline):
    """One-call opt-in API: baseline is from risu_analyze.analyze(payload)."""
    rows=_case_rows(payload)
    return assess_cases({'cases':rows},baseline)


def main(argv=None):
    p=argparse.ArgumentParser()
    p.add_argument('saved_pairs',type=Path)
    p.add_argument('baseline',type=Path)
    p.add_argument('--json-out',type=Path)
    p.add_argument('--text-out',type=Path)
    args=p.parse_args(argv)
    for file in (args.saved_pairs,args.baseline):
        if file.stat().st_size>MAX_BYTES:raise ValueError('file too large')
    inp=json.loads(args.saved_pairs.read_text())
    base=json.loads(args.baseline.read_text())
    result=assess_cases(inp,base)
    rendered=render(result)
    print(rendered)
    if args.json_out:args.json_out.write_text(json.dumps(result,indent=2)+'\n')
    if args.text_out:args.text_out.write_text(rendered)

if __name__=='__main__':main()
