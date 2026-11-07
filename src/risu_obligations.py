"""P4-S: distinguish observed MCP output-schema duties from operator-selected rules.

No inference of legal contract, third-party fault, real-world causality, or
independent importance. Publisher/server output requirements are admitted only
from a matching, actually observed native MCP tools/list outputSchema frame.
Source fields are judged through the pre-existing P4-R residual evidence gate.
Neither rule kind can rewrite a legacy verdict, semantic coverage or P4-J gate.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

from risu_capture import _read, loads, _jsonl, _jsonfile, _id
from risu_semantics import _pointer

SCHEMA='risu-explicit-field-obligation-policy-v1'
RESULT_SCHEMA='risu-observed-field-obligation-assessment-v1'
MAX_POLICY=100_000
IDENT=re.compile(r'[A-Za-z][A-Za-z0-9_-]{0,79}\Z',re.ASCII)
LEVELS={'CRITICAL','HIGH','MEDIUM','LOW'}
KINDS={'OPERATOR_POLICY','RECORDED_MCP_OUTPUT_SCHEMA'}
CONDITIONS={'ALWAYS','SOURCE_NONEMPTY'}


def _policy(path,capture):
    p=Path(path)
    if p.is_symlink() or not p.is_file() or not 0<p.stat().st_size<=MAX_POLICY:
        raise ValueError('obligation policy must be a regular, non-symlink JSON file <=100 KB')
    cp=Path(capture).resolve()
    if p.resolve()==cp or cp in p.resolve().parents:
        raise ValueError('obligation policy must be selected outside capture directory')
    raw=_read(p);data=loads(raw.decode('utf-8'))
    if not isinstance(data,dict) or set(data)!={'schema','policy_id','issuer','cases'} or data['schema']!=SCHEMA:
        raise ValueError('unrecognized obligation policy schema')
    if not isinstance(data['policy_id'],str) or not IDENT.fullmatch(data['policy_id']):
        raise ValueError('unsafe obligation policy id')
    issuer=data['issuer']
    if not isinstance(issuer,dict) or set(issuer)!={'name','kind'} or issuer['kind']!='OPERATOR' or not isinstance(issuer['name'],str) or not 3<=len(issuer['name'])<=100:
        raise ValueError('issuer is an operator assertion and must say so')
    cases=data['cases'];ids=set();total=0
    if not isinstance(cases,list) or not 1<=len(cases)<=50:raise ValueError('1-50 policy cases required')
    for case in cases:
        if not isinstance(case,dict) or set(case)!={'case_id','tool','obligations'}:
            raise ValueError('invalid policy case object')
        ident=case['case_id'];tool=case['tool']
        if not isinstance(ident,str) or not IDENT.fullmatch(ident) or ident in ids:
            raise ValueError('missing, invalid or repeated policy case identity')
        if not isinstance(tool,str) or not IDENT.fullmatch(tool):
            raise ValueError('invalid tool identity')
        ids.add(ident)
        obligations=case['obligations'];ruleids=set();subjects=set()
        if not isinstance(obligations,list) or not 1<=len(obligations)<=40:
            raise ValueError('1-40 obligations required per case')
        for o in obligations:
            if not isinstance(o,dict):raise ValueError('invalid obligation entry')
            basis=o.get('basis')
            common={'id','basis','importance','importance_reason'}
            fields=(common|{'source_path','residual_rule_id','when','allow_normalized'}
                    if basis=='OPERATOR_POLICY' else common|{'target_path'})
            if set(o)!=fields or basis not in KINDS:
                raise ValueError('unsupported or incomplete obligation fields')
            rid=o['id']
            if not isinstance(rid,str) or not IDENT.fullmatch(rid) or rid in ruleids:
                raise ValueError('duplicate or unsafe obligation identity')
            ruleids.add(rid)
            if o['importance'] not in LEVELS:
                raise ValueError('importance must be a bounded operator label')
            reason=o['importance_reason']
            if not isinstance(reason,str) or not 24<=len(reason)<=400 or any(ord(c)<32 and c not in '\t' for c in reason):
                raise ValueError('importance requires a concrete 24-400 character rationale')
            if basis=='OPERATOR_POLICY':
                src=o['source_path'];_pointer({},src)
                if not src.startswith('/result/'):
                    raise ValueError('operator source field must be an explicit source result pointer')
                if src in subjects:raise ValueError('duplicate obligations for source field')
                subjects.add(src)
                if o['when'] not in CONDITIONS or type(o['allow_normalized']) is not bool:
                    raise ValueError('operator condition or normalized acceptance invalid')
                if not isinstance(o['residual_rule_id'],str) or not IDENT.fullmatch(o['residual_rule_id']):
                    raise ValueError('operator requires exact P4-R rule identity')
            else:
                dest=o['target_path'];_pointer({},dest)
                if not dest.startswith('/') or dest=='/' or dest in subjects:
                    raise ValueError('invalid or repeated output-schema field pointer')
                subjects.add(dest)
                # Output-schema requiredness is only verified on ordinary JSON
                # object property chains, never array positions or wildcards.
                parts=dest.split('/')[1:]
                if not all(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',x,re.ASCII) for x in parts):
                    raise ValueError('output schema property chain must be plain names')
            total+=1
    if total>150:raise ValueError('policy too large')
    return data,hashlib.sha256(raw).hexdigest()


def _observed_server_schemas(directory):
    """Require an actual matching tools/list request and response on native wire."""
    frames=_jsonl(Path(directory),'mcp.jsonl')
    requests=[f for f in frames if f.get('method')=='tools/list']
    if not requests:return None,'MCP_TOOLS_LIST_NOT_CAPTURED'
    if len(requests)!=1:return None,'AMBIGUOUS_TOOLS_LIST_REQUEST'
    call=requests[0];req_id=call.get('id')
    if type(req_id) not in (str,int) or isinstance(req_id,str) and not req_id:
        return None,'INVALID_TOOL_LIST_REQUEST_ID'
    results=[x for x in frames if x.get('id')==req_id and 'result' in x]
    if len(results)!=1:return None,'TOOLS_LIST_REPLY_NOT_UNIQUELY_OBSERVED'
    result=results[0].get('result')
    if not isinstance(result,dict) or not isinstance(result.get('tools'),list):
        return None,'MALFORMED_TOOLS_LIST_RESULT'
    schemas={}
    for tool in result['tools']:
        if not isinstance(tool,dict) or not isinstance(tool.get('name'),str):
            return None,'MALFORMED_TOOL_DESCRIPTOR'
        name=tool['name']
        if name in schemas:return None,'DUPLICATED_TOOL_DESCRIPTOR'
        schema=tool.get('outputSchema')
        if schema is None:
            schemas[name]=None
        elif isinstance(schema,dict):
            schemas[name]=schema
        else:
            return None,'INVALID_OUTPUT_SCHEMA'
    return schemas,'RECORDED_TOOLS_LIST_OUTPUT_SCHEMA'


def _required_property(schema,pointer):
    """Return (required_by_observed_schema, type declaration, reason).

    A field is required only if EVERY edge is in its container's required
    list. 'present in properties' is not itself an obligation.
    """
    current=schema
    for token in pointer.split('/')[1:]:
        if not isinstance(current,dict) or current.get('type')!='object':
            return False,None,'PARENT_NOT_A_PLAIN_OBJECT_SCHEMA'
        required=current.get('required',[]);props=current.get('properties',{})
        if not isinstance(required,list) or len(required)!=len(set(map(str,required))) or not isinstance(props,dict):
            return False,None,'MALFORMED_REQUIRED_OR_PROPERTIES'
        if token not in required:
            return False,None,'NOT_IN_OBSERVED_SCHEMA_REQUIRED_LIST'
        if token not in props or not isinstance(props[token],dict):
            return False,None,'REQUIRED_PROPERTY_SCHEMA_NOT_OBSERVED'
        current=props[token]
    return True,current.get('type'),'REQUIRED_BY_RECORDED_MCP_OUTPUT_SCHEMA'


def _compatible(value,schema_type):
    if schema_type=='string':return type(value) is str
    if schema_type=='number':return type(value) in (int,float)
    if schema_type=='integer':return type(value) is int
    if schema_type=='boolean':return type(value) is bool
    if schema_type=='array':return type(value) is list
    if schema_type=='object':return type(value) is dict
    if schema_type=='null':return value is None
    # Unsupported/union schema types cannot be used to certify type safety.
    return None


def assess_obligations(payload,residual,policy_path,capture):
    if not Path(capture).is_dir() or not isinstance(payload,dict) or not isinstance(payload.get('cases'),list):
        raise ValueError('original native paired capture required for duty assessment')
    if residual.get('schema')!='risu-original-field-disposition-results-v1':
        raise ValueError('P4-R source-field disposition required')
    policy,policy_sha=_policy(policy_path,capture)
    actual={c['id']:c for c in payload['cases']}
    evidence={c['case_id']:c for c in residual['cases']}
    if len(actual)!=len(payload['cases']) or len(evidence)!=len(residual['cases']):
        raise ValueError('duplicated capture/residual case')
    tool_schemas,schema_origin=_observed_server_schemas(capture)
    pairs=_jsonfile(Path(capture),'pairs.json').get('pairs')
    if not isinstance(pairs,list) or len({x.get('case_id') for x in pairs if isinstance(x,dict)})!=len(pairs):
        raise ValueError('ambiguous original MCP call-pair identities')
    calls={}
    for frame in _jsonl(Path(capture),'mcp.jsonl'):
        if frame.get('method')=='tools/call':
            key=_id(frame.get('id'))
            if key in calls:raise ValueError('duplicated native tools/call request')
            calls[key]=frame.get('params',{}).get('name')
    native_tool={}
    for pair in pairs:
        key=_id(pair.get('mcp_call_id'))
        if pair.get('tool')!=calls.get(key):
            raise ValueError('native tool request does not match explicit pair')
        native_tool[pair['case_id']]=pair['tool']
    out=[];tot={k:0 for k in ('OPERATOR_POLICY_UNSATISFIED_OBSERVED','OPERATOR_POLICY_SATISFIED','OPERATOR_POLICY_SATISFIED_NORMALIZED',
        'NOT_APPLICABLE_TO_OBSERVED_SOURCE','UNASSESSED_OPERATOR_REQUIREMENT','SERVER_SCHEMA_REQUIREMENT_SATISFIED',
        'SERVER_SCHEMA_REQUIRED_FIELD_MISSING','SERVER_SCHEMA_REQUIRED_FIELD_WRONG_TYPE','NO_OBSERVED_SERVER_SCHEMA_REQUIREMENT','SERVER_SCHEMA_EVIDENCE_UNAVAILABLE')}
    priority={x:0 for x in ('CRITICAL','HIGH','MEDIUM','LOW')}
    for case in policy['cases']:
        ident=case['case_id']
        if ident not in actual or ident not in evidence:
            raise ValueError('declared policy case not found in the original native capture and residual report')
        captured=actual[ident]
        if native_tool.get(ident)!=case['tool']:
            raise ValueError('obligation tool identity differs from actual native tools/call')
        body=captured['source']['body'];mcp=captured['mcp']
        observed_fields={r['source_path']:r for r in evidence[ident]['rules']}
        scored=[]
        for o in case['obligations']:
            basis=o['basis'];why=''; status=''
            if basis=='OPERATOR_POLICY':
                exists,value=_pointer(body,o['source_path'])
                if not exists:
                    status='UNASSESSED_OPERATOR_REQUIREMENT';why='ORIGINAL_SOURCE_FIELD_NOT_OBSERVED'
                elif o['when']=='SOURCE_NONEMPTY' and (value is None or value=='' or value==[] or value=={}):
                    status='NOT_APPLICABLE_TO_OBSERVED_SOURCE';why='DECLARED_CONDITION_SOURCE_NONEMPTY_FALSE'
                else:
                    match=observed_fields.get(o['source_path'])
                    if match is None or match['id']!=o['residual_rule_id']:
                        status='UNASSESSED_OPERATOR_REQUIREMENT';why='EXACT_P4R_FIELD_DISPOSITION_NOT_AVAILABLE'
                    elif match['outcome']=='OBSERVED_NONEXPOSURE':
                        status='OPERATOR_POLICY_UNSATISFIED_OBSERVED';why='EXPLICIT_OPERATOR_DUTY_WITH_OBSERVED_FIELD_NONEXPOSURE'
                    elif match['outcome']=='VERIFIED_EXACT_REMAP':
                        status='OPERATOR_POLICY_SATISFIED';why='P4R_TYPED_SOURCE_VALUE_MATCHES_DECLARED_MCP_FIELD'
                    elif match['outcome']=='VERIFIED_EMPTY_STRUCTURAL_EXPANSION':
                        if o['allow_normalized']:
                            status='OPERATOR_POLICY_SATISFIED_NORMALIZED';why='P4R_VERIFIED_DECLARED_EMPTY_OBJECT_NORMALIZATION'
                        else:
                            status='UNASSESSED_OPERATOR_REQUIREMENT';why='STRICT_ORIGINAL_OBJECT_EXPOSURE_NOT_PROVED'
                    else:
                        status='UNASSESSED_OPERATOR_REQUIREMENT';why='RESIDUAL_CONTRADICTED_OR_INSUFFICIENT'
            else:
                if tool_schemas is None or case['tool'] not in tool_schemas or tool_schemas[case['tool']] is None:
                    status='SERVER_SCHEMA_EVIDENCE_UNAVAILABLE';why=schema_origin if tool_schemas is None else 'MATCHING_TOOL_OUTPUT_SCHEMA_MISSING'
                else:
                    required,typ,reason=_required_property(tool_schemas[case['tool']],o['target_path'])
                    if not required:
                        if reason in ('MALFORMED_REQUIRED_OR_PROPERTIES','REQUIRED_PROPERTY_SCHEMA_NOT_OBSERVED'):
                            status='SERVER_SCHEMA_EVIDENCE_UNAVAILABLE'
                        else:
                            status='NO_OBSERVED_SERVER_SCHEMA_REQUIREMENT'
                        why=reason
                    elif not isinstance(mcp.get('structuredContent'),dict):
                        status='SERVER_SCHEMA_EVIDENCE_UNAVAILABLE';why='STRUCTURED_MCP_RESULT_NOT_OBSERVED'
                    else:
                        exists,val=_pointer(mcp['structuredContent'],o['target_path'])
                        if not exists:
                            status='SERVER_SCHEMA_REQUIRED_FIELD_MISSING';why='REQUIRED_FIELD_MISSING_FROM_STRUCTURED_MCP_RESULT'
                        elif _compatible(val,typ) is False:
                            status='SERVER_SCHEMA_REQUIRED_FIELD_WRONG_TYPE';why='REQUIRED_FIELD_WRONG_JSON_TYPE'
                        elif _compatible(val,typ) is None:
                            status='SERVER_SCHEMA_EVIDENCE_UNAVAILABLE';why='UNSUPPORTED_REQUIRED_FIELD_TYPE_SCHEMA'
                        else:
                            status='SERVER_SCHEMA_REQUIREMENT_SATISFIED';why='REQUIRED_OUTPUT_FIELD_PRESENT_WITH_DECLARED_JSON_TYPE'
            tot[status]+=1
            priority[o['importance']]+=1
            scored.append({'id':o['id'],'basis':basis,'source_path':o.get('source_path'),
                'target_path':o.get('target_path'),'importance':o['importance'],
                'importance_is_operator_selected':True,'outcome':status,'reason':why,
                'independent_legal_obligation_proved':False,'independent_causal_loss_proved':False})
        out.append({'case_id':ident,'tool':case['tool'],'obligations':scored})
    return {'schema':RESULT_SCHEMA,'policy_sha256':policy_sha,'policy_id':policy['policy_id'],
        'issuer_kind':'OPERATOR_UNVERIFIED','importance_method':'OPERATOR_REASONED_LABEL_NOT_INDEPENDENT_SEVERITY',
        'advertised_schema_origin':schema_origin,'summary':tot,'importance_labels':priority,'cases':out,
        'publisher_schema_observations_are_not_legal_contracts':True,
        'operator_requirements_are_local_acceptance_criteria_not_publisher_promises':True,
        'reported_policy_violation_does_not_change_confirmed_loss':True,
        'field_values_or_original_sensitive_headers_exported':False}


def render(result):
    lines=['Observed output requirements versus operator-selected field duties:']
    for case in result['cases']:
        lines.append(case['case_id']+' tool='+case['tool'])
        for r in case['obligations']:
            lines.append('  '+r['id']+': '+r['outcome']+' ['+r['basis']+' / '+r['importance']+']')
    lines.append('Server-advertised schemas do not themselves prove legal obligations or independent provenance.')
    lines.append('Operator priorities are not objectively verified. No confirmed causal loss is asserted.')
    return '\n'.join(lines)+'\n'
