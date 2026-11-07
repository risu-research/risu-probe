"""P4-R: source-grounded disposition of original source fields left unverified by P4-Q.

Explicit, bounded opt-in observations only. A syntactic remap, a normalized
empty source object, and fields excluded from the observed MCP result are
*separate* outcomes. Nothing here certifies independent causality or semantic
necessity, and absent envelope fields are NOT counted as confirmed data loss.

Fail closed on duplicate/overlapping rules, changed source types, missing
capture evidence, mismatched declared field names, source ambiguity, and
unobserved target structures. No dynamic transforms, evaluated expressions,
heuristic value matching, network, third-party code, or original field values
in output.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path

from risu_capture import _read, loads
from risu_coverage import _leaves
from risu_semantics import _pointer, _equals

SCHEMA='risu-declared-residual-disposition-v1'
OUT='risu-original-field-disposition-results-v1'
MAX_BYTES=100_000
MAX_RULES=100


def _load_contract(path, directory):
    path=Path(path)
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= MAX_BYTES:
        raise ValueError('residual mapping must be a regular non-symlink JSON file <= 100 KB')
    if Path(directory).resolve() == path.resolve() or Path(directory).resolve() in path.resolve().parents:
        raise ValueError('residual mapping must be selected outside captured data directory')
    raw=_read(path)
    spec=loads(raw.decode('utf-8'))
    if not isinstance(spec,dict) or set(spec)!={'schema','cases'} or spec['schema']!=SCHEMA:
        raise ValueError('unrecognized residual mapping schema')
    cases=spec['cases']
    if not isinstance(cases,list) or not 1<=len(cases)<=50:
        raise ValueError('residual mapping requires 1-50 cases')
    ids=set();n=0
    for c in cases:
        if not isinstance(c,dict) or set(c)!={'case_id','rules'}:
            raise ValueError('invalid residual case object')
        if not isinstance(c['case_id'],str) or not (1<=len(c['case_id'])<=90) or c['case_id'] in ids:
            raise ValueError('invalid or duplicated residual case identity')
        ids.add(c['case_id'])
        rules=c['rules'];check_ids=set();sources=set();targets=set()
        if not isinstance(rules,list) or not 1<=len(rules)<=MAX_RULES:
            raise ValueError('residual case must declare 1-100 rules')
        for r in rules:
            if not isinstance(r,dict):raise ValueError('invalid residual rule')
            kind=r.get('kind')
            fields={'id','kind','source_path'}
            if kind=='strict_equal':fields|={'target_path'}
            elif kind=='empty_object_expanded':fields|={'target_path','expected_target_fields'}
            elif kind=='observed_not_exposed':fields|={'field_aliases','require_nonempty_source_absent'}
            else:raise ValueError('unknown residual rule kind')
            if set(r)!=fields:raise ValueError('residual rule has missing or unsupported members')
            rid=r['id'];sp=r['source_path']
            if not isinstance(rid,str) or not rid or len(rid)>80 or not all(ch.isalnum() or ch in '_-' for ch in rid) or rid in check_ids:
                raise ValueError('duplicate or unsafe residual check ID')
            check_ids.add(rid)
            _pointer({},sp)
            if sp in sources:raise ValueError('same source field may not be declared by two residual rules')
            sources.add(sp)
            if kind in ('strict_equal','empty_object_expanded'):
                tp=r['target_path'];_pointer({},tp)
                if tp in targets:raise ValueError('multiple residual source fields cannot claim the same target path')
                targets.add(tp)
            if kind=='empty_object_expanded':
                expected=r['expected_target_fields']
                if not isinstance(expected,list) or not 1<=len(expected)<=16 or len(set(expected))!=len(expected):
                    raise ValueError('empty object expansion must declare 1-16 unique expected keys')
                if not all(isinstance(x,str) and x and x.isidentifier() and len(x)<=80 for x in expected):
                    raise ValueError('unsafe expansion key')
            if kind=='observed_not_exposed':
                aliases=r['field_aliases']
                if not isinstance(aliases,list) or not 1<=len(aliases)<=5 or len(set(aliases))!=len(aliases):
                    raise ValueError('invalid field aliases')
                if not all(isinstance(x,str) and x and x.isidentifier() and len(x)<=80 for x in aliases):
                    raise ValueError('unsafe field alias')
                if r['source_path'].split('/')[-1] not in aliases:
                    raise ValueError('observed-not-exposed check must include the exact original source field name')
                if type(r['require_nonempty_source_absent']) is not bool:
                    raise ValueError('nonempty check must be boolean')
            n+=1
    if n>MAX_RULES:raise ValueError('too many residual rules across cases')
    return spec,hashlib.sha256(raw).hexdigest()


def _contains_named_key(node,aliases):
    stack=[node];seen=0
    while stack:
        v=stack.pop();seen+=1
        if seen>20000:raise ValueError('too many MCP nodes to check envelope field exposure')
        if isinstance(v,dict):
            if aliases.intersection(v):return True
            stack.extend(v.values())
        elif isinstance(v,list):stack.extend(v)
    return False


def _parse_text_content(mcp):
    """Include both native MCP structured output and all text carriers.

    The text output may contain JSON as a string. It must be inspected for
    source values or alternate names, not treated as absent by default.
    """
    content=mcp.get('content')
    if not isinstance(content,list) or not 1<=len(content)<=16:
        return False,[]
    pieces=[]
    for item in content:
        if not isinstance(item,dict):return False,[]
        if item.get('type')=='text':
            s=item.get('text')
            if not isinstance(s,str) or len(s)>1_000_000:return False,[]
            pieces.append(s)
        else:
            # Non-text content could carry uninspected data. Do not assert
            # complete non-exposure for unknown media.
            return False,[]
    return True,pieces


def _rule(r,body,mcp,structured):
    exists,original=_pointer(body,r['source_path'])
    if not exists:return 'INSUFFICIENT','SOURCE_PATH_NOT_OBSERVED',False,False
    kind=r['kind']
    if kind in ('strict_equal','empty_object_expanded'):
        if not isinstance(structured,dict):return 'INSUFFICIENT','STRUCTURED_MCP_RESULT_UNOBSERVED',False,False
        present,target=_pointer(structured,r['target_path'])
        if not present:return 'CONTRADICTED','DECLARED_TARGET_FIELD_MISSING',False,False
        if kind=='strict_equal':
            if not _equals(original,target):
                return 'CONTRADICTED','TARGET_VALUE_OR_TYPE_DIFFERENT',False,False
            return 'VERIFIED_EXACT_REMAP','EXACT_TYPED_VALUE_OBSERVED_AT_DECLARED_TARGET',True,False
        if not isinstance(original,dict) or original:
            return 'CONTRADICTED','SOURCE_EXPECTED_EMPTY_OBJECT',False,False
        if not isinstance(target,dict) or set(target)!=set(r['expected_target_fields']) or not all(type(value) is str and value=='' for value in target.values()):
            return 'CONTRADICTED','DEFAULT_MODEL_EXPANSION_SHAPE_OR_VALUE_DIFFERENT',False,False
        return 'VERIFIED_EMPTY_STRUCTURAL_EXPANSION','EMPTY_OBJECT_REPRESENTED_BY_DECLARED_DEFAULT_FIELDS',False,True
    # An unfinished or tool-error response cannot prove that a successful
    # adapter deliberately excluded metadata from its structured result.
    if mcp.get('isError') is not False:
        return 'INSUFFICIENT','SUCCESSFUL_MCP_RESULT_NOT_OBSERVED',False,False
    # Actual absence in *the observed MCP result*, not a causal loss finding.
    aliases=set(r['field_aliases'])
    ok,pieces=_parse_text_content(mcp)
    if not ok or not isinstance(structured,dict):
        return 'INSUFFICIENT','MCP_CONTENT_CARRIERS_INCOMPLETE',False,False
    if _contains_named_key(structured,aliases):
        return 'CONTRADICTED','DECLARED_ABSENT_FIELD_FOUND_IN_STRUCTURED_MCP',False,False
    for s in pieces:
        if any(ali in s for ali in aliases):
            return 'CONTRADICTED','DECLARED_ABSENT_FIELD_FOUND_IN_TEXT_CARRIER',False,False
    if r['require_nonempty_source_absent']:
        # Absent nonempty values can be detected only when no text carrier
        # even contains that token; equal tokens alone are not provenance.
        if type(original) is not str or not original:
            return 'INSUFFICIENT','NONEMPTY_QUOTA_VALUE_NOT_OBSERVED',False,False
        if any(original in s for s in pieces) or original in json.dumps(structured,ensure_ascii=False):
            return 'INSUFFICIENT','SOURCE_VALUE_PRESENT_SOMEWHERE_WITHOUT_PROVENANCE',False,False
        return 'OBSERVED_NONEXPOSURE','NAMED_FIELD_AND_ORIGINAL_NONEMPTY_TOKEN_ABSENT_FROM_OBSERVED_MCP_RESULT',False,False
    if type(original) is not str or original != '':
        # A nonempty error message cannot be adjudicated by an empty-message
        # rule. Explicitly unknown if content is transformed to a summary.
        return 'INSUFFICIENT','EXPECTED_EMPTY_ERROR_MESSAGE_ONLY',False,False
    return 'OBSERVED_NONEXPOSURE','NAMED_EMPTY_ENVELOPE_FIELD_ABSENT_FROM_OBSERVED_MCP_RESULT',False,False


def assess_residual(payload,combined,contract_path,capture_dir):
    if capture_dir is None or not Path(capture_dir).is_dir():
        raise ValueError('original capture folder required for residual assessment')
    contract,sha=_load_contract(contract_path,capture_dir)
    if combined.get('schema')!='risu-source-coverage-with-keyed-arrays-v1':
        raise ValueError('P4-Q certified baseline required')
    known={x['case_id']:x for x in contract['cases']}
    by_case={x['case_id']:x for x in combined['cases']}
    if len(by_case)!=len(combined['cases']):raise ValueError('duplicate base coverage identities')
    declared=set(known)
    if not declared.issubset({x['id'] for x in payload['cases']}):
        raise ValueError('declared residual case missing from actual native capture')
    rows=[];tot={'source_leaf_units':0,'baseline_verified':0,'exact_new':0,'normalized_new':0,'observed_nonexposure':0,'unknown_or_contradicted':0,'final_verified':0,'remaining_unverified':0}
    for item in payload['cases']:
        ident=item['id'];baseline=by_case.get(ident)
        if baseline is None:raise ValueError('P4-Q base coverage case missing')
        body=item['source']['body'];mcp=item['mcp'];structured=mcp.get('structuredContent')
        leaves=_leaves(body)
        still=set(baseline['still_unverified_source_paths'])
        if baseline.get('still_unverified_paths_truncated'):
            raise ValueError('P4-Q residual path list was truncated; cannot certify residual coverage')
        if len(still)!=baseline['combined_unverified_units']:raise ValueError('truncated/inconsistent P4-Q residual paths')
        declared_paths=set();outcomes=[];exact=set();normalized=set();absent=set();uncertain=set()
        if ident in known:
            for rule in known[ident]['rules']:
                sp=rule['source_path'];declared_paths.add(sp)
                if sp not in still or sp not in leaves:
                    # No rule-shopping: a previously certified or absent path
                    # cannot be credited to a residual contract.
                    raise ValueError('declared residual source field not in the current P4-Q residual set')
                status,reason,is_exact,is_normalized=_rule(rule,body,mcp,structured)
                if status=='VERIFIED_EXACT_REMAP':exact.add(sp)
                elif status=='VERIFIED_EMPTY_STRUCTURAL_EXPANSION':normalized.add(sp)
                elif status=='OBSERVED_NONEXPOSURE':absent.add(sp)
                else:uncertain.add(sp)
                outcomes.append({'id':rule['id'],'source_path':sp,'kind':rule['kind'],
                    'outcome':status,'reason':reason,'verified_exact':is_exact,
                    'verified_normalized':is_normalized,'causal_loss_confirmed':False})
        new=exact|normalized
        if len(new&absent) or len(new&uncertain):raise AssertionError('residual disposition overlap')
        total=baseline['total_source_leaf_units'];prev=baseline['combined_verified_units']
        if total!=len(leaves) or prev+len(still)!=total:
            raise ValueError('source leaf denominator does not match P4-Q baseline')
        remain=still-new
        case={'case_id':ident,'source_leaf_units':total,'prior_verified':prev,
              'verified_exact_new':len(exact),'verified_normalized_new':len(normalized),
              'observed_nonexposure_count':len(absent),
              'declared_but_insufficient_or_contradicted':len(uncertain),
              'undeclared_residual_count':len(still-declared_paths),
              'combined_verified':prev+len(new),'remaining_unverified':len(remain),
              'combined_verified_pct':round(100*(prev+len(new))/total,2) if total else None,
              'remaining_unverified_source_paths':sorted(remain),
              'rules':outcomes,'scope':'ONLY_ORIGINAL_PREVIOUSLY_UNVERIFIED_SOURCE_LEAVES',
              'independent_causality_verified':False}
        rows.append(case)
        tot['source_leaf_units']+=total;tot['baseline_verified']+=prev
        tot['exact_new']+=len(exact);tot['normalized_new']+=len(normalized)
        tot['observed_nonexposure']+=len(absent);tot['unknown_or_contradicted']+=len(uncertain)+len(still-declared_paths)
        tot['final_verified']+=prev+len(new);tot['remaining_unverified']+=len(remain)
    if tot['final_verified']+tot['remaining_unverified']!=tot['source_leaf_units']:
        raise AssertionError('field accounting inconsistent')
    tot['final_verified_pct']=round(100*tot['final_verified']/tot['source_leaf_units'],2) if tot['source_leaf_units'] else None
    return {'schema':OUT,'contract_sha256':sha,'summary':tot,'cases':rows,
            'exposure_evidence_level':'OBSERVED_NATIVE_MCP_RESULT_UNVERIFIED_INDEPENDENT_CAUSALITY',
            'operator_declared_rules_not_proof_of_domain_requiredness':True,
            'observed_nonexposure_is_not_confirmed_semantic_loss':True,
            'field_values_or_token_hashes_exported':False}


def render(result):
    s=result['summary']
    out=['Source residual field classification: exact='+str(s['exact_new'])+', normalized='+str(s['normalized_new'])+', observed non-exposure='+str(s['observed_nonexposure'])+', unresolved='+str(s['unknown_or_contradicted'])]
    out.append('Combined verified source fields '+str(s['final_verified'])+'/'+str(s['source_leaf_units'])+' ('+str(s['final_verified_pct'])+'%).')
    out.append('Non-exposure is an observation of this MCP result, NOT proven causal/required-field loss.')
    for row in result['cases']:
        out.append(row['case_id']+': remaining='+str(row['remaining_unverified']))
        for rule in row['rules']:
            out.append('  '+rule['id']+' '+rule['outcome']+' '+rule['source_path']+' ('+rule['reason']+')')
    return '\n'.join(out)+'\n'
