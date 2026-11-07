"""P4-P: count observed HTTP source leaf units, and exactly which were checked.

Opt-in, conservative accounting. Every primitive and empty collection is one
source leaf, including null, false, empty string, and every array element.
Checking an entire equal-valued subtree covers its descendant leaves. A lookup
status transition is counted separately from a literal value copied to MCP.
Unmentioned fields remain UNKNOWN, never LOSS. Overlapping rules do not double
count. Operator-declared rules cannot override P4-J causal gate or comparator.

No network, external imports, code eval, automatic snake-case mapping, path
interpolation, data value emission or root-subtree exclusions.
"""
from __future__ import annotations

import hashlib
import json

from risu_recovery import bounded
from risu_semantics import _pointer, _read_contract, _check_spec

SCHEMA='risu-source-leaf-coverage-v1'
MAX_LEAVES=1500
MAX_PATHS_DISPLAY=80


def _escape(token):
    return str(token).replace('~','~0').replace('/','~1')


def _leaves(body):
    """RFC6901 pointer -> primitive kind. Empty containers count as units."""
    if not isinstance(body,dict) or not bounded(body):
        raise ValueError('source coverage requires bounded JSON object')
    todo=[('',body,0)]
    out={}
    while todo:
        path,node,depth=todo.pop()
        if depth>32 or len(out)>MAX_LEAVES:
            raise ValueError('source coverage path or leaf limit exceeded')
        if isinstance(node,dict):
            if not node:out[path]='empty_object'
            else:
                for key in sorted(node,reverse=True):
                    todo.append((path+'/'+_escape(key),node[key],depth+1))
        elif isinstance(node,list):
            if not node:out[path]='empty_array'
            else:
                for idx in reversed(range(len(node))):
                    todo.append((path+'/'+str(idx),node[idx],depth+1))
        elif node is None:out[path]='null'
        elif type(node) is bool:out[path]='bool'
        elif type(node) is str:out[path]='string'
        elif type(node) is int:out[path]='integer'
        elif type(node) is float:out[path]='float'
        else:raise ValueError('source coverage unsupported primitive')
    if len(out)>MAX_LEAVES:raise ValueError('source coverage leaf cap exceeded')
    return out


def _descendants(leaves,root):
    """Pointer prefix is segment-aware: /a and /ab do not overlap."""
    return {p for p in leaves if p==root or p.startswith(root+'/')}


def _report_scope(allkeys,exact,transition,failed,insufficient,leaf_kinds,scope):
    paths=set(allkeys)
    # Contradicting or insufficient overlapping rules invalidate a claim of
    # verified equivalence for that same source leaf. No rule-shopping.
    f=failed&paths
    ins=(insufficient&paths)-f
    e=(exact&paths)-f-ins
    t=(transition&paths)-f-ins-e
    rest=paths-e-t-f-ins
    assert len(e)+len(t)+len(f)+len(ins)+len(rest)==len(paths)
    n=len(paths)
    counted=len(e)+len(t)
    return {
        'scope':scope,
        'total_source_leaf_units':n,
        'exact_value_verified':len(e),
        'transition_only_verified':len(t),
        'failed_declared_rule_leaf_units':len(f),
        'insufficient_evidence_leaf_units':len(ins),
        'undeclared_unassessed_leaf_units':len(rest),
        'coverage_verified_units':counted,
        'verified_coverage_pct':round(100*counted/n,2) if n else None,
        'exact_coverage_pct':round(100*len(e)/n,2) if n else None,
        'source_type_breakdown':{kind:sum(leaf_kinds[p]==kind for p in paths) for kind in
            ('string','integer','float','bool','null','empty_object','empty_array') if any(leaf_kinds[p]==kind for p in paths)},
        'unverified_source_paths':sorted(f|ins|rest)[:MAX_PATHS_DISPLAY],
        'unverified_source_paths_truncated':len(f|ins|rest)>MAX_PATHS_DISPLAY,
        'failed_declared_rule_paths':sorted(f)[:MAX_PATHS_DISPLAY],
        'insufficient_declared_rule_paths':sorted(ins)[:MAX_PATHS_DISPLAY],
        'all_source_fields_verified':n>0 and counted==n and not f and not ins,
    }


def _lookup_paths(rule,body,match):
    """Only document the components genuinely checked by P4-O lookup rule.

    Status code is an inferred mapping state, never an identical carried value.
    Empty {} under no-data is a verified structural state, not literal copying.
    Found source identifier is *exactly* compared against observed MCP input.
    Other sibling source fields are untouched by the lookup assertion.
    """
    sid=rule['status_path'];data=rule['source_data_path']
    found=rule['outcome']=='found'
    if match:
        exact={rule['source_id_path']} if found else set()
        transition={sid} if found else {sid,data}
        return exact,transition,set(),set()
    return set(),set(),({sid,data}|({rule['source_id_path']} if found else set())),set()


def assess_coverage(payload,semantic_result,mapping_path):
    """Compute field coverage from raw observed source, scoped validated rules.

    Semantic result (case/rule outcomes) MUST be produced from the same mapping
    contract and capture. Hash enforces contract identity, while callers need
    to call this immediately after semantic assessment on same payload.
    """
    contract,contract_sha=_read_contract(mapping_path)
    _check_spec(contract)
    if semantic_result.get('contract_sha256')!=contract_sha:
        raise ValueError('semantic coverage contract digest mismatch')
    configured={case['case_id']:case for case in contract['cases']}
    assessed={case['case_id']:case for case in semantic_result['cases']}
    cases=[]
    overall={'total_source_leaf_units':0,'exact_value_verified':0,
             'transition_only_verified':0,'failed_declared_rule_leaf_units':0,
             'insufficient_evidence_leaf_units':0,'undeclared_unassessed_leaf_units':0,
             'coverage_verified_units':0}
    for case in payload['cases']:
        ident=case['id']
        if ident not in assessed:raise ValueError('semantic coverage case mismatch')
        leaves=_leaves(case['source']['body'])
        verified=set();transitions=set();failed=set();insufficient=set()
        by_kind={}
        data_roots=set()
        spec=configured.get(ident)
        if spec is not None:
            recorded=assessed[ident]
            checks={check['id']:check for check in recorded['checks']}
            if len(checks)!=len(recorded['checks']):raise ValueError('duplicate semantic check')
            for rule in spec['rules']:
                check=checks.get(rule['id'])
                if check is None or check['kind']!=rule['kind']:
                    raise ValueError('semantic coverage check is missing or mismatched')
                outcome=check['outcome']
                if outcome not in ('OBSERVED_MATCH','CONTRADICTED','INSUFFICIENT'):
                    raise ValueError('semantic coverage unrecognized check')
                if rule['kind']=='equal_paths':
                    path=rule['source_path']
                    if outcome=='OBSERVED_MATCH': verified.update(_descendants(leaves,path))
                    elif outcome=='CONTRADICTED':failed.update(_descendants(leaves,path))
                    else:insufficient.update(_descendants(leaves,path))
                else:
                    data_roots.add(rule['source_data_path'])
                    x,t,f,_=_lookup_paths(rule,case['source']['body'],outcome=='OBSERVED_MATCH')
                    if outcome=='OBSERVED_MATCH':
                        verified.update(x&set(leaves));transitions.update(t&set(leaves))
                    elif outcome=='CONTRADICTED':failed.update(f&set(leaves))
                    else:insufficient.update(f&set(leaves))
            # A built-in HTTP error gate is a rule contradiction, not a
            # source JSON leaf. Never convert its result to a verified count.
            if any(x['id']=='BUILTIN_HTTP_ERROR_FLAG' and x['outcome']=='CONTRADICTED' for x in recorded['checks']):
                by_kind['independent_http_error_flag_gate_failed']=True
        full=_report_scope(leaves,verified,transitions,failed,insufficient,leaves,'ENTIRE_HTTP_JSON_BODY')
        data_paths=set()
        for root in data_roots:data_paths.update(_descendants(leaves,root))
        focused=_report_scope(data_paths,verified,transitions,failed,insufficient,leaves,
                        'OPERATOR_DECLARED_LOOKUP_DATA_SUBTREES') if data_roots else None
        for key in overall:overall[key]+=full[key]
        cases.append({
            'case_id':ident,
            'rule_outcome':assessed[ident]['outcome'],
            'source_schema_sha256':hashlib.sha256(json.dumps(sorted(leaves.items()),
                ensure_ascii=False,separators=(',',':')).encode()).hexdigest(),
            'full_source':full,
            'lookup_data_scope':focused,
            'lookup_data_scope_roots':sorted(data_roots),
            'source_leaf_unit_policy':'Every observed JSON primitive or empty object/array is one leaf; arrays counted by index; no values emitted.',
            'semantic_verification_limitations':by_kind
        })
    total=overall['total_source_leaf_units'];good=overall['coverage_verified_units']
    overall['verified_coverage_pct']=round(100*good/total,2) if total else None
    overall['exact_coverage_pct']=round(100*overall['exact_value_verified']/total,2) if total else None
    assert good==overall['exact_value_verified']+overall['transition_only_verified']
    assert total==good+overall['failed_declared_rule_leaf_units']+overall['insufficient_evidence_leaf_units']+overall['undeclared_unassessed_leaf_units']
    return {
        'schema':SCHEMA,
        'contract_sha256':contract_sha,
        'meaning':'OBSERVED_SOURCE_LEAF_COVERAGE_UNDER_OPERATOR_DECLARED_RULES',
        'counts_source_not_target':'MCP-only generated fields are excluded from the SOURCE denominator; no assumption about invertibility.',
        'not_equivalent_to':['semantic completeness','verified independent causality','false positive rate','original status code surviving as same bytes','unverified field loss'],
        'source_path_values_exported':False,
        'source_path_keys_exported':True,
        'all_cases_full_source':overall,
        'cases':cases,
        'unchanged_original_comparator_and_p4j_gate':True,
    }


def render(out):
    lines=['RISU Source Field Coverage | all observed source JSON primitive/empty-container leaves included']
    for case in out['cases']:
        f=case['full_source']
        lines.append(f"{case['case_id']}: verified={f['coverage_verified_units']}/{f['total_source_leaf_units']} ({f['verified_coverage_pct']}%); exact={f['exact_value_verified']} transition={f['transition_only_verified']} failed={f['failed_declared_rule_leaf_units']} insufficient={f['insufficient_evidence_leaf_units']} undeclared={f['undeclared_unassessed_leaf_units']}")
        if case['lookup_data_scope']:
            d=case['lookup_data_scope']
            lines.append(f"  declared lookup data scope: verified={d['coverage_verified_units']}/{d['total_source_leaf_units']} ({d['verified_coverage_pct']}%)")
    lines.append('Unverified fields are UNKNOWN, not proven losses. Operator mappings are not independent domain or causal evidence.')
    return '\n'.join(lines)+'\n'
