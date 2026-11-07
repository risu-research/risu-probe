"""P4-Q: explicit, identity-joined arrays in a recorded HTTP -> MCP result.

Opt-in evidence lens, NEVER causal proof or generic semantic completeness.
Only whitelisted, declared scalar fields in keyed array rows are compared.
There is NO index/position fallback and NO nearest-match heuristic. Children
are attached only after their parent was unambiguously joined by a typed key.
Any duplicate, missing key, unequal set of row identities, or field mismatch
blocks certification for the *whole* array group and its child groups.

No network, application imports, eval, value disclosure, untrusted code exec.
"""
from __future__ import annotations
import hashlib
import json
import re
from pathlib import Path

from risu_semantics import _pointer, _read_contract, _check_spec, _equals
from risu_capture import loads, _read
from risu_coverage import _leaves, _descendants, _lookup_paths

SCHEMA='risu-identity-array-groups-v1'
OUTPUT='risu-identity-array-results-v1'
NAME=re.compile(r'[A-Za-z][A-Za-z0-9]{0,79}\Z',re.ASCII)
ID=re.compile(r'[A-Za-z][A-Za-z0-9_-]{0,79}\Z',re.ASCII)
TARGETNAME=re.compile(r'[a-z][a-z0-9_]{0,79}\Z',re.ASCII)
MAX_FILE=300_000
MAX_GROUPS=12
MAX_ROWS=200
MAX_SCALAR_FIELDS=24
MAX_TOTAL_SOURCE_LEAVES=1500


def camel_to_snake(k):
    """Only a declared, finite, deterministic schema naming transform."""
    if not isinstance(k,str) or not NAME.fullmatch(k):
        raise ValueError('array field must be simple declared camel-case identifier')
    return re.sub(r'(?<=[a-z0-9])(?=[A-Z])','_',k).lower()


def _parse_contract(path, capture_dir):
    path=Path(path)
    if path.is_symlink() or not path.is_file() or not 0<path.stat().st_size<=MAX_FILE:
        raise ValueError('array map must be a regular nonsymlink file <=300 KB')
    try: path.resolve().relative_to(Path(capture_dir).resolve())
    except ValueError: pass
    else: raise ValueError('operator array map must be outside captured input directory')
    raw=_read(path)
    obj=loads(raw.decode('utf-8'))
    if not isinstance(obj,dict) or set(obj)!={'schema','cases'} or obj['schema']!=SCHEMA:
        raise ValueError('unrecognized array mapping contract')
    cases=obj['cases']
    if not isinstance(cases,list) or not 1<=len(cases)<=50:
        raise ValueError('array mapping requires 1-50 cases')
    seen=set()
    for case in cases:
        if not isinstance(case,dict) or set(case)!={'case_id','groups'} or not ID.fullmatch(str(case['case_id'])):
            raise ValueError('invalid array mapping case')
        if case['case_id'] in seen:raise ValueError('duplicate array mapping case id')
        seen.add(case['case_id'])
        groups=case['groups']
        if not isinstance(groups,list) or not 1<=len(groups)<=MAX_GROUPS:
            raise ValueError('array mapping requires 1-12 ordered groups')
        parent_ids=set();locations=set()
        for group in groups:
            if not isinstance(group,dict):raise ValueError('invalid array group')
            nested=group.get('parent') is not None
            required={'id','parent','identity','fields','naming','source_field','target_field'} if nested else {'id','parent','identity','fields','naming','source_array','target_array'}
            if set(group)!=required:raise ValueError('invalid array group keys or missing parent')
            if not isinstance(group['id'],str) or not ID.fullmatch(group['id']) or group['id'] in parent_ids:
                raise ValueError('duplicate or invalid array group name')
            if nested and group['parent'] not in parent_ids:
                raise ValueError('array child must reference prior distinct parent')
            if not nested and group['parent'] is not None:raise ValueError('invalid top-level parent')
            if nested:
                for x in ('source_field','target_field'):
                    if not isinstance(group[x],str) or not (NAME if x=='source_field' else TARGETNAME).fullmatch(group[x]):
                        raise ValueError('unsafe nested array field')
                if camel_to_snake(group['source_field'])!=group['target_field']:
                    raise ValueError('nested field name mapping is not declared camel_to_snake')
            else:
                for x in ('source_array','target_array'):_pointer({},group[x])
            origin=(group['parent'],group.get('source_array',group.get('source_field')),
                    group.get('target_array',group.get('target_field')))
            if origin in locations:raise ValueError('duplicate array location declared by multiple groups')
            locations.add(origin)
            if group['naming']!='DECLARED_CAMEL_TO_SNAKE_V1':
                raise ValueError('array column map must declare a supported exact deterministic policy')
            fields=group['fields'];identities=group['identity']
            if not isinstance(fields,list) or not 1<=len(fields)<=MAX_SCALAR_FIELDS or len(set(fields))!=len(fields):
                raise ValueError('invalid or repeated array scalar fields')
            if not isinstance(identities,list) or not 1<=len(identities)<=4 or len(set(identities))!=len(identities):
                raise ValueError('invalid or repeated typed key columns')
            if not set(identities).issubset(fields):raise ValueError('identity keys must be among all compared scalar columns')
            for col in fields:camel_to_snake(col)
            mapped=[camel_to_snake(x) for x in fields]
            if len(set(mapped))!=len(mapped):raise ValueError('camel_to_snake mapping collision')
            parent_ids.add(group['id'])
    return obj,hashlib.sha256(raw).hexdigest()


def _identity(row,names):
    vals=[]
    for name in names:
        if name not in row:raise ValueError('identity key absent')
        v=row[name]
        if type(v) not in (str,int) or (type(v) is str and (not v or len(v)>120)):
            raise ValueError('array identity must be exact, bounded primitive string or integer')
        vals.append((type(v).__name__,v))
    return tuple(vals)


def _match_group(group,contexts,children,all_leaves):
    """(source array, target array, absolute source path) contexts, per parent.

    Returns matching key-linked rows and source leaf paths ONLY if EVERY
    specified row/field is consistent in EVERY parent context; all-or-none.
    """
    gid=group['id']
    source_names=group['fields']
    source_child_names=set(children.get(gid,()))
    target_names=[camel_to_snake(s) for s in source_names]
    target_child_names={camel_to_snake(s) for s in source_child_names}
    # A group certifies only scalar columns, and explicitly delegates children.
    source_columns=set(source_names)|source_child_names
    target_columns=set(target_names)|target_child_names
    matches=[];certified=set();parent_count=0;row_count=0
    for source,target,base in contexts:
        parent_count+=1
        if not isinstance(source,list) or not isinstance(target,list):
            return 'INSUFFICIENT' if target is None else 'CONTRADICTED',[],set(),'ABSENT_OR_NONARRAY_BOUNDARY',parent_count,row_count
        if len(source)>MAX_ROWS or len(target)>MAX_ROWS:
            return 'CONTRADICTED',[],set(),'ROW_LIMIT_EXCEEDED',parent_count,row_count
        if len(source)!=len(target):
            return 'CONTRADICTED',[],set(),'ARRAY_CARDINALITY_DIFFERENT',parent_count,row_count
        smap={}; tmap={}
        try:
            for i,row in enumerate(source):
                if not isinstance(row,dict) or set(row)!=source_columns:
                    return 'CONTRADICTED',[],set(),'SOURCE_COLUMN_SHAPE_DISAGREEMENT',parent_count,row_count
                for field in source_names:
                    if isinstance(row[field],(dict,list)):
                        return 'CONTRADICTED',[],set(),'DECLARED_SCALAR_FIELD_HAS_COMPOSITE_VALUE',parent_count,row_count
                k=_identity(row,group['identity'])
                if k in smap:
                    return 'CONTRADICTED',[],set(),'DUPLICATE_OR_AMBIGUOUS_SOURCE_IDENTITY',parent_count,row_count
                smap[k]=(i,row)
            for i,row in enumerate(target):
                if not isinstance(row,dict) or set(row)!=target_columns:
                    return 'CONTRADICTED',[],set(),'TARGET_COLUMN_SHAPE_DISAGREEMENT',parent_count,row_count
                for field in target_names:
                    if isinstance(row[field],(dict,list)):
                        return 'CONTRADICTED',[],set(),'DECLARED_TARGET_SCALAR_IS_COMPOSITE',parent_count,row_count
                k=_identity(row,[camel_to_snake(x) for x in group['identity']])
                if k in tmap:
                    return 'CONTRADICTED',[],set(),'DUPLICATE_OR_AMBIGUOUS_TARGET_IDENTITY',parent_count,row_count
                tmap[k]=(i,row)
        except ValueError as exc:
            # Only exported error categories; never emit raw identity key values.
            return 'CONTRADICTED',[],set(),'UNREADABLE_IDENTITY_OR_FIELD',parent_count,row_count
        if smap.keys()!=tmap.keys():
            return 'CONTRADICTED',[],set(),'MISSING_OR_EXTRA_TARGET_IDENTITY',parent_count,row_count
        for k,(i,srow) in smap.items():
            _,trow=tmap[k]
            for col in source_names:
                if not _equals(srow[col],trow[camel_to_snake(col)]):
                    return 'CONTRADICTED',[],set(),'MISMATCHED_ROW_FIELD_VALUE_OR_TYPE',parent_count,row_count
                p=base+'/'+str(i)+'/'+col.replace('~','~0').replace('/','~1')
                if p not in all_leaves:
                    return 'CONTRADICTED',[],set(),'ARRAY_LEAF_PATH_NOT_IN_ORIGINAL_SOURCE',parent_count,row_count
                certified.add(p)
            row_count+=1
            matches.append((srow,trow,base+'/'+str(i)))
    return 'OBSERVED_MATCH',matches,certified,'STRICT_EXACT_TYPED_IDENTITY_AND_SCALAR_VALUES',parent_count,row_count


def assess_arrays(payload,array_path,capture_dir):
    contract,digest=_parse_contract(array_path,capture_dir)
    configs={c['case_id']:c for c in contract['cases']}
    observed={c['id']:c for c in payload['cases']}
    if not set(configs).issubset(observed):raise ValueError('array contract references uncaptured case')
    result=[];overall={'groups':0,'matched_groups':0,'contradicted_groups':0,'insufficient_groups':0,'matched_rows':0,'candidate_exact_leaf_units':0}
    for case in payload['cases']:
        ident=case['id'];leaves=_leaves(case['source']['body'])
        groups=configs.get(ident,{}).get('groups',[])
        children={g['id']:[] for g in groups}
        for g in groups:
            if g['parent'] is not None:children[g['parent']].append(g['source_field'])
        output=[];joined={};valid_paths=set();inhibited_paths=set();statuses={}
        mcp=case.get('mcp',{}).get('structuredContent')
        for group in groups:
            gid=group['id']; parent=group['parent']
            if parent:
                if statuses.get(parent)!='OBSERVED_MATCH':
                    status,matches,paths,reason,parents,rows='INSUFFICIENT',[],set(),'PARENT_NOT_CERTIFIED',0,0
                else:
                    context=[(s.get(group['source_field']),t.get(group['target_field']),base+'/'+group['source_field'])
                             for s,t,base in joined[parent]]
                    status,matches,paths,reason,parents,rows=_match_group(group,context,children,leaves)
            else:
                sp,sv=_pointer(case['source']['body'],group['source_array'])
                tp,tv=_pointer(mcp,group['target_array']) if isinstance(mcp,dict) else (False,None)
                if not sp:
                    status,matches,paths,reason,parents,rows='INSUFFICIENT',[],set(),'SOURCE_ARRAY_NOT_OBSERVED',0,0
                elif not tp:
                    status,matches,paths,reason,parents,rows='INSUFFICIENT',[],set(),'MACHINE_TARGET_ARRAY_NOT_OBSERVED',0,0
                else:
                    status,matches,paths,reason,parents,rows=_match_group(group,[(sv,tv,group['source_array'])],children,leaves)
            statuses[gid]=status
            joined[gid]=matches if status=='OBSERVED_MATCH' else []
            if status=='OBSERVED_MATCH':valid_paths.update(paths)
            else:
                # No rule-shopping: any uncertified group prevents its own
                # array subtree from being marked as verified by the array lens.
                # Preexisting P4-P coverage remains a separate report.
                if parent:
                    # Keyed parent rows known only if parent verified.
                    for s,_,base in joined.get(parent,[]):
                        inhibited_paths.update(_descendants(leaves,base+'/'+group['source_field']))
                else:inhibited_paths.update(_descendants(leaves,group['source_array']))
            output.append({'id':gid,'parent':parent,'status':status,'reason':reason,
                           'parent_scopes_checked':parents,'matched_rows':rows,
                           'verified_scalar_source_leaf_units':len(paths) if status=='OBSERVED_MATCH' else 0,
                           'reordering_allowed_by_identity':True,'positional_matching_used':False,
                           'exported_identifiers_or_source_values':False})
            overall['groups']+=1
            overall[{'OBSERVED_MATCH':'matched_groups','CONTRADICTED':'contradicted_groups','INSUFFICIENT':'insufficient_groups'}[status]]+=1
            if status=='OBSERVED_MATCH':overall['matched_rows']+=rows
        valid_paths-=inhibited_paths
        overall['candidate_exact_leaf_units']+=len(valid_paths)
        result.append({'case_id':ident,'groups':output,'verified_exact_source_paths':sorted(valid_paths),
                       'blocked_array_source_paths':sorted(inhibited_paths),
                       'exact_verified_source_leaf_units':len(valid_paths),
                       'declared_group_count':len(groups)})
    return {'schema':OUTPUT,'contract_sha256':digest,'cases':result,'summary':overall,
            'source_values_or_keys_exported':False,
            'operator_declared_mapping_not_independent_proof':True,
            'not_proof_of':['independent HTTP/MCP causality','complete source preservation','domain-level equivalence','field false positive rate'],
            'matching_policy':'strict typed composite identity, complete row-key coverage, all-or-none group checks, no positional fallback'}


def merge_coverage(coverage,arrays,payload,semantic_result,semantic_map):
    """Return a second metric; don't overwrite the original P4-P denominator.

    Array path evidence only counts when row/identity/field checks succeed;
    on contradiction all array matching credit is withheld. Prior P4-P
    credit is never retracted from its original separate report.
    """
    contract,sha=_read_contract(semantic_map)
    _check_spec(contract)
    if sha!=semantic_result['contract_sha256'] or sha!=coverage['contract_sha256']:
        raise ValueError('semantic mapping and coverage originate from different contracts')
    rules_by_case={c['case_id']:c['rules'] for c in contract['cases']}
    sem_by_case={c['case_id']:c for c in semantic_result['cases']}
    rows={c['case_id']:c for c in arrays['cases']}
    output=[];agg={'source_leaf_units':0,'baseline_verified':0,'array_verified_unique':0,'overlap_with_baseline':0,
                   'newly_verified_by_array_groups':0,'combined_verified':0,'combined_unverified':0}
    for original,c in zip(payload['cases'],coverage['cases']):
        if original['id']!=c['case_id']:raise ValueError('coverage case ordering mismatch')
        leaves=_leaves(original['source']['body'])
        a=rows[c['case_id']]
        # Reproduce P4-P baseline from the same verified semantic checks.
        # P4-P deliberately caps exported path lists at 80, so its missing
        # field inventory cannot be used as a full baseline for 134+ leaves.
        f=c['full_source']
        good=set();transitions=set();failed=set();insufficient=set()
        checks={x['id']:x for x in sem_by_case[c['case_id']]['checks']}
        for rule in rules_by_case.get(c['case_id'],[]):
            chk=checks[rule['id']]
            outcome=chk['outcome']
            if rule['kind']=='equal_paths':
                paths=_descendants(leaves,rule['source_path'])
                if outcome=='OBSERVED_MATCH':good.update(paths)
                elif outcome=='CONTRADICTED':failed.update(paths)
                else:insufficient.update(paths)
            else:
                exact,trans,failing,_=_lookup_paths(rule,original['source']['body'],outcome=='OBSERVED_MATCH')
                if outcome=='OBSERVED_MATCH':
                    good.update(exact&set(leaves));transitions.update(trans&set(leaves))
                elif outcome=='CONTRADICTED':failed.update(failing&set(leaves))
                else:insufficient.update(failing&set(leaves))
        baseline=(good|transitions)-failed-insufficient
        if len(baseline)!=f['coverage_verified_units']:
            raise ValueError('recomputed P4-P verified baseline disagrees with original report')
        candidate=set(a['verified_exact_source_paths'])
        if not candidate<=set(leaves):raise ValueError('array evidence outside observed source')
        new=candidate-baseline
        combined=baseline|candidate
        assert len(combined)+len(set(leaves)-combined)==len(leaves)
        metrics={'case_id':c['case_id'],'total_source_leaf_units':len(leaves),'baseline_verified_units':len(baseline),
                 'array_verified_unique_units':len(candidate),'overlap_with_baseline_units':len(candidate&baseline),
                 'newly_verified_by_array_groups':len(new),'combined_verified_units':len(combined),
                 'combined_unverified_units':len(leaves)-len(combined),
                 'combined_coverage_pct':round(100*len(combined)/len(leaves),2) if leaves else None,
                 'still_unverified_source_paths':sorted(set(leaves)-combined)[:80],
                 'still_unverified_paths_truncated':len(leaves)-len(combined)>80,
                 'incomplete_not_lost':True,
                 'array_contract_outcomes':{x['id']:x['status'] for x in a['groups']}}
        for k,key in [('source_leaf_units','total_source_leaf_units'),('baseline_verified','baseline_verified_units'),
                      ('array_verified_unique','array_verified_unique_units'),('overlap_with_baseline','overlap_with_baseline_units'),
                      ('newly_verified_by_array_groups','newly_verified_by_array_groups'),('combined_verified','combined_verified_units'),
                      ('combined_unverified','combined_unverified_units')]:agg[k]+=metrics[key]
        output.append(metrics)
    agg['combined_coverage_pct']=round(100*agg['combined_verified']/agg['source_leaf_units'],2) if agg['source_leaf_units'] else None
    assert agg['combined_verified']==agg['baseline_verified']+agg['newly_verified_by_array_groups']
    return {'schema':'risu-source-coverage-with-keyed-arrays-v1','cases':output,'summary':agg,
            'original_p4p_report_unchanged':True,
            'only_declared_and_verified_scalar_fields_credit':True,
            'no_automatic_causal_or_loss_promotion':True}


def render(result):
    out=['RISU keyed array coverage | exact values and typed identities; no positional fallback']
    for row in result['cases']:
        out.append(row['case_id']+': '+', '.join(g['id']+'='+g['status']+'('+str(g['matched_rows'])+' rows)' for g in row['groups']))
    return '\n'.join(out)+'\n'
