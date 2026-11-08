"""P6-B10 development regressions on original B9 actual-upstream captured results.

The B9 CYAN760 and CYAN785 misses become DEVELOPMENT cases after B9 scoring.
Never include these in B10's three-family independent holdout denominator.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from risu_display_fidelity import verify_display_fidelity

CASES=('CYAN760','CYAN785')

def check_row(path:Path,family:str)->dict:
    doc=json.loads(path.read_text())
    if doc.get('schema')!='risu-p6b9-cyan-authentic-framework-v1' or doc.get('family')!=family:
        raise ValueError('Wrong pinned B9 source capture')
    if doc.get('component_origin')!='ACTUAL_UPSTREAM_SOURCE_UNIT_EXECUTION_NOT_WIRE':
        raise ValueError('Not genuine B9 source component evidence')
    return doc

def make_trace(doc:dict,family:str,rev:str,out:Path)->dict:
    if family=='CYAN760':
        prefix='Error: '
        pointer='/error/message'
        mode='markdown-literal'
        err=True
    else:
        prefix='**effectiveQuery:** '
        pointer='/effectiveQuery'
        mode='code-copy'
        err=False
    rules=[];tools=[];rows=[]
    for index,kind in enumerate(('issue','control'),2):
        name='b9_dev_'+kind
        rules.append({'id':kind,'tool':name,'pointer':pointer,
            'line_prefix':prefix,'mode':mode,'is_error':err})
        tools.append({'name':name,'inputSchema':{'type':'object'},
            'outputSchema':{'type':'object'}})
        rows.extend([
            {'jsonrpc':'2.0','id':index,'method':'tools/call',
             'params':{'name':name,'arguments':{}}},
            {'jsonrpc':'2.0','id':index,'result':doc[kind]}])
    trace=[
        {'jsonrpc':'2.0','id':1,'method':'tools/list','params':{}},
        {'jsonrpc':'2.0','id':1,'result':{'tools':tools}}
    ]+rows
    path=out/(family+'_'+rev+'.jsonl')
    path.write_text(''.join(json.dumps(row,ensure_ascii=False)+'\n' for row in trace))
    return {'schema':'risu-display-fidelity-contract-v1','rules':rules}

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--source',required=True,type=Path)
    p.add_argument('--out',required=True,type=Path)
    a=p.parse_args()
    a.out.mkdir(parents=True,exist_ok=True)
    result={'schema':'risu-p6b10-b9-development-regressions-v1',
            'dataset_role':'DEVELOPMENT_ONLY_NOT_NEW_INDEPENDENT_HOLDOUT',
            'families':[]}
    for family in CASES:
        old=check_row(a.source/family/'old.json',family)
        fixed=check_row(a.source/family/'fixed.json',family)
        seen={}
        for rev,doc in [('old',old),('fixed',fixed)]:
            contract=make_trace(doc,family,rev,a.out)
            rep=verify_display_fidelity(a.out/(family+'_'+rev+'.jsonl'),contract)
            (a.out/(family+'_'+rev+'_risu.json')).write_text(json.dumps(rep,indent=2)+'\n')
            seen[rev]=rep
        def h(s):return hashlib.sha256(s.encode()).hexdigest()[:12]
        old_ids={r['rule_sha256'] for r in seen['old']['findings']}
        fixed_ids={r['rule_sha256'] for r in seen['fixed']['findings']}
        passed=(h('issue') in old_ids and h('issue') not in fixed_ids
            and h('control') not in old_ids|fixed_ids
            and seen['old']['summary']['unverified']==0
            and seen['fixed']['summary']['unverified']==0)
        result['families'].append({'family':family,
            'old_issue_findings':int(h('issue') in old_ids),
            'fixed_issue_findings':int(h('issue') in fixed_ids),
            'normal_control_clean':h('control') not in old_ids|fixed_ids,
            'regression_pass':passed,
            'source_class':'PINNED_B9_SOURCE_RECORD_WITH_RECONSTRUCTED_JSONRPC'})
    (a.out/'dev_summary.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
    if not all(x['regression_pass'] for x in result['families']):
        raise SystemExit('B10 development regression did not pass, do not change independent scores')

if __name__=='__main__':main()
