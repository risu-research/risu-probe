"""P6-B10 independent read-only aggregator of three immutable external source scores.

Separate the original 3 selected independent families from two B9 development cases.
No detector edits, no third-party source execution, no inferred broad recall rate.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

SCHEMAS={
 'GEONAMES28':'risu-p6b10-real-upstream-module-score-v1',
 'FDIC25':'risu-p6b10-real-upstream-module-score-v1',
 'CLINICAL177':'risu-p6b10-clinical177-pair-score-v1',
}
def aggregate(manifest:Path, files:dict[str,Path])->dict:
    raw=manifest.read_bytes()
    m=json.loads(raw)
    if m.get('schema')!='risu-p6b10-display-fidelity-prelocked-v1':
        raise ValueError('Wrong selection register')
    expected=[v['id'] for v in m['families']]
    if expected!=['GEONAMES28','CLINICAL177','FDIC25']:
        raise ValueError('Selected families changed')
    if not set(files).issubset(set(expected)):
        raise ValueError('Score from unselected family')
    rows=[]
    for family in expected:
        row={'family':family,'selection_prelocked':True,'status':'UNVERIFIED_NOT_EXECUTED',
             'frozen_rule_detected':None,'normal_control_pass':None}
        if family not in files:
            rows.append(row)
            continue
        content=files[family].read_bytes()
        s=json.loads(content)
        if s.get('schema')!=SCHEMAS[family] or s.get('family')!=family or s.get('role')!='PRELOCKED_NEW_INDEPENDENT_FAMILY':
            raise ValueError('Unexpected source score schema/family/role')
        if s.get('evidence_transport') not in ('ADAPTER_RECONSTRUCTED_NOT_MCP_WIRE','TEST_ADAPTER_JSONRPC_NOT_WIRE'):
            raise ValueError('Invalid observation kind')
        if type(s.get('source_defect_independently_reproduced')) is not bool or type(s.get('normal_control_pass')) is not bool or type(s.get('frozen_rule_detected')) is not bool:
            raise ValueError('Required boolean score absent')
        passed=s['source_defect_independently_reproduced'] and s['normal_control_pass']
        row.update({'status':'VERIFIED_SOURCE_REPRODUCTION' if passed else 'UNVERIFIED_CAUSAL_OR_CONTROL',
                    'frozen_rule_detected':s['frozen_rule_detected'] if passed else None,
                    'normal_control_pass':s['normal_control_pass'],
                    'source_score_sha256':hashlib.sha256(content).hexdigest(),
                    'source_execution':s['source_code_execution'],
                    'evidence_transport':s['evidence_transport'],
                    'old_fidelity_findings':s['old_fidelity_findings'],
                    'fixed_fidelity_findings':s['fixed_fidelity_findings']})
        rows.append(row)
    qualified=[v for v in rows if v['status']=='VERIFIED_SOURCE_REPRODUCTION']
    detected=[v for v in qualified if v['frozen_rule_detected'] is True]
    return {
      'schema':'risu-p6b10-three-family-independent-source-ledger-v1',
      'manifest_sha256':hashlib.sha256(raw).hexdigest(),
      'frozen_detector_module_git_blob':'8bc96f64eba96a314479dfaea17af46b38e1ad0a',
      'dataset_role':'PRELOCKED_NEW_EXTERNAL_SOURCE_FAMILIES_ONLY',
      'summary':{
        'families_preselected':len(expected),
        'families_scored':len(files),
        'verified_source_reproductions':len(qualified),
        'selected_family_detected':len(detected),
        'verified_family_misses':len(qualified)-len(detected),
        'unverified_or_unexecuted':len(expected)-len(qualified),
        'normal_control_failed_families':sum(v['normal_control_pass'] is False for v in rows),
        'population_recall':'NOT_ESTIMABLE',
        'population_false_positive_rate':'NOT_ESTIMABLE',
      },
      'cases':rows,
      'limits':[
        'Three nonrandomly selected published issue families, not ecosystem recall',
        'Reproduced old and official fixed source module with synthetic inputs, not complete live MCP wire',
        'Input contract maps are explicitly supplied, not inferred from unknown tool semantics',
        'Evidence artifacts originate from pinned GitHub Actions and are not cryptographic attestation',
        'Old B9 CYAN760 and CYAN785 are development cases and excluded from these metrics',
      ]
    }

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--manifest',type=Path,default=Path('benchmarks/p6b10/prelocked_three_display_fidelity.json'))
    p.add_argument('--score',action='append',default=[])
    p.add_argument('--out',required=True,type=Path)
    p.add_argument('--require-all',action='store_true')
    args=p.parse_args()
    files={}
    for item in args.score:
        family,sep,path=item.partition('=')
        if not sep or family in files:
            raise ValueError('Pass unique FAMILY=/path for source score')
        files[family]=Path(path)
    result=aggregate(args.manifest,files)
    args.out.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    print(json.dumps(result['summary'],indent=2,sort_keys=True))
    if args.require_all and result['summary']['families_scored'] != 3:
        raise SystemExit('Missing preregistered source score')
    if args.require_all and (result['summary']['verified_source_reproductions']!=3
       or result['summary']['selected_family_detected']!=3
       or result['summary']['normal_control_failed_families']!=0):
        raise SystemExit('Frozen source ledger does not meet qualified result')

if __name__=='__main__':main()
