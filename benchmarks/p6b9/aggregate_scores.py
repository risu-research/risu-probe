"""P6-B9 cross-language heldout scorebook. Never silently drop a preregistered case.

Consumes independent run score JSON, not output copied from this source file. This
aggregator does not execute third-party libraries or modify detector rules.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

SCHEMA = {
 'PHP673':('risu-p6b9-php673-adjudicated-result-v1','upstream_reproduction','VERIFIED_BUG_FIX','detected_family','source_normal_controls'),
 'GO1139':('risu-p6b9-go1139-independently-scored-v1','upstream_bugfix_reproduced',True,'detected_family','normal_control_pass'),
 'PROXY253':('risu-p6b9-proxy253-paired-score-v1','reproduced',True,'diagnostic_detected','normal_initial_page_control_pass'),
 'CYAN760':('risu-p6b9-cyan-independent-score-v1','upstream_bugfix_reproduced',True,'relevant_auto_detected','normal_control_pass'),
 'CYAN785':('risu-p6b9-cyan-independent-score-v1','upstream_bugfix_reproduced',True,'relevant_auto_detected','normal_control_pass'),
 'RUST137':('risu-p6b9-rust137-source-scored-v1','upstream_source_boundary_bugfix_reproduced',True,'loss_detected_by_risu_on_adapter_record','normal_control_pass'),
 'AG23262':('risu-p6b9-ag23262-eval-v1','upstream_bugfix_reproduced',True,'incomplete_catalog_symptom_detected','single_page_normal_control'),
}
DIRECT={'PHP673','GO1139','RUST137'}
DIAGNOSTIC={'PROXY253','AG23262'}
BEHAVIOR={'CYAN760','CYAN785'}

def audit(manifest:Path, supplied:dict[str,Path])->dict:
    b=manifest.read_bytes()
    m=json.loads(b)
    if m.get('schema')!='risu-p6b9-precommitted-independent-bugfix-set-v1':
        raise ValueError('Unrecognized immutable selected-family manifest')
    cases=m['cases']
    ids={x['id'] for x in cases}
    if len(cases)!=7 or len(ids)!=7 or ids!=set(SCHEMA) or m['family_count_preselected']!=7:
        raise ValueError('Selected family list does not match frozen register')
    if not set(supplied).issubset(ids):
        raise ValueError('Result for unselected family')
    rows=[]
    for case in cases:
        ident=case['id']
        row={'family':ident,'source_repository':case['repo'],
             'original_issue':case['issue'],'selected_before_execution':True,
             'component_evidence_kind':case['evidence_form'],
             'status':'UNVERIFIED_NOT_EXECUTED','independent_detection':None,
             'normal_controls_passed':None,'detection_evidence_class':None}
        if ident not in supplied:
            rows.append(row);continue
        raw=supplied[ident].read_bytes()
        score=json.loads(raw)
        expected,truth,truth_ok,detector,normal=SCHEMA[ident]
        if score.get('schema')!=expected or score.get('family')!=ident or score.get('role')!='PRELOCKED_NEW_INDEPENDENT_FAMILY':
            raise ValueError('Score schema, family or prior-selection label invalid: '+ident)
        normal_value=score.get(normal)
        controls_pass=(all(normal_value.values()) if type(normal_value) is dict else normal_value is True)
        reproduced=(score.get(truth)==truth_ok)
        detected=score.get(detector)
        if type(detected) is not bool:
            raise ValueError('Detection assessment missing or nonboolean: '+ident)
        row['source_score_sha256']=hashlib.sha256(raw).hexdigest()
        row['normal_controls_passed']=bool(controls_pass)
        row['status']=('VERIFIED_REPRODUCTION' if reproduced and controls_pass else
                       'UNVERIFIED_FAILED_CAUSAL_OR_NORMAL_CONTROL')
        row['independent_detection']=(detected if reproduced and controls_pass else None)
        row['detection_evidence_class']=('DIRECT_ADAPTER_CONTRACT_MISMATCH' if ident in DIRECT else
            'INCOMPLETE_OR_DUPLICATE_CATALOG_DIAGNOSTIC' if ident in DIAGNOSTIC else
            'OUT_OF_SCHEMA_TEXT_SEMANTICS')
        rows.append(row)
    eligible=[x for x in rows if x['status']=='VERIFIED_REPRODUCTION']
    detected=[x for x in eligible if x['independent_detection']]
    missed=[x for x in eligible if not x['independent_detection']]
    return {
      'schema':'risu-p6b9-independent-heldout-ledger-v1',
      'frozen_engine_git_blob':m['engine_frozen_blob_git_sha1'],
      'selection_manifest_sha256':hashlib.sha256(b).hexdigest(),
      'origin_integrity':'PINNED_PUBLIC_SOURCE_ACTIONS_UNATTESTED_ARTIFACT_SCORES',
      'summary':{
        'families_preselected':len(rows),'families_scored':len(supplied),
        'verified_reproduced_families':len(eligible),
        'not_verified_or_not_executed':len(rows)-len(eligible),
        'issue_relevant_detected_families':len(detected),
        'observed_direct_adapter_mismatches':sum(x['family'] in DIRECT for x in detected),
        'observed_incomplete_catalog_diagnostics':sum(x['family'] in DIAGNOSTIC for x in detected),
        'reproduced_families_missed':len(missed),
        'normal_controls_failed_families':sum(x['normal_controls_passed'] is False for x in rows),
        'ecosystem_precision':'NOT_ESTIMABLE_FROM_PRESELECTED_ISSUE_FAMILIES',
        'false_positive_rate':'NOT_ESTIMABLE_FROM_FIXED_PAIRS_AND_HAND_SELECTED_CONTROLS'
      },
      'case_rows':rows,
      'limitations':[
        'Public upstream issues were selected nonrandomly; no ecosystem-level recall, precision, specificity or calibration claim',
        'Diagnostic messages and adapter projections are not proof of causal source-level defects or full live protocol',
        'Every unexecuted or failed reproduction remains in the selected seven-case registry',
        'Source identity is verified by Git commit and blob checks in source workflows; an artifact digest is an identity anchor, not a cryptographic signature of execution',
      ]
    }

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--manifest',type=Path,default=Path('benchmarks/p6b9/prelocked_seven_families.json'))
    ap.add_argument('--score',action='append',default=[],help='FAMILY=/path/to/score.json (repeat)')
    ap.add_argument('--out',type=Path)
    ap.add_argument('--require-all',action='store_true')
    args=ap.parse_args()
    supplied={}
    for item in args.score:
        ident, sep, path=item.partition('=')
        if not sep or ident in supplied:
            ap.error('Pass a unique FAMILY=score.json per score')
        supplied[ident]=Path(path)
    result=audit(args.manifest,supplied)
    output=json.dumps(result,indent=2,sort_keys=True)+'\n'
    if args.out:
        with args.out.open('x',encoding='utf-8') as f:f.write(output)
    else:
        print(output,end='')
    if args.require_all and result['summary']['families_scored']!=7:
        raise SystemExit(2)

if __name__=='__main__':
    main()
