"""B10 independent 3-family score reconciler: no cherry-picked omission, no double credit."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

EXPECTED={'GEONAMES28':'RMC507','OPENALEX128':'RMC507','MITRECWE16':'RMC508'}

def audit(manifest:Path,score_paths:dict[str,Path])->dict:
    raw=manifest.read_bytes()
    selected=json.loads(raw)
    assert selected['schema']=='risu-p6b10-prelocked-new-display-heldout-v1'
    assert selected['engine_trace_blob']=='f722cd7fdc380e04a3416ba5defba99f249af950'
    assert selected['engine_display_blob']=='f4f6dc4241ce4cfed355f9dddae2307e642b35ad'
    cases=selected['selected']
    ids=[x['id'] for x in cases]
    if len(ids)!=3 or set(ids)!=set(EXPECTED) or len(set(ids))!=3:
        raise ValueError('Prelocked candidate list was modified')
    if set(score_paths)-set(ids):
        raise ValueError('Score for a case outside original selection')
    rows=[]
    for c in cases:
        id=c['id']
        row={'family':id,'issue':c['issue'],'source_repo':c['repository'],
             'original_stdio_captured':False,
             'same_publisher_as_other_cases':True,
             'status':'UNVERIFIED_NOT_EXECUTED','relevant_detection':None,
             'normal_control_passed':None}
        if id in score_paths:
            data=score_paths[id].read_bytes()
            d=json.loads(data)
            if d.get('family')!=id or d.get('schema')!='risu-p6b10-independent-public-source-score-v1' or d.get('role')!='PRELOCKED_NEW_SOURCE_HELDOUT':
                raise ValueError('Wrong family/role/schema for recorded independent result')
            ok=d.get('original_upstream_bugfix_reproduced') is True
            normal=d.get('normal_control_passed') is True
            find=d.get('old_findings')==[EXPECTED[id]] and d.get('fixed_findings')==[]
            detection=d.get('relevant_frozen_rule_detected') is True
            row.update({
                'status':'VERIFIED_REPRODUCTION' if ok and normal else 'UNVERIFIED_OR_FAILED_CONTROL',
                'normal_control_passed':normal,
                'relevant_detection':(bool(detection and find) if ok and normal else None),
                'source_score_sha256':hashlib.sha256(data).hexdigest()
            })
        rows.append(row)
    verified=[x for x in rows if x['status']=='VERIFIED_REPRODUCTION']
    detected=[x for x in verified if x['relevant_detection']]
    return {'schema':'risu-p6b10-three-family-independent-ledger-v1',
            'manifest_sha256':hashlib.sha256(raw).hexdigest(),
            'locked_trace_blob':selected['engine_trace_blob'],
            'locked_display_blob':selected['engine_display_blob'],
            'summary':{'preselected':len(cases),
                       'source_score_files':len(score_paths),
                       'reproduced_with_controls':len(verified),
                       'relevant_detections':len(detected),
                       'confirmed_misses':len(verified)-len(detected),
                       'unverified_or_missing':len(cases)-len(verified),
                       'population_recall':'NOT_ESTIMABLE_NONRANDOM_SAME_PUBLISHER',
                       'population_false_positive_rate':'NOT_ESTIMABLE_NARROW_NORMAL_CONTROLS'},
            'rows':rows,
            'limitations':['Three different repositories maintained by the same publisher, not three vendor-independent measurements',
                           'Actual upstream helper functions executed; MCP JSON-RPC output envelopes reconstructed by evaluator',
                           'Single narrow normal control per family; cannot estimate real-world false positives',
                           'Legacy known CYAN760/CYAN785 development cases explicitly excluded',
                           'Go 1139 original stdio is provenance upgrade of B9 and separately excluded']}
def main():
    p=argparse.ArgumentParser()
    p.add_argument('--manifest',type=Path,default=Path('benchmarks/p6b10/prelocked_three_heldout.json'))
    p.add_argument('--score',action='append',default=[])
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    data={}
    for pair in a.score:
        id,sep,path=pair.partition('=')
        if not sep or id in data:raise SystemExit('Unique FAMILY=FILE required')
        data[id]=Path(path)
    result=audit(a.manifest,data)
    a.output.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps(result['summary'],indent=2,sort_keys=True))
    if result['summary']['source_score_files']!=3:
        raise SystemExit('Three prelocked results were not all available')
if __name__=='__main__':
    main()
