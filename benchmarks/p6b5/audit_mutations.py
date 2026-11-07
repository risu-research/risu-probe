"""Independently audit only PUBLIC synthetic mutations based on raw SDK stdio."""
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path

def audit(directory:Path)->dict:
    manifest=json.loads((directory/'mutation_manifest.json').read_text())
    assert manifest['schema']=='risu-p6b5-public-mutations-v1'
    assert manifest['origin']=='PUBLIC_OWN_SYNTHETIC_TRANSFORMS_NOT_EXTERNAL_DEFECTS'
    frozen={'normal':([],[]),'missing':(['RMC501'],[]),'wrong_type':(['RMC502'],[]),
      'invalid_schema':(['RMC503'],[]),'legacy_root':(['RMC504'],[]),
      'truncated':([],['MISSING_RESPONSE']),
      'declared_protocol_conflict':([],['PROTOCOL_VERSION_CONFLICT'])}
    assert {x['name'] for x in manifest['cases']}==set(frozen) and len(manifest['cases'])==7
    for case in manifest['cases']:
        name=case['name']
        expected_rules,expected_unverified=frozen[name]
        assert case['expected_rules']==expected_rules
        assert case['expected_unverified']==expected_unverified
        data=(directory/(name+'.jsonl')).read_bytes()
        assert case['input_sha256']==hashlib.sha256(data).hexdigest()
        result=(directory/(name+'_report.json')).read_bytes()
        assert case['report_sha256']==hashlib.sha256(result).hexdigest()
        report=json.loads(result)
        assert report['capture_sha256']==case['input_sha256']
        got_rules=sorted(x['rule_id'] for x in report['findings'])
        assert got_rules==sorted(expected_rules),(name,got_rules,expected_rules)
        gaps={x['code'] for x in report['unverified']}
        assert set(expected_unverified)<=gaps,(name,gaps,expected_unverified)
        assert report['origin_integrity']=='UNATTESTED_LOCAL_CAPTURE'
        assert 'P6B5_SYNTHETIC_VALUE_NEVER_ECHO_SECRET' not in result.decode()
        if name=='normal':
            assert report['summary']['structured_values_schema_checked']==2
            assert report['summary']['findings']==0
        if name=='declared_protocol_conflict':
            assert report['session_protocols'][0]['effective_protocol']=='unknown'
    return {'status':'PASS','synthetic_control_cases':len(frozen),
            'intentional_mismatches_detected':4,'normal_and_incomplete_controls_not_flagged':3,
            'independent_external_defects_found':0,'not_general_false_positive_rate':True}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--dir',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    x=audit(a.dir)
    a.out.write_text(json.dumps(x,indent=2,sort_keys=True)+'\n')
    print('P6B5_CONTROLLED_MUTATION_AUDIT',x,flush=True)
