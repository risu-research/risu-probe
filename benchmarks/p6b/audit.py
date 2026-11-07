"""P6-B independent offline score and provenance auditor."""
import argparse,hashlib,json
from pathlib import Path
from run import blobhash,summarize

def audit(manifest_path,report_path,sources):
    raw=Path(manifest_path).read_bytes()
    manifest=json.loads(raw)
    report=json.loads(Path(report_path).read_bytes())
    assert report['schema']=='risu-p6b-public-actual-source-benchmark-v1'
    assert report['manifest_sha256']==hashlib.sha256(raw).hexdigest()
    assert report['source']=='PINNED_PUBLIC_GIT_BLOBS'
    assert report['upstream_executed'] is False and report['third_party_modules_imported'] is False
    assert report['development_case_tuned'] is True
    declared={x['id']:x for x in manifest['cases']}
    assert len(declared)==len(report['cases'])==7
    assert {x['id'] for x in report['cases']}==set(declared)
    for row in report['cases']:
        case=declared[row['id']]
        for key in ('id','label','split','repo','commit','path','git_blob','target_rule','issue','repair_pr'):
            assert row[key]==case.get(key),(row['id'],'mislabelled',key)
        ext=Path(case['path']).suffix
        f=Path(sources)/('case-'+case['id'])/('upstream'+ext)
        assert f.is_file() and not f.is_symlink(),('missing',case['id'])
        content=f.read_bytes()
        assert blobhash(content)==case['git_blob'],('hash-tamper',case['id'])
        assert hashlib.sha256(content).hexdigest()==row['original_sha256']
        for key in ('baseline','candidate'):
            r=row[key]
            assert r['target_detected'] is bool(case.get('target_rule') and any(
                z['rule_id']==case['target_rule'] for z in r['findings']))
            if case['label']=='out_of_scope':
                assert r['status']=='OUT_OF_SCOPE_TYPESCRIPT' and not r['findings']
            else:
                assert r['parsed']==1 and r['unverified']==0
                assert all(x['verdict']=='SUSPECTED_LOSS' and x['confidence']=='STATIC_HYPOTHESIS'
                           for x in r['findings'])
    for key in ('baseline','candidate'):
        assert report['metrics'][key]==summarize(report['cases'],key)
    assert report['metrics']['baseline']['detected']==0
    assert report['metrics']['candidate']['detected']==1
    assert report['metrics']['candidate']['missed']==2
    assert report['metrics']['candidate']['false_alarms_on_repairs']==0
    return {'status':'PASS','cases':7,'metrics':report['metrics'],'manifest_sha256':report['manifest_sha256']}

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--manifest',type=Path,required=True)
    p.add_argument('--report',type=Path,required=True)
    p.add_argument('--sources',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    report=audit(a.manifest,a.report,a.sources)
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print('RISU_P6B_INDEPENDENT_GIT_BLOB_AND_METRIC_AUDIT_PASS',report['metrics'])
if __name__=='__main__':main()
