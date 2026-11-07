"""P6-B frozen public Git source defect benchmark. Never executes upstream code."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ALLOWED={'PrefectHQ/fastmcp','langchain-ai/langchain','psf/requests','modelcontextprotocol/typescript-sdk'}
LABELS={'known_defect','official_repaired','unlabeled_background','out_of_scope'}

def blobhash(data):
    return hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()

def git(root,*argv):
    env={**os.environ,'GIT_TERMINAL_PROMPT':'0','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':os.devnull}
    cp=subprocess.run(['git','-c','core.hooksPath=/dev/null',*argv],cwd=root,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,timeout=180)
    if cp.returncode:raise RuntimeError('PUBLIC_GIT_FETCH_FAILED: '+cp.stderr.decode('utf-8','replace')[-400:])
    return cp.stdout

def scan(cli,src):
    cp=subprocess.run([str(cli),'check',str(src),'--format','json'],capture_output=True,timeout=50)
    try:report=json.loads(cp.stdout)
    except Exception as e:raise RuntimeError('Installed RISU CLI did not produce JSON: '+cp.stderr.decode(errors='replace')[-300:]) from e
    stats=report.get('summary',{})
    assert cp.returncode==0 and stats.get('python_parsed')==1 and stats.get('unverified')==0,('INCOMPLETE_SCAN',stats,cp.returncode)
    findings=[{'rule_id':x['rule_id'],'line':x['line'],'verdict':x['verdict'],
               'confidence':x['confidence']} for x in report.get('suspected',[])]
    assert all(x['verdict']=='SUSPECTED_LOSS' and x['confidence']=='STATIC_HYPOTHESIS' for x in findings)
    return {'status':report['status'],'findings':findings,'parsed':stats['python_parsed'],
            'unverified':stats['unverified'],'report_sha256':hashlib.sha256(cp.stdout).hexdigest()}

def summarize(rows,which):
    positive=[r for r in rows if r['label']=='known_defect']
    repaired=[r for r in rows if r['label']=='official_repaired']
    unsupported=[r for r in rows if r['label']=='out_of_scope']
    unlabeled=[r for r in rows if r['label']=='unlabeled_background']
    assert (len(positive),len(repaired),len(unsupported),len(unlabeled))==(3,2,1,1)
    hit=sum(r[which]['target_detected'] for r in positive)
    false_hit=sum(r[which]['target_detected'] for r in repaired)
    return {'positive_cases':len(positive),'detected':hit,'missed':len(positive)-hit,
            'recall_on_this_selected_set':round(hit/len(positive),3),
            'repaired_cases':len(repaired),'false_alarms_on_repairs':false_hit,
            'repaired_case_false_alarm_rate':round(false_hit/len(repaired),3),
            'out_of_scope_excluded':len(unsupported),'unlabeled_excluded':len(unlabeled)}

def main():
    p=argparse.ArgumentParser()
    for flag in ('manifest','baseline-cli','candidate-cli','scratch','out'):
        p.add_argument('--'+flag,required=True,type=Path)
    a=p.parse_args()
    raw=a.manifest.read_bytes()
    manifest=json.loads(raw)
    assert manifest['schema']=='risu-p6b-predeclared-public-source-benchmark-v1'
    cases=manifest['cases']
    assert len(cases)==7 and len({c['id'] for c in cases})==7
    assert all(c['repo'] in ALLOWED and c['label'] in LABELS for c in cases)
    assert not a.scratch.exists()
    a.scratch.mkdir(parents=True)
    rows=[]
    for index,case in enumerate(cases):
        # Each pinned source gets its own shallow clone. Re-fetching multiple
        # non-ancestor SHAs into one shallow checkout can corrupt shallow state
        # and cause intermittent "shallow file has changed" Git errors.
        repo=case['repo']
        root=a.scratch/('git_'+str(index))
        root.mkdir()
        git(root,'init','-q')
        git(root,'remote','add','origin','https://github.com/'+repo+'.git')
        commit=case['commit']
        blob=case['git_blob']
        assert len(commit)==len(blob)==40
        assert all(ch in '0123456789abcdef' for ch in commit+blob)
        path=Path(case['path'])
        assert not path.is_absolute() and '..' not in path.parts and path.suffix in ('.py','.ts')
        git(root,'fetch','--no-tags','--depth','1','origin',commit)
        content=git(root,'show',commit+':'+case['path'])
        assert len(content)<512000 and blobhash(content)==blob,('UPSTREAM_BLOB_MISMATCH',case['id'])
        file=a.scratch/('case-'+case['id'])/('upstream'+path.suffix)
        file.parent.mkdir()
        file.write_bytes(content)
        item={k:case.get(k) for k in ('id','label','split','repo','commit','path','git_blob','target_rule','issue','repair_pr')}
        item['original_sha256']=hashlib.sha256(content).hexdigest()
        for label,cli in (('baseline',a.baseline_cli),('candidate',a.candidate_cli)):
            if case['label']=='out_of_scope':
                result={'status':'OUT_OF_SCOPE_TYPESCRIPT','findings':[],'parsed':0,'unverified':1}
            else:
                result=scan(cli,file)
            result['target_detected']=bool(case['target_rule'] and
                any(f['rule_id']==case['target_rule'] for f in result['findings']))
            item[label]=result
        rows.append(item)
        print('P6B_CASE',item['id'],'baseline',item['baseline']['target_detected'],
              'candidate',item['candidate']['target_detected'],flush=True)
    by={r['id']:r for r in rows}
    assert by['F5030-before']['baseline']['target_detected'] is False
    assert by['F5030-before']['candidate']['target_detected'] is True
    assert by['F5030-fixed']['candidate']['target_detected'] is False
    assert not by['F3717-before']['candidate']['target_detected']
    assert not by['LC40471-open']['candidate']['target_detected']
    metrics={k:summarize(rows,k) for k in ('baseline','candidate')}
    output={'schema':'risu-p6b-public-actual-source-benchmark-v1',
       'manifest_sha256':hashlib.sha256(raw).hexdigest(),
       'source':'PINNED_PUBLIC_GIT_BLOBS','upstream_executed':False,
       'third_party_modules_imported':False,'development_case_tuned':True,
       'metrics':metrics,'cases':rows,
       'limits':'Three selected real defect sources, two merged repairs; one trained rule, two holdout misses; no population estimate.'}
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(output,indent=2,sort_keys=True)+'\n')
    print('P6B_REAL_SOURCE_DETECTION_SCORES',json.dumps(metrics,sort_keys=True))
if __name__=='__main__':main()
