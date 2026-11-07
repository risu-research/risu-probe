"""Run identical 10 pinned public repositories against unmodified P5-E and P6-A wheels.

Only static read-only risu-probe check commands are used; no source imports,
server processes, project setup, network tests or hooks.
"""
from __future__ import annotations
import argparse,hashlib,json,os,platform,subprocess,time,statistics
from pathlib import Path

def checkout(repo,root):
    name=repo['name'];commit=repo['commit'];dest=root/name
    assert len(commit)==40 and all(x in '0123456789abcdef' for x in commit)
    if dest.exists():raise RuntimeError('Existing repo target: '+str(dest))
    dest.mkdir(parents=True)
    for args in (
      ['git','init','-q',str(dest)],
      ['git','-C',str(dest),'remote','add','origin',f"https://github.com/{repo['repository']}.git"],
      ['git','-c','core.hooksPath=/dev/null','-c','core.autocrlf=false','-C',str(dest),'fetch','--no-tags','--depth','1','origin',commit],
      ['git','-c','core.hooksPath=/dev/null','-c','core.autocrlf=false','-C',str(dest),'checkout','-q','--detach','FETCH_HEAD'],
    ):
        p=subprocess.run(args,capture_output=True,text=True,timeout=220)
        if p.returncode:raise RuntimeError(f'{name} checkout failed: {p.stderr[-1500:]}')
    head=subprocess.check_output(['git','-C',str(dest),'rev-parse','HEAD'],text=True).strip()
    assert head==commit
    return dest

def call(cli:Path,source:Path):
    env=os.environ.copy();env['PYTHONUTF8']='1';env['PYTHONDONTWRITEBYTECODE']='1'
    t=time.perf_counter()
    p=subprocess.run([str(cli),'check',str(source),'--format','json'],capture_output=True,
                     text=True,encoding='utf-8',errors='replace',timeout=160,env=env)
    ms=round((time.perf_counter()-t)*1000,3)
    if p.returncode!=0:raise AssertionError(f'CLI failed rc={p.returncode}: {p.stderr[-1200:]}')
    try:obj=json.loads(p.stdout)
    except json.JSONDecodeError as e:raise RuntimeError('Malformed JSON CLI output: '+p.stdout[-400:]) from e
    # Do not strip rules, locations, evidence, coverage, or ordering.
    obj.pop('version',None)
    summary=obj['summary']
    eligible=int(summary['python_parsed'])+int(summary['openapi_parsed'])
    complete=(eligible>0 and int(summary['unverified'])==0 and not obj.get('unverified'))
    return obj,ms,complete

def check(manifest:Path,baseline:Path,candidate:Path,root:Path,out:Path):
    data=json.loads(manifest.read_text());repos=data['repositories']
    assert len(repos)==10 and len({r['name'] for r in repos})==10
    assert len({r['commit'] for r in repos})==10
    root.mkdir(parents=True,exist_ok=True);results=[]
    for r in repos:
        d=checkout(r,root)
        old,t0,oldcomplete=call(baseline,d)
        new,t1,newcomplete=call(candidate,d)
        if old!=new:
            out.parent.mkdir(parents=True,exist_ok=True)
            fail=out.with_name(r['name']+'-DIFFERENCE.json')
            fail.write_text(json.dumps({'old':old,'new':new},indent=2,sort_keys=True))
            raise AssertionError('FULL_VERDICT_DRIFT '+r['name']+' '+str(fail))
        if not(oldcomplete and newcomplete):raise AssertionError('INCOMPLETE_COVERAGE '+r['name'])
        digest=hashlib.sha256(json.dumps(old,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()).hexdigest()
        results.append({'repo':r['name'],'github':r['repository'],'commit':r['commit'],
                        'exact_normalized_json_equal':True,'complete_both':True,'normalized_report_sha256':digest,
                        'base_time_ms':t0,'candidate_time_ms':t1,
                        'findings':{'suspected':len(old.get('suspected',[])),'confirmed':len(old.get('confirmed',[])),'unverified':len(old.get('unverified',[]))}})
        print('P6A_PINNED_REPO_PARITY_PASS',r['name'],digest,flush=True)
    report={'schema':'risu-p6a-rebuilt-product-exact-ten-repo-parity-v1',
            'platform':platform.system(),'python':platform.python_version(),'pinned_source_manifest_sha256':hashlib.sha256(manifest.read_bytes()).hexdigest(),
            'baseline':'P5-E CI wheel 0.9.20.dev0','candidate':'P6-A rebuilt from checked-in source 0.9.20.dev0',
            'total':len(results),'exact_verdict_equal':sum(r['exact_normalized_json_equal'] for r in results),
            'complete_source_scan':sum(r['complete_both'] for r in results),
            'results':results,'caveat':'10 fixed public repositories, no scanned user code executed. No claim of representative defect detection or speed advantage.'}
    out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print('P6A_TEN_REPO_ALL_FIELD_VERDICT_PARITY_PASS',report['platform'],len(results),flush=True)
    return report

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--manifest',type=Path,required=True);p.add_argument('--baseline',type=Path,required=True)
    p.add_argument('--candidate',type=Path,required=True);p.add_argument('--checkouts',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
    a=p.parse_args();check(a.manifest,a.baseline,a.candidate,a.checkouts,a.out)
