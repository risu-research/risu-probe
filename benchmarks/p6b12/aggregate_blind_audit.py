"""P6-B12 cross-artifact, prelocked first-pass ledger with a postfreeze rescore.

Keeps unverified and failed cases in denominator; no inferred unknown bugs.
The frozen native original stdout and core RISU outputs are never rewritten.
"""
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path

FROZEN={
    'src/risu_mcp_trace.py':'9f017ca0344d94cf54bd0229ddb14d4f586101c8',
    'src/risu_display_fidelity.py':'6785b2ed912d3e9a41dda956da537dc2e5f4f8e3'}
EXPECTED={'FS','MEM','ALCHEMY','GO','SQLITE'}

def audit(manifest:Path,records:dict[str,Path])->dict:
    raw=manifest.read_bytes()
    info=json.loads(raw)
    chosen=info.get('cases')
    if info.get('frozen_analyzer_blobs')!=FROZEN or not isinstance(chosen,list):
        raise ValueError('Frozen source or baseline identity modified')
    if len(chosen)!=5 or {x.get('id') for x in chosen}!=EXPECTED:
        raise ValueError('First-pass selected case set changed')
    if len({x['org'] for x in chosen})!=4 or len([x for x in chosen if x['selection']=='BLIND'])!=4:
        raise ValueError('Publisher/blind denominator changed')
    if set(records)-EXPECTED:raise ValueError('Nonpreselected candidate injected')
    rows=[]
    for case in chosen:
        ident=case['id']
        row={'case':ident,'repo':case['repository'],'commit':case['commit'],
             'selection':case['selection'],'status':'UNVERIFIED_MISSING_CAPTURE',
             'initial_core_findings':None,'initial_oracle_mismatches':None,
             'rescored_oracle_mismatches':None,'rescored_oracle_unverified':None,
             'hypothesized_new_unreported_bug':False}
        if ident in records:
            root=records[ident]
            origin=json.loads((root/'capture/origin.json').read_text())
            raw_trace=(root/'capture/original_stdio.jsonl').read_bytes()
            initial=json.loads((root/'first_pass_score.json').read_text())
            rescore=json.loads((root/'postfreeze_score.json').read_text())
            scanner=json.loads((root/'risu.json').read_text())
            if origin.get('case')!=ident or origin.get('source_commit')!=case['commit']:
                raise ValueError('Wrong pinned original source identity')
            if hashlib.sha256(raw_trace).hexdigest()!=origin['raw_original_stdio_sha256']:
                raise ValueError('Original source stdout SHA256 mismatch')
            for result in (initial,rescore):
                if result.get('case')!=ident or result.get('raw_trace_sha256')!=origin['raw_original_stdio_sha256']:
                    raise ValueError('Score not bound to original source stdout')
                if result.get('core_frozen_risu_findings')!=[
                    x.get('rule_id') for x in scanner.get('findings',[])]:
                    raise ValueError('Postfreeze rescore fabricated a different frozen RISU output')
            row.update({
                'status':'VERIFIED_GENUINE_ORIGINAL_STDIO',
                'initial_core_findings':initial['core_frozen_risu_findings'],
                'initial_oracle_mismatches':initial['oracle_mismatches'],
                'initial_oracle_unverified':initial['oracle_unverified'],
                'rescored_oracle_mismatches':rescore['oracle_mismatches'],
                'rescored_oracle_unverified':rescore['oracle_unverified'],
                'postfreeze_oracles':rescore['oracle_checks'],
                'raw_original_stdio_sha256':origin['raw_original_stdio_sha256'],
                'project_source_commit':origin['source_commit'],
                'probe_count':origin['selected_call_count'],
                'self_reported_unknown_bug_count':0,
                'novelty_status':'NOT_CLAIMED',
            })
        rows.append(row)
    complete=[x for x in rows if x['status']=='VERIFIED_GENUINE_ORIGINAL_STDIO']
    blind=[x for x in complete if x['selection']=='BLIND']
    calib=[x for x in complete if x['selection']!='BLIND']
    return {'schema':'risu-b12-five-original-stdio-blind-audit-ledger-v1',
        'manifest_sha256':hashlib.sha256(raw).hexdigest(),
        'frozen_analyzer_blobs':FROZEN,'selected':rows,
        'summary':{
            'preselected_native_upstream_servers':5,
            'different_organization_owners':4,
            'preselected_blind_servers':4,
            'original_stdout_captures_verified':len(complete),
            'blind_cases_reproduced':len(blind),
            'blind_core_risu_findings':sum(len(v['initial_core_findings']) for v in blind),
            'blind_functional_oracle_mismatches':sum(v['rescored_oracle_mismatches'] for v in blind),
            'calibration_oracle_mismatches':sum(v['rescored_oracle_mismatches'] for v in calib),
            'postfreeze_rechecks_unverified':sum(v['rescored_oracle_unverified'] for v in complete),
            'unverified_missing_selected_servers':5-len(complete),
            'independently_confirmed_previously_unreported_bugs':0,
            'blind_ecosystem_recall':'NOT_ESTIMABLE_4_NONRANDOM_SERVERS',
            'semantics':'Original native stdio captures are authentic; the scanner found no blind defects in those preselected tool calls, which does not prove absence of bugs'},
        'limitations':[
            'Four blind server deployments, three independent publisher organizations (plus one source-inspected calibration server)',
            'The initial Go mismatch was the oracle rejecting 3.750000, which is numerically equal to 3.75',
            'SQLite parser initially abstained because FastMCP 0.4.1 emits one JSON object per text block; a postfreeze parser-only rescore is separate and auditable',
            'SQLite source was inspected before the blind survey; cannot credit its observed row-limit bug to blind detection',
            'SQLite keyword scanning and suppressed SQL LIMIT are already described in upstream security issue #12; no completely new root cause claimed',
            'Official Memory and Filesystem share one upstream repo owner',
            'No broad accuracy, precision or unknown-defect discovery claim without independently adjudicated novel examples']}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--manifest',type=Path,default=Path('benchmarks/p6b12/prelocked_blind_servers.json'))
    parser.add_argument('--record',action='append',default=[])
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args()
    rec={}
    for item in args.record:
        name,sep,path=item.partition('=')
        if not sep or name in rec:parser.error('Unique CASE=path required')
        rec[name]=Path(path)
    result=audit(args.manifest,rec)
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(result,indent=2,ensure_ascii=False,sort_keys=True)+'\n')
    print(json.dumps(result['summary'],indent=2,sort_keys=True))
    if set(rec)!=EXPECTED:
        raise SystemExit('Selected native MCP cases omitted from audit')
if __name__=='__main__':main()
