"""Source-independent, conservative first-pass fixture oracles.

A mismatch is a CANDIDATE only, never a novel confirmed external defect.
Core RISU result and independent oracles are counted separately.
"""
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path


def text_of(resp):
    if not isinstance(resp,dict) or not isinstance(resp.get('result'),dict):return ''
    return '\n'.join(b.get('text','') for b in resp['result'].get('content',[])
        if isinstance(b,dict) and b.get('type')=='text' and isinstance(b.get('text'),str))


def good(call):
    v=call.get('response',{})
    return isinstance(v,dict) and isinstance(v.get('result'),dict) and v['result'].get('isError') is not True


def status(check,why=''):
    return {'oracle':check[0], 'status':check[1], 'reason':why}


def evaluate(case, calls, fixture):
    out=[]
    def item(name, yes, observed=True, note=''):
        out.append(status((name,'PASS' if yes else ('MISMATCH_CANDIDATE' if observed else 'UNVERIFIED')),note))
    if case=='FS2':
        if len(calls)!=6:return [status(('call_count','UNVERIFIED'),'Unexpected number of captured calls')]
        t=[text_of(c['response']) for c in calls]
        item('full_read_preserves_first_and_last',good(calls[0]) and 'RISU_B13_FIRST' in t[0] and 'RISU_B13_LAST' in t[0],
             good(calls[0]),'Exact synthetic file marker tokens')
        item('head_two_preserves_first_and_excludes_last',good(calls[1]) and 'RISU_B13_FIRST' in t[1] and 'RISU_B13_LAST' not in t[1],
             good(calls[1]),'Line slice declared head=2')
        structure=calls[2]['response'].get('result',{}).get('structuredContent')
        possible=[]
        if isinstance(structure,dict):
            for x in structure.get('results',[]):
                if isinstance(x,dict):
                    for v in (x.get('value'),x):
                        if isinstance(v,dict) and isinstance(v.get('size'),int):possible.append(v['size'])
        item('stat_matches_independent_file_bytes',fixture['file_bytes'] in possible,
             good(calls[2]) and bool(possible),'Exact OS fixture byte size vs MCP stat')
        item('literal_search_finds_known_marker',good(calls[3]) and 'RISU_B13_FIRST' in t[3],
             good(calls[3]),'Known fixture token is searchable')
        s=calls[4]['response'].get('result',{}).get('structuredContent')
        cnt=s.get('totalMatches') if isinstance(s,dict) else None
        item('literal_search_absent_has_zero_hits',cnt==0,good(calls[4]) and isinstance(cnt,int),
             'Known-absent token has no matches')
        item('directory_contains_fixture_file',good(calls[5]) and 'b13.txt' in t[5],
             good(calls[5]),'New local file must be present in listing')
    elif case=='SQL2':
        if len(calls)!=7:return [status(('call_count','UNVERIFIED'),'Unexpected number of captured calls')]
        t=[text_of(c['response']) for c in calls]
        item('open_and_schema_contains_records',good(calls[0]) and good(calls[1]) and 'records' in t[1],
             good(calls[0]) and good(calls[1]),'Local fixture table exists')
        item('literal_and_bound_id_two_agree',all(good(calls[i]) and 'RISU_B13_TWO' in t[i] for i in (2,3)),
             good(calls[2]) and good(calls[3]),'SQL id=2 and bound id=? both identify same fixture value')
        item('unicode_parameter_preserved',good(calls[4]) and 'RISU_B13_Ω' in t[4],
             good(calls[4]),'Unicode bind roundtrip')
        item('sql_update_visible_in_followup_query',good(calls[5]) and good(calls[6]) and 'RISU_B13_MUTATED' in t[6],
             good(calls[5]) and good(calls[6]),'Final SELECT should observe successful UPDATE')
        rows=fixture['db_rows']
        item('independent_sqlite_state_after_update',len(rows)==6 and rows[0]==[1,'RISU_B13_MUTATED'],
             True,'SQLite stdlib direct DB oracle, independent of MCP display')
    else:raise ValueError('Unknown selected cohort case')
    return out


def audit(case,original,risu,manifest):
    chosen=json.loads(manifest.read_text())
    if chosen.get('schema')!='risu-p6b13-public-native-cross-publisher-metamorphic-v1':
        raise ValueError('Invalid prelocked cohort schema')
    target=next(x for x in chosen['cohort'] if x['id']==case)
    meta=json.loads((original/'origin.json').read_text())
    raw=(original/'original_stdio.jsonl').read_bytes()
    calls=json.loads((original/'unmodified_calls.json').read_text())
    report=json.loads(risu.read_text())
    if not(meta['native_upstream_process'] and meta['source_stdout_unmodified'] and
           meta['source_commit']==target['sha'] and meta['repository']==target['repo'] and
           hashlib.sha256(raw).hexdigest()==meta['original_stdio_sha256'] and
           len(calls)==len(target['tool_calls'])):
        raise ValueError('Original source/bytes or preregistered denominator mismatch')
    for orig, locked in zip(calls,target['tool_calls']):
        if orig['tool']!=locked['name']:raise ValueError('Unregistered tool in execution')
    checks=evaluate(case,calls,meta['known_fixture'])
    return {'schema':'risu-b13-two-independent-native-originals-first-pass-v1',
            'case':case,'source_repo':meta['repository'],'source_commit':meta['source_commit'],
            'raw_original_stdio_sha256':meta['original_stdio_sha256'],
            'native_process':True,'selected_calls':len(calls),
            'frozen_risu_findings':[x.get('rule_id') for x in report.get('findings',[])],
            'independent_oracles':checks,
            'oracles_pass':sum(x['status']=='PASS' for x in checks),
            'candidate_mismatches':sum(x['status']=='MISMATCH_CANDIDATE' for x in checks),
            'oracle_unverified':sum(x['status']=='UNVERIFIED' for x in checks),
            'confirmed_newly_discovered_upstream_defects':0,
            'novelty_status':'UNASSESSED',
            'limits':'A first-pass oracle mismatch is not a verified bug. Inspect original evidence; replicate with independent client, source chronology and controls before filing or claiming novelty.'}


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--case',choices=('FS2','SQL2'),required=True)
    p.add_argument('--capture',type=Path,required=True)
    p.add_argument('--scanner',type=Path,required=True)
    p.add_argument('--manifest',type=Path,default=Path('benchmarks/p6b13/prelocked_native_cases.json'))
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    result=audit(a.case,a.capture,a.scanner,a.manifest)
    a.out.write_text(json.dumps(result,indent=2,ensure_ascii=False,sort_keys=True)+'\n')
    print('B13_SOURCE_NATIVE_INDEPENDENT_ORACLE',json.dumps({k:result[k] for k in
      ('case','oracles_pass','candidate_mismatches','oracle_unverified','frozen_risu_findings')},sort_keys=True))

if __name__=='__main__':main()