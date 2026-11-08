"""P6-B10 actual upstream source module pairs, independently adjudicated.

Only public pinned source modules, no external service calls. JSON-RPC envelopes
in this harness are TEST ADAPTER PROJECTIONS of true upstream renderer output,
never captured stdio or wire data.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from risu_display_fidelity import verify_display_fidelity

CASE_IDS = {
    'GEONAMES28': ('url', 'plain'),
    'FDIC25': ('linebreak', 'blank', 'plain'),
}
MODE = {'GEONAMES28': 'markdown-literal', 'FDIC25': 'json-string-special'}
MANIFEST = Path('benchmarks/p6b10/prelocked_three_display_fidelity.json')


def read_source(path: Path, family: str, rev: str) -> dict:
    raw=path.read_bytes()
    row=json.loads(raw)
    assert row.get('family')==family and row.get('revision')==rev
    samples=row['samples']
    assert type(samples) is list and len(samples)==len(CASE_IDS[family])
    assert tuple(x['id'] for x in samples)==CASE_IDS[family]
    assert all(type(x['raw']) is str and type(x['rendered']) is str for x in samples)
    return row


def derive_trace(row: dict, family: str, out: Path) -> dict:
    rules=[]
    msgs=[]
    methods=[]
    for index, sample in enumerate(row['samples'],2):
        tool='p6b10_'+sample['id']
        rules.append({'id':sample['id'],'tool':tool,'pointer':'/value',
                      'line_prefix':'**value:** ','mode':MODE[family],'is_error':False})
        methods += [
            {'jsonrpc':'2.0','id':index,'method':'tools/call',
             'params':{'name':tool,'arguments':{'synthetic':True}}},
            {'jsonrpc':'2.0','id':index,'result':{
                'isError':False, 'content':[{'type':'text','text':'**value:** '+sample['rendered']}],
                'structuredContent':{'value':sample['raw']}}},
        ]
    msgs=[
        {'jsonrpc':'2.0','id':1,'method':'tools/list','params':{}},
        {'jsonrpc':'2.0','id':1,'result':{'tools':[{'name':r['tool'],
              'inputSchema':{'type':'object'},'outputSchema':{'type':'object',
              'properties':{'value':{'type':'string'}},'required':['value']}}
              for r in rules]}},
    ]+methods
    out.write_text(''.join(json.dumps(m,ensure_ascii=False)+'\n' for m in msgs))
    return {'schema':'risu-display-fidelity-contract-v1','rules':rules}


def upstream_adjudication(family: str, old: dict, fixed: dict) -> tuple[bool,bool,dict]:
    ob={x['id']:x for x in old['samples']}
    fb={x['id']:x for x in fixed['samples']}
    if family=='GEONAMES28':
        o=ob['url'];f=fb['url']
        reproduced=(o['raw']==f['raw']=='www.example.com'
            and r'www\[.\]example.com' in o['rendered']
            and f['rendered']=='www.example.com')
        normal=(ob['plain']['rendered']==fb['plain']['rendered']=='Normal Name 123')
        detail={'observed_old_url_trigger_bracketing':r'www\[.\]example.com' in o['rendered'],
                'fixed_original_url_preserved':f['rendered']=='www.example.com'}
    else:
        o=ob['linebreak'];f=fb['linebreak']
        quoted=f['rendered']
        recovered=None
        try:
            # Genuine upstream fixed renderer uses a code span around JSON string.
            if quoted.startswith(chr(96)) and quoted.endswith(chr(96)):
                recovered=json.loads(quoted.strip(chr(96)))
        except ValueError:
            pass
        reproduced=(o['raw']==f['raw']=='line1\nline2'
           and o['rendered']=='line1 line2' and recovered==f['raw']
           and ob['blank']['rendered']=='' and fb['blank']['rendered']==chr(96)+'""'+chr(96))
        normal=(ob['plain']['rendered']==fb['plain']['rendered']=='Normal Name 123')
        detail={'old_linebreak_flattened':o['rendered']=='line1 line2',
                'fixed_json_code_recovers_source':recovered==f['raw'],
                'fixed_empty_disambiguation':fb['blank']['rendered']==chr(96)+'""'+chr(96)}
    return reproduced,normal,detail


def score(family: str, old_file: Path, fixed_file: Path, root: Path):
    manifest=json.loads(MANIFEST.read_text())
    assert manifest['schema']=='risu-p6b10-display-fidelity-prelocked-v1'
    case=next(x for x in manifest['families'] if x['id']==family)
    assert family in CASE_IDS and case['old']!=case['fixed']
    old=read_source(old_file,family,'old')
    fixed=read_source(fixed_file,family,'fixed')
    root.mkdir(parents=True,exist_ok=True)
    outcome={}
    for rev,source in [('old',old),('fixed',fixed)]:
        trace=root/(rev+'_adapter.jsonl')
        policy=derive_trace(source,family,trace)
        (root/(rev+'_policy.json')).write_text(json.dumps(policy,indent=2)+'\n')
        result=verify_display_fidelity(trace,policy)
        (root/(rev+'_risu.json')).write_text(json.dumps(result,indent=2)+'\n')
        outcome[rev]=result
    reproduced,normal,detail=upstream_adjudication(family,old,fixed)
    a=outcome['old'];b=outcome['fixed']
    old_find={x['rule_sha256'] for x in a['findings']}
    fixed_find={x['rule_sha256'] for x in b['findings']}
    issue_rules= {'GEONAMES28':['url'],'FDIC25':['linebreak','blank']}[family]
    expected_old={hashlib.sha256(ident.encode()).hexdigest()[:12] for ident in issue_rules}
    matching=bool(expected_old & old_find)
    normal_clean=(not any(x['rule_sha256']==hashlib.sha256('plain'.encode()).hexdigest()[:12]
                           for x in a['findings']+b['findings']))
    detected=(reproduced and normal and matching and not (expected_old & fixed_find)
              and normal_clean and a['summary']['unverified']==0 and b['summary']['unverified']==0)
    report={
        'schema':'risu-p6b10-real-upstream-module-score-v1',
        'family':family,'role':'PRELOCKED_NEW_INDEPENDENT_FAMILY',
        'source_code_execution':'REAL_PINNED_MODULES_WITH_SYNTHETIC_INPUT',
        'evidence_transport':'ADAPTER_RECONSTRUCTED_NOT_MCP_WIRE',
        'source_defect_independently_reproduced':reproduced,
        'normal_control_pass':normal and normal_clean,
        'old_fidelity_findings':len(a['findings']),
        'fixed_fidelity_findings':len(b['findings']),
        'frozen_rule_detected':detected,
        'source_expected_properties':detail,
        'limitations':'Rules and chosen structured-to-text relation supplied by test adapter; not autonomous inference from arbitrary tool output',
    }
    (root/'score.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
    if not reproduced or not normal:
        raise SystemExit('Independent upstream causal source reproduction did not qualify')


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('family',choices=sorted(CASE_IDS))
    ap.add_argument('old',type=Path)
    ap.add_argument('fixed',type=Path)
    ap.add_argument('output_directory',type=Path)
    a=ap.parse_args()
    score(a.family,a.old,a.fixed,a.output_directory)


if __name__=='__main__':
    main()
