"""Deterministic synthetic controls. This is *not* the seven-family independent holdout.

800 varied valid MCP traces + 400 directly known injected type violations.
Use to check accidental detector false alarms and simple mutation sensitivity,
not to estimate real ecosystem false-positive rate.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import random
import tempfile
from risu_mcp_trace import verify_trace

SEED=20261108
SCHEMA='risu-p6b9-synthetic-property-controls-v1'
PROTOCOLS=('2025-06-18','2025-11-25','2026-07-28')
VALUES=[
    ('integer',0,False),
    ('integer',-123456789,True),
    ('string','A*p* [brackets] and \\ escaped',12),
    ('string','',False),
    ('boolean',False,'false'),
    ('boolean',True,0),
    ('null',None,1),
    ('array',[],{}),
    ('array',[1,2,3],'value'),
    ('object',{},[1]),
    ('object',{'a':1,'b':'x'},'not-object'),
]

def trace(seed:int,kind:str)->tuple[list[dict],str]:
    rng=random.Random(seed)
    type_name,normal,mutant=VALUES[seed%len(VALUES)]
    proto=PROTOCOLS[seed%len(PROTOCOLS)]
    tool_name='read_tool_'+str(seed)
    output_schema={'type':'object','properties':{
        'key':{'type':'string'},
        'value':{'type':type_name},
    },'required':['key','value']}
    listings=[{'name':tool_name,'inputSchema':{'type':'object'},'outputSchema':output_schema}]
    for i in range(rng.randrange(0,7)):
        listings.append({'name':'extra_'+str(seed)+'_'+str(i),
                         'inputSchema':{'type':'object'},
                         'outputSchema':{'type':'object','properties':{'extra':{'type':'string'}}}})
    rng.shuffle(listings)
    returned={'key':'test_'+str(seed),
              'value':normal if kind=='normal' else mutant}
    result={'isError':False,
            'content':[{'type':'text','text':rng.choice([
                'normal', 'A*p*', 'opaque text, no shape promise',
                'Line1\\n- list item', 'SENTINEL_DO_NOT_EMIT_'+str(seed)
            ])}],
            'structuredContent':returned}
    if proto=='2026-07-28':result['resultType']='complete'
    records=[
        {'jsonrpc':'2.0','id':1,'method':'tools/list','params':{}},
        {'jsonrpc':'2.0','id':1,'result':{'tools':listings}},
        {'jsonrpc':'2.0','id':2,'method':'tools/call','params':{
            'name':tool_name,'arguments':{}}},
        {'jsonrpc':'2.0','id':2,'result':result},
    ]
    return records,proto

def evaluate(out:Path)->dict:
    false_alerts=[]
    missed_mutations=[]
    other_incomplete=[]
    normal_count=800
    mutation_count=400
    with tempfile.TemporaryDirectory(prefix='risu_b9_controls_') as d:
        path=Path(d)/'case.jsonl'
        for kind,count in [('normal',normal_count),('mutation',mutation_count)]:
            for i in range(count):
                seed=i if kind=='normal' else 10000+i
                records,proto=trace(seed,kind)
                path.write_text(''.join(json.dumps(rec,ensure_ascii=False,sort_keys=True)+'\n'
                                        for rec in records),encoding='utf-8')
                report=verify_trace(path,proto)
                findings=[v['rule_id'] for v in report['findings']]
                if report['unverified'] or report['semantic_verification'] not in (
                    'CHECKED_NO_MISMATCHES','OBSERVED_MISMATCHES_IN_CAPTURE'):
                    other_incomplete.append({'kind':kind,'index':i,'codes':[
                        x['code'] for x in report['unverified']]})
                if kind=='normal' and findings:
                    false_alerts.append({'index':i,'rule_ids':findings})
                if kind=='mutation' and (findings!=['RMC502']):
                    missed_mutations.append({'index':i,'rule_ids':findings})
                if report['summary']['structured_values_schema_checked']!=1:
                    other_incomplete.append({'kind':kind,'index':i,'code':'NOT_SCHEMA_CHECKED'})
                if 'SENTINEL_DO_NOT_EMIT_' in json.dumps(report):
                    raise AssertionError('An arbitrary recorded content string appeared in public diagnostics')
    record={
        'schema':SCHEMA,
        'test_class':'DETERMINISTIC_INTERNAL_SYNTHETIC_CONTROLS_NOT_INDEPENDENT_EXTERNAL_BUGS',
        'seed':SEED,'normal_traces':normal_count,
        'injected_single_field_type_mismatch_traces':mutation_count,
        'unexpected_findings_on_normal':len(false_alerts),
        'injected_mismatch_non_detections':len(missed_mutations),
        'unverified_or_unchecked_cases':len(other_incomplete),
        'unexpected_findings_examples':false_alerts[:10],
        'mutation_non_detection_examples':missed_mutations[:10],
        'uncertainty':'No random real systems, no real-world false-positive rate or semantic completeness; only supported, bounded schema types',
        'source_script_git_note':'The CI workflow verifies the frozen RISU analyzer blob before running this script',
    }
    out.write_text(json.dumps(record,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    if false_alerts or missed_mutations or other_incomplete:
        raise SystemExit('Synthetic control/mutation suite failed')
    return record

def main()->None:
    p=argparse.ArgumentParser()
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    r=evaluate(a.out)
    print(json.dumps({k:v for k,v in r.items() if not isinstance(v,list)},indent=2,sort_keys=True))

if __name__=='__main__':main()
