"""Third preselected B10 source-family score, not a new detector rule.

Source component executes in a genuine upstream Vitest module. Structured
response + JSON-RPC record are labeled TEST-ADAPTER, not live MCP transport.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from risu_display_fidelity import verify_display_fidelity


def read(path: Path, revision: str) -> dict:
    x=json.loads(path.read_text())
    assert x['family']=='CLINICAL177'
    assert x['revision']==revision
    assert x['source_execution']=='ACTUAL_PINNED_ENRICHMENT_RENDERER_TEST_ONLY'
    assert [s['id'] for s in x['samples']]==['location','plain']
    assert all(type(s['raw']) is str and type(s['rendered']) is str for s in x['samples'])
    return x


def render_trace(source: dict, filename: Path) -> dict:
    rules=[]
    tools=[]
    msgs=[]
    for i,item in enumerate(source['samples'],2):
        name='clinical_'+item['id']
        tools.append({'name':name,'inputSchema':{'type':'object'},'outputSchema':{'type':'object',
           'properties':{'value':{'type':'string'}},'required':['value']}})
        rules.append({'id':item['id'],'tool':name,'pointer':'/value',
            'line_prefix':'**value:** ','mode':'markdown-literal','is_error':False})
        msgs.extend([
           {'jsonrpc':'2.0','id':i,'method':'tools/call','params':{'name':name,'arguments':{}}},
           {'jsonrpc':'2.0','id':i,'result':{'isError':False,
              'content':[{'type':'text','text':'**value:** '+item['rendered']}],
              'structuredContent':{'value':item['raw']}}},
        ])
    rows=[
       {'jsonrpc':'2.0','id':1,'method':'tools/list','params':{}},
       {'jsonrpc':'2.0','id':1,'result':{'tools':tools}},
    ]+msgs
    filename.write_text(''.join(json.dumps(row)+'\n' for row in rows))
    return {'schema':'risu-display-fidelity-contract-v1','rules':rules}


def main():
    p=argparse.ArgumentParser()
    p.add_argument('old',type=Path)
    p.add_argument('fixed',type=Path)
    p.add_argument('output',type=Path)
    args=p.parse_args()
    m=json.loads(Path('benchmarks/p6b10/prelocked_three_display_fidelity.json').read_text())
    assert next(c for c in m['families'] if c['id']=='CLINICAL177')['old']=='dae110236e4960f6e1f964a22a7404aecdd55d3dd'
    before=read(args.old,'old')
    after=read(args.fixed,'fixed')
    a,b=before['samples'],after['samples']
    value='SEARCH[Location](AREA[LocationCountry]"Mexico")'
    reproduced=(a[0]['raw']==b[0]['raw']==value
         and a[0]['rendered']==value
         and b[0]['rendered'].startswith(chr(96))
         and b[0]['rendered'].endswith(chr(96))
         and b[0]['rendered'].strip(chr(96))==value)
    normal=(a[1]['raw']==b[1]['raw']=='asthma'
        and a[1]['rendered']=='asthma'
        and b[1]['rendered'].strip(chr(96))=='asthma')
    args.output.mkdir(parents=True,exist_ok=True)
    scores={}
    for rev,source in [('old',before),('fixed',after)]:
        trace=args.output/(rev+'_adapter.jsonl')
        contract=render_trace(source,trace)
        report=verify_display_fidelity(trace,contract)
        (args.output/(rev+'_risu.json')).write_text(json.dumps(report,indent=2)+'\n')
        scores[rev]=report
    def codes(report,rule_id):
        h=hashlib.sha256(rule_id.encode()).hexdigest()[:12]
        return sum(v['rule_sha256']==h for v in report['findings'])
    detection=(reproduced and normal and codes(scores['old'],'location')==1
        and codes(scores['fixed'],'location')==0 and
        codes(scores['old'],'plain')==0 and codes(scores['fixed'],'plain')==0
        and scores['old']['summary']['unverified']==0 and scores['fixed']['summary']['unverified']==0)
    result={
      'schema':'risu-p6b10-clinical177-pair-score-v1',
      'family':'CLINICAL177','role':'PRELOCKED_NEW_INDEPENDENT_FAMILY',
      'source_code_execution':'ACTUAL_PINNED_ENRICHMENT_RENDERER',
      'evidence_transport':'TEST_ADAPTER_JSONRPC_NOT_WIRE',
      'source_defect_independently_reproduced':bool(reproduced),
      'normal_control_pass':bool(normal),
      'old_fidelity_findings':scores['old']['summary']['findings'],
      'fixed_fidelity_findings':scores['fixed']['summary']['findings'],
      'frozen_rule_detected':bool(detection),
      'limits':'Only a caller-declared literal output field; NOT autonomous validation of arbitrary clinical trial behavior',
    }
    (args.output/'score.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
    if not reproduced or not normal:
        raise SystemExit('Pinned upstream source reproduction or control failed')


if __name__=='__main__':
    main()
