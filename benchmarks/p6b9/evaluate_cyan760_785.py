"""P6B9 CYAN760/785 origin-correct, predefined outcome, frozen RISU trace score."""
from __future__ import annotations
import argparse
import json
from pathlib import Path

def read(p):
    x=json.loads(p.read_text())
    assert x['schema']=='risu-p6b9-cyan-authentic-framework-v1'
    assert x['component_origin']=='ACTUAL_UPSTREAM_SOURCE_UNIT_EXECUTION_NOT_WIRE'
    assert x['family'] in ('CYAN760','CYAN785')
    return x

def texts(result):
    assert type(result)==dict
    return [x.get('text','') for x in result.get('content',[]) if x.get('type')=='text']

def make_trace(x):
    fam=x['family']
    if fam=='CYAN760':
        schema={'type':'object'}
    else:
        schema={'type':'object','properties':{
            'items':{'type':'array','items':{'type':'string'}},
            'effectiveQuery':{'type':'string'}
        },'required':['items','effectiveQuery']}
    rows=[
      {'jsonrpc':'2.0','id':1,'method':'tools/list','params':{}},
      {'jsonrpc':'2.0','id':1,'result':{'tools':[{
          'name':'issue','inputSchema':{'type':'object'},'outputSchema':schema},
          {'name':'control','inputSchema':{'type':'object'},'outputSchema':schema}]}},
    ]
    for i,name in enumerate(('issue','control'),2):
        rows.extend([
            {'jsonrpc':'2.0','id':i,'method':'tools/call',
             'params':{'name':name,'arguments':{'synthetic':True}}},
            {'jsonrpc':'2.0','id':i,'result':x[name]},
        ])
    return rows

def score(o,f,ro,rf):
    fam=o['family']
    assert f['family']==fam
    if fam=='CYAN760':
        a='No running app matches "A*p*".'
        old_txt=''.join(texts(o['issue']))
        fixed_txt=''.join(texts(f['issue']))
        reproduced=(a in old_txt and a not in fixed_txt
                    and 'A\\*p\\*' in fixed_txt
                    and o['issue']['structuredContent']['error']['message']==a
                    and f['issue']['structuredContent']['error']['message']==a)
        control=(texts(o['control'])==texts(f['control']) and
                 'Safari' in ''.join(texts(o['control'])))
        symptom='Raw Markdown-active error text escaped by official fix'
    else:
        raw=o['raw_value']
        old_txt=''.join(texts(o['issue']))
        fixed_txt=''.join(texts(f['issue']))
        reproduced=(raw==f['raw_value'] and raw in str(o['issue']['structuredContent']['effectiveQuery'])
                    and raw in str(f['issue']['structuredContent']['effectiveQuery'])
                    and '\\*' in old_txt and '\\*' not in fixed_txt
                    and '`'+raw+'`' in fixed_txt)
        control=(o['control']['structuredContent'].get('effectiveQuery')=='simple'
                 and f['control']['structuredContent'].get('effectiveQuery')=='simple'
                 and all('simple' in ''.join(texts(v['control'])) for v in (o,f)))
        symptom='Upstream enrichment value became code literal instead of escaped copy token'
    oldfind=[v['rule_id'] for v in ro.get('findings',[])]
    newfind=[v['rule_id'] for v in rf.get('findings',[])]
    return {
        'schema':'risu-p6b9-cyan-independent-score-v1',
        'family':fam,'role':'PRELOCKED_NEW_INDEPENDENT_FAMILY',
        'upstream_bugfix_reproduced':bool(reproduced),
        'normal_control_pass':bool(control),
        'old_findings':oldfind,'fixed_findings':newfind,
        'relevant_auto_detected':bool(reproduced and oldfind and not newfind),
        'text_semantics_checked_by_risu':False,
        'symptom':symptom,
        'evidence_transport':'REAL_UPSTREAM_COMPONENT_RESULT_WITH_ADAPTER_CONTRACT_NOT_LIVE_MCP_WIRE',
        'claim_boundary':'Text/Markdown interpretation and copy-paste integrity not inferred by current generic JSON schema validator',
    }

def main():
    p=argparse.ArgumentParser()
    p.add_argument('mode',choices=('trace','score'))
    p.add_argument('files',nargs='+',type=Path)
    a=p.parse_args()
    if a.mode=='trace':
        assert len(a.files)==2
        rows=make_trace(read(a.files[0]))
        a.files[1].write_text(''.join(json.dumps(r,sort_keys=True)+'\n' for r in rows))
    else:
        assert len(a.files)==5
        o,f,ro,rf,out=a.files
        v=score(read(o),read(f),json.loads(ro.read_text()),json.loads(rf.read_text()))
        out.write_text(json.dumps(v,indent=2,sort_keys=True)+'\n')
        print(json.dumps(v,indent=2,sort_keys=True))
        if not v['normal_control_pass']:
            raise SystemExit('Normal control failed')
if __name__=='__main__':main()
