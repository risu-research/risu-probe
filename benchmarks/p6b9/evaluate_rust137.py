"""P6B9 RUST137 paired actual Rust SDK typed roundtrip and RISU boundary check."""
import argparse
import json
from pathlib import Path

def read(path):
    x=json.loads(path.read_text())
    assert x['schema']=='risu-p6b9-rust137-original-type-roundtrip-v1'
    assert x['source']=='ACTUAL_UPSTREAM_RUST_TOOLCALLRESULT_SERDE_COMPONENT_NOT_FULL_CLI'
    return x

def trace(x):
    schema={'type':'object','properties':{
        'count':{'type':'integer'},
        'items':{'type':'array','items':{'type':'string'}}},'required':['count','items']}
    return [
        {'jsonrpc':'2.0','id':1,'method':'tools/list','params':{}},
        {'jsonrpc':'2.0','id':1,'result':{'tools':[{
            'name':'rust_serde_result','inputSchema':{'type':'object'},'outputSchema':schema}]}},
        {'jsonrpc':'2.0','id':2,'method':'tools/call',
         'params':{'name':'rust_serde_result','arguments':{}}},
        {'jsonrpc':'2.0','id':2,'result':x['issue_roundtrip']},
    ]

def evaluate(o,f,ro,rf):
    first=o['issue_roundtrip'];second=f['issue_roundtrip']
    before=o['issue_original'];after=f['issue_original']
    loss=(before==after and
          'structuredContent' not in first and 'resultType' not in first and
          second.get('structuredContent')==before['structuredContent'] and
          second.get('resultType')=='complete')
    control=(o['control_original']==f['control_original'] and
             o['control_roundtrip']==f['control_roundtrip'] and
             o['control_roundtrip']==o['control_original'])
    old_codes=[x['rule_id'] for x in ro.get('findings',[])]
    fixed_codes=[x['rule_id'] for x in rf.get('findings',[])]
    detected=loss and control and 'RMC501' in old_codes and not fixed_codes
    return {'schema':'risu-p6b9-rust137-source-scored-v1',
            'family':'RUST137','role':'PRELOCKED_NEW_INDEPENDENT_FAMILY',
            'upstream_source_boundary_bugfix_reproduced':bool(loss),
            'normal_control_pass':bool(control),
            'old_findings':old_codes,'fixed_findings':fixed_codes,
            'loss_detected_by_risu_on_adapter_record':bool(detected),
            'cli_end_to_end_tested':False,
            'evidence':'ACTUAL_UPSTREAM_RUST_TOOLCALLRESULT_SERDE_COMPONENT_WITH_ADAPTER_JSONRPC',
            'limitation':'The source-real typed serializer is implicated in the CLI path, but the CLI was not invoked and no authentic stdio traffic is claimed.'}

def main():
    p=argparse.ArgumentParser()
    p.add_argument('mode',choices=['trace','score'])
    p.add_argument('files',nargs='+',type=Path)
    a=p.parse_args()
    if a.mode=='trace':
        assert len(a.files)==2
        rows=trace(read(a.files[0]))
        a.files[1].write_text(''.join(json.dumps(q,sort_keys=True)+'\n' for q in rows))
    else:
        assert len(a.files)==5
        old,fixed,ro,rf,out=a.files
        r=evaluate(read(old),read(fixed),json.loads(ro.read_text()),json.loads(rf.read_text()))
        out.write_text(json.dumps(r,indent=2,sort_keys=True)+'\n')
        print(json.dumps(r,indent=2,sort_keys=True))
        if not r['normal_control_pass']:raise SystemExit('Normal control failed')
if __name__=='__main__':main()
