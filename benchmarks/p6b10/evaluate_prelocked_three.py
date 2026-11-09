"""P6-B10 prelocked original external display/copy fidelity pair adjudication.

Source truth is separately checked from a specific before/fix fingerprint, then
frozen RISU diagnostics are scored; no target output is synthesized except the
declared stable prefix/JSONRPC envelope, both explicitly marked as adapters.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path

FAMILIES={'GEONAMES28':'markdown-rendered',
          'OPENALEX128':'markdown-rendered',
          'MITRECWE16':'raw-copy'}

def read(p:Path,ident:str)->dict:
    c=json.loads(p.read_text(encoding='utf-8'))
    if (c.get('schema')!='risu-p6b10-real-source-display-v1'
            or c.get('family')!=ident
            or c.get('origin')!='REAL_PINNED_UPSTREAM_HELPER_OUTPUT_ADAPTER_JSONRPC_NOT_STDIO'):
        raise ValueError('Not a genuine target-family capture')
    for key in ('issue','normal'):
        if (type(c[key]) is not dict or set(c[key])!={'raw','rendered'}
                or any(type(v) is not str for v in c[key].values())):
            raise ValueError('Malformed source result')
    return c

def traces(c:dict)->tuple[list[dict],dict]:
    family=c['family'];mode=FAMILIES[family]
    rule=[]
    tools=[]
    rows=[]
    for i,key in enumerate(('issue','normal'),2):
        name=family.lower()+'_'+key
        tools.append({'name':name,'inputSchema':{'type':'object'},
                      'outputSchema':{'type':'object','properties':{
                          'value':{'type':'string'}},'required':['value']}})
        rule.append({'id':family+'_'+key,'tool':name,'source':'/value',
                     'content_index':0,'prefix_raw':'Value: ',
                     'mode':mode,'on_error':False})
        rows.extend([
            {'jsonrpc':'2.0','id':i,'method':'tools/call','params':{
                'name':name,'arguments':{}}},
            {'jsonrpc':'2.0','id':i,'result':{
                'isError':False,'structuredContent':{'value':c[key]['raw']},
                'content':[{'type':'text','text':'Value: '+c[key]['rendered']}]}},
        ])
    rows=[{'jsonrpc':'2.0','id':1,'method':'tools/list','params':{}},
          {'jsonrpc':'2.0','id':1,'result':{'tools':tools}}]+rows
    return rows,{'schema':'risu-mcp-display-contract-v1','rules':rule}

def independent_truth(old:dict,fixed:dict)->tuple[bool,bool]:
    o=old['issue'];f=fixed['issue']
    normal=(old['normal']['raw']==fixed['normal']['raw'] and
            old['normal']['rendered']==old['normal']['raw'] and
            fixed['normal']['rendered']==fixed['normal']['raw'])
    if old['family']=='GEONAMES28':
        mutation=(o['raw']==f['raw']=='www.example.com' and
                  o['rendered'].replace('\\','').find('[.]')>=0 and
                  f['rendered']=='www.example.com')
    elif old['family']=='OPENALEX128':
        mutation=(o['raw']==f['raw']=='alpha\nbeta' and
                  '\n' not in o['rendered'] and o['rendered'].find('alpha beta')>=0 and
                  '\n' in f['rendered'] and 'alpha' in f['rendered'] and 'beta' in f['rendered'])
    else:
        mutation=(o['raw']==f['raw']=='CWE-80' and
                  '\\-' in o['rendered'] and f['rendered']=='CWE-80')
    return bool(mutation),bool(normal)

def score(old:dict,fixed:dict,o:dict,f:dict)->dict:
    family=old['family'];mode=FAMILIES[family]
    mutation,normal=independent_truth(old,fixed)
    rule='RMC508' if mode=='raw-copy' else 'RMC507'
    def findings(r):return [x['rule_id'] for x in r['findings']]
    before=findings(o);after=findings(f)
    detected=(mutation and normal and before==[rule] and not after and
              o['summary']['explicit_display_rules_checked']==2 and
              f['summary']['explicit_display_rules_checked']==2 and
              o['summary']['explicit_display_rules_passed']==1 and
              f['summary']['explicit_display_rules_passed']==2)
    return {'schema':'risu-p6b10-independent-public-source-score-v1',
            'family':family,'role':'PRELOCKED_NEW_SOURCE_HELDOUT',
            'original_upstream_bugfix_reproduced':mutation,
            'normal_control_passed':normal,
            'old_findings':before,'fixed_findings':after,
            'relevant_frozen_rule_detected':bool(detected),
            'original_stdo_raw_captured':False,
            'evidence_tier':'PINNED_SOURCE_COMPONENT_WITH_RECONSTRUCTED_JSONRPC',
            'comparison_direction':'structuredContent source string versus caller-declared content prefix segment',
            'selection_limit':'Three repositories of same publisher; not random, cross-vendor or ecosystem precision estimate'}

def main():
    p=argparse.ArgumentParser()
    p.add_argument('mode',choices=('prepare','score'))
    p.add_argument('family',choices=tuple(FAMILIES))
    p.add_argument('paths',nargs='+',type=Path)
    a=p.parse_args()
    if a.mode=='prepare':
        if len(a.paths)!=3:raise SystemExit('prepare requires capture, jsonl, contract')
        c=read(a.paths[0],a.family)
        rows,contract=traces(c)
        a.paths[1].write_text(''.join(json.dumps(v,sort_keys=True)+'\n' for v in rows))
        a.paths[2].write_text(json.dumps(contract,indent=2,sort_keys=True)+'\n')
    else:
        if len(a.paths)!=5:raise SystemExit('score requires old, fixed, two RISU outputs, and destination')
        old,fixed,oldr,fixr,out=a.paths
        score_data=score(read(old,a.family),read(fixed,a.family),
                         json.loads(oldr.read_text()),json.loads(fixr.read_text()))
        out.write_text(json.dumps(score_data,indent=2,sort_keys=True)+'\n')
        print(json.dumps(score_data,indent=2,sort_keys=True))
        if not score_data['original_upstream_bugfix_reproduced'] or not score_data['normal_control_passed']:
            raise SystemExit('Source reproduction or normal control failed; case is UNVERIFIED, never a detection success')
if __name__=='__main__':main()
