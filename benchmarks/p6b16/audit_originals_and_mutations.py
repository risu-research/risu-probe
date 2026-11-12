"""Independent source-original B16 audit without importing the B16 checker.

This script validates raw native bytes, in-band catalog epochs and synthetic
postfreeze mutation claims. Original observed errors remain zero by design.
"""
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path

PINS={'AISH':'c9ad99acac291dd3a7b38162b6159bf5b01a1ed9',
      'MM':'75dc67c58e6468cdd81a6e5c3cb0a2f1521af93d'}

def h(b):return hashlib.sha256(b).hexdigest()
def read(p):return json.loads(p.read_text('utf-8'))
def require(x,why):
    if not x:raise ValueError(why)

def index_wire(raw):
    lines=[json.loads(x) for x in raw.splitlines()]
    requests={v['id']:(i,v) for i,v in enumerate(lines,1)
              if v.get('method')=='tools/call' and 'id' in v}
    responses={v['id']:(i,v) for i,v in enumerate(lines,1)
               if 'id' in v and v.get('method') is None}
    return lines,requests,responses

def audit(root:Path,case:str):
    folder=root/'.b16-source'
    origin=read(folder/'origin.json')
    trace=(folder/'original_stdio.jsonl').read_bytes()
    calls=read(folder/'calls.json')
    contract=read(folder/'contract.json')
    witness=read(folder/'state_witness.json')
    report=read(folder/'catalog_authority_firstpass.json')
    require(origin['case']==case and origin['source_commit']==PINS[case],
            'Pinned source identity mismatch')
    require(origin['status']=='CAPTURED_ORIGINAL','Native source capture failed')
    require(origin['trace_sha256']==h(trace)==report['trace_sha256']
            ==witness['trace_sha256'],'Original wire or witness SHA mismatch')
    require(contract['schema']=='risu-mcp-observation-contract-v1','Wrong contract family')
    total=5 if case=='AISH' else 2
    require(origin['calls_executed']==len(calls)==total,'Missing original selected call')
    wire,reqs,responses=index_wire(trace)
    require(len(reqs)==total,'Original tool request count changed')
    for entry in calls:
        line,req=reqs[entry['response']['id']]
        resp_line,resp=responses[entry['response']['id']]
        require((line,resp_line)==(entry['request_line'],entry['response_line']),
                'Derived call lines disagree with original MCP bytes')
        require(req['params']['name']==entry['tool'] and resp==entry['response'],
                'Derived request or response not original wire')
    if case=='AISH':
        for ident in (20,23,25):
            result=responses[ident][1].get('result')
            require(type(result) is dict and result.get('isError',False) is not True,
                    'Expected genuine normal structured result')
            require(result.get('structuredContent')=={'ok':True,'count':3},
                    'Original upstream output abnormal or missing')
        notifications=[i for i,v in enumerate(wire,1)
                       if v.get('method')=='notifications/tools/list_changed']
        require(len(notifications)==1,'Native original catalog-change notification missing')
        require(responses[22][0]<notifications[0]<reqs[23][0],
                'No contemporaneous catalog invalidation before stale call')
        require(reqs[23][0]<next(i for i,v in enumerate(wire,1)
             if v.get('method')=='tools/list' and v.get('id')==34)<reqs[25][0],
             'Original list refresh order wrong')
        s=report['summary']
        require(s['matched_obligations']==4 and s['qualified_passes']==2
                and s['advisory_passes']==1 and s['observed_mismatches']==0,
                'B16 native firstpass changed')
        by_line={c['request_line']:c for c in report['checks']}
        pre=by_line[reqs[20][0]]
        stale=by_line[reqs[23][0]]
        refreshed=by_line[reqs[25][0]]
        require(pre['authority_grade']=='CATALOG_NORMATIVE' and
                refreshed['authority_grade']=='CATALOG_NORMATIVE',
                'Original structured schema qualification absent')
        require(stale['authority_grade']=='UNVERIFIED' and
                stale['authority_reason']=='CATALOG_CHANGED_NOTIFICATION',
                'Stale original catalog improperly trusted')
        require(pre['catalog_sha256']!=refreshed['catalog_sha256'],
                'Native catalog change did not change digest')
        require(pre['tool_descriptor_sha256']==refreshed['tool_descriptor_sha256'],
                'Original stable structured tool contract changed unexpectedly')
        return {'case':case,'sha':h(trace),'original_calls':total,
                'catalog_change_after_response':notifications[0],
                'new_catalog_qualified_passes':2,'stale_catalog_quarantined':True}
    s=report['summary']
    require(s['matched_obligations']==2 and s['qualified_mismatches']==0
            and s['observed_mismatches']==0,'MM original observation changed')
    require(all(x['before_sha256']==x['after_sha256'] for x in calls),
            'MM original read-only state unexpectedly changed')
    return {'case':case,'sha':h(trace),'original_calls':total,
            'catalog_change_after_response':None,'new_catalog_qualified_passes':0,
            'stale_catalog_quarantined':False}

def audit_mutations(original:Path, mutations:Path):
    root=original/'.b16-source'
    original_bytes=(root/'original_stdio.jsonl').read_bytes()
    original_lines=original_bytes.splitlines()
    ledger=read(mutations/'SYNTHETIC_INJECTION_LEDGER.json')
    require(ledger['mutation_not_upstream_bug'] is True,'Missing synthetic label')
    require(ledger['negative_hash_binding']=='REJECTED_WRONG_RAW_TRACE_HASH',
            'Tampered original witness binding not rejected')
    for case,ident,expected in [
       ('before_change',20,'QUALIFIED_MISMATCH'),
       ('after_list_change',23,'QUARANTINED_MISMATCH'),
       ('after_refresh',25,'QUALIFIED_MISMATCH')]:
        folder=mutations/case
        raw=(folder/'mutated_stdio.jsonl').read_bytes()
        changed=raw.splitlines()
        require(len(changed)==len(original_lines),'Unexpected extra messages in synthetic evidence')
        differing=[i for i,(a,b) in enumerate(zip(original_lines,changed)) if a!=b]
        require(len(differing)==1,'Mutation modified more than one native source message')
        original_message=json.loads(original_lines[differing[0]])
        mutant=json.loads(changed[differing[0]])
        require(original_message.get('id')==mutant.get('id')==ident,
                'Synthetic message edited wrong original MCP response')
        require(original_message['result']['structuredContent']['count']==3 and
                mutant['result']['structuredContent']['count']=='three',
                'Synthetic case does not have exactly declared type mutation')
        mut_copy=json.loads(json.dumps(mutant))
        mut_copy['result']['structuredContent']['count']=3
        require(mut_copy==original_message,'Synthetic mutation changed more than required field')
        report=read(folder/'product_report.json')
        require(report['trace_sha256']==h(raw),'Synthetic report detached from original source bytes')
        findings=[v for v in report['checks'] if v['observed']=='MISMATCH']
        require(len(findings)==1 and findings[0]['disposition']==expected,
                'Frozen B16 mutation disposition incorrect')
    return {'synthetic_mutations':3,'qualified_mutation_cases':2,
            'quarantined_mutation_cases':1,
            'genuine_upstream_issues_added_by_synthetic_injection':0,
            'wrong_trace_binding_rejected':True}

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--aish',required=True,type=Path)
    p.add_argument('--mm',required=True,type=Path)
    p.add_argument('--mutations',required=True,type=Path)
    p.add_argument('--out',required=True,type=Path)
    a=p.parse_args()
    cases=[audit(a.aish,'AISH'),audit(a.mm,'MM')]
    fault=audit_mutations(a.aish,a.mutations)
    report={'schema':'risu-p6b16-independent-raw-source-and-mutation-audit-v1',
            'firstpass_original_run':43295550845,
            'new_original_owners':2,'seven_original_tool_calls':7,
            'source_informed_not_blind':True,
            'original_upstream_confirmed_new_bugs':0,
            'cases':cases,'synthetic_fault_injection':fault,
            'conclusion':'Catalog-anchored normative structured-output checks and stale-catalog rejection were independently verified on external source-native stdio. Fault injection proves sensitivity only; no genuine external bug discovered.'}
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(report,indent=2,ensure_ascii=False,sort_keys=True)+'\n')
    print('B16_EXTERNAL_FIRSTPASS_INDEPENDENT_CROSS_AUDIT',json.dumps({
       'owners':2,'calls':7,'real_bugs':0,
       'synthetic_qualified':2,'synthetic_quarantined':1,
       'wrong_binding_rejected':True},sort_keys=True))

if __name__=='__main__':main()
