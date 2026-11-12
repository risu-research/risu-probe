"""Postfreeze synthetic fault injections into immutable B16 original MCP wire.

Uses genuinely recorded third-party native stdio as the carrier, but inserted
mismatches are SYNTHETIC. Never count them as actual external discovered bugs.
"""
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path
from risu_mcp_authority import verify
from risu_mcp_observations import ObservationError

CASES=[('before_change',20,'qualified'),('after_list_change',23,'quarantined'),
       ('after_refresh',25,'qualified')]

def raw_lines(raw):
    return [bytes(x)+b'\n' for x in raw.splitlines()]

def product(out,contract,witness):
    report=verify(out/'mutated_stdio.jsonl',contract,witness)
    (out/'product_report.json').write_text(
        json.dumps(report,indent=2,ensure_ascii=False,sort_keys=True)+'\n')
    return report

def execute(root:Path,target:Path):
    evidence=root/'.b16-source'
    original=(evidence/'original_stdio.jsonl').read_bytes()
    origin=json.loads((evidence/'origin.json').read_text())
    contract=json.loads((evidence/'contract.json').read_text())
    witness=json.loads((evidence/'state_witness.json').read_text())
    assert origin['case']=='AISH' and origin['status']=='CAPTURED_ORIGINAL'
    assert origin['source_commit']=='c9ad99acac291dd3a7b38162b6159bf5b01a1ed9'
    assert hashlib.sha256(original).hexdigest()==origin['trace_sha256']
    assert witness['trace_sha256']==origin['trace_sha256']
    if target.exists():raise ValueError('Refuse to overwrite existing synthetic evidence')
    target.mkdir(parents=True)
    records=[json.loads(x) for x in original.splitlines()]
    request_by_id={x['id']:x for x in records if x.get('method')=='tools/call'}
    response_positions={x['id']:i for i,x in enumerate(records)
                        if type(x) is dict and 'id' in x and 'method' not in x}
    assert all(request_by_id[k]['params']['name']=='structured' for _,k,_ in CASES)
    firstpass=verify(evidence/'original_stdio.jsonl',contract,witness)
    assert firstpass['summary']['qualified_passes']==2
    assert firstpass['summary']['observed_mismatches']==0
    ledger=[]
    for label,request_id,expected in CASES:
        position=response_positions[request_id]
        changed=list(original.splitlines(keepends=True))
        response=json.loads(changed[position])
        assert response['id']==request_id
        assert response['result']['structuredContent']['count']==3
        response['result']['structuredContent']['count']='three'
        changed[position]=(json.dumps(response,ensure_ascii=False,separators=(',',':'))+'\n').encode()
        synthetic=b''.join(changed)
        assert synthetic!=original and sum(a!=b for a,b in zip(
            original.splitlines(),synthetic.splitlines()))==1
        output=target/label
        output.mkdir()
        (output/'mutated_stdio.jsonl').write_bytes(synthetic)
        altered=json.loads(json.dumps(witness))
        altered['trace_sha256']=hashlib.sha256(synthetic).hexdigest()
        (output/'synthetic_witness.json').write_text(
            json.dumps(altered,indent=2,sort_keys=True)+'\n')
        report=product(output,contract,altered)
        s=report['summary']
        assert s['observed_mismatches']==1,(label,s)
        assert s['qualified_mismatches']==int(expected=='qualified'),(label,s)
        assert s['quarantined_mismatches']==int(expected=='quarantined'),(label,s)
        checks=[x for x in report['checks'] if x['observed']=='MISMATCH']
        assert len(checks)==1
        ledger.append({'case':label,'altered_id':request_id,
                       'type':'SYNTHETIC_MUTATION_NOT_REAL_BUG',
                       'original_sha256':origin['trace_sha256'],
                       'mutated_sha256':hashlib.sha256(synthetic).hexdigest(),
                       'observation':'MISMATCH','authority':checks[0]['disposition'],
                       'catalog_hash':checks[0]['catalog_sha256']})
    # Negative evidence binding. Same altered wire with original unmodified
    # witness MUST be rejected, even if the visible result looks plausible.
    try:
        verify(target/'before_change/mutated_stdio.jsonl',contract,witness)
    except ObservationError:
        negative='REJECTED_WRONG_RAW_TRACE_HASH'
    else:
        raise AssertionError('Tampered wire incorrectly accepted with stale witness')
    result={'schema':'risu-b16-original-stdio-synthetic-mutation-audit-v1',
            'original_native_upstream':'AI-Shell-Team/aish',
            'original_source_sha':'c9ad99acac291dd3a7b38162b6159bf5b01a1ed9',
            'mutation_not_upstream_bug':True,'mutations':ledger,
            'negative_hash_binding':negative,
            'interpretation':'Original upstream always returned valid structured output. These three errors were inserted offline after freezing B16; they prove sensitivity and authority gating under controlled mutation only.'}
    (target/'SYNTHETIC_INJECTION_LEDGER.json').write_text(
        json.dumps(result,indent=2,ensure_ascii=False,sort_keys=True)+'\n')
    print('B16_FROZEN_SOURCE_WIRE_MUTATIONS',json.dumps({
        'independent_original_calls':origin['calls_executed'],
        'synthetic_qualified':2,'synthetic_quarantined':1,
        'tampered_binding':negative},sort_keys=True))

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--original',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    execute(a.original,a.out)
if __name__=='__main__':
    main()
