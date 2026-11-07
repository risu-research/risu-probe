"""Independent local checks on SDK-normalized baseline and controlled mutations.

Not evidence of new external bugs. Does not trust the verifier's own score summary.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

EXPECTED={
    'sdk_real_normalized':set(),
    'mutation_missing_structured':{'RMC501'},
    'mutation_wrong_type':{'RMC502'},
    'mutation_error_exempt':set(),
}

def audit(folder:Path)->dict:
    meta=json.loads((folder/'origin.json').read_text())
    assert meta['schema']=='risu-p6b4-official-sdk-normalized-sample-v1'
    assert meta['capture_format']=='NORMALIZED_SDK_OBSERVED_OBJECTS_NOT_LITERAL_JSONRPC_WIRE'
    assert meta['sdk_version']=='2.1.0' and meta['origin_authenticated'] is False
    results={}
    for case,expected_rules in EXPECTED.items():
        p=folder/(case+'.jsonl')
        raw=p.read_bytes()
        frames=[json.loads(line) for line in raw.splitlines() if line.strip()]
        assert len(frames)==6 and all(x['session']=='sdk-local-fixture' for x in frames)
        assert [frames[i]['message']['method'] for i in [0,2,4]]==['tools/list','tools/call','tools/call']
        listing=frames[1]['message']['result']['tools']
        assert {t['name'] for t in listing}=={'get_count','get_total'}
        assert all('outputSchema' in t for t in listing)
        baseline=folder/(case+'_audit.json')
        result=json.loads(baseline.read_text())
        assert result['schema']=='risu-mcp-jsonrpc-trace-audit-v1'
        assert result['capture_sha256']==hashlib.sha256(raw).hexdigest()
        assert result['origin_integrity']=='UNATTESTED_LOCAL_CAPTURE'
        assert result['summary']['tool_call_requests']==2
        assert result['summary']['tool_call_responses_matched']==2
        codes={f['rule_id'] for f in result['findings']}
        assert codes==expected_rules,(case,codes,expected_rules)
        assert all(f['verdict']=='OBSERVED_IN_UNATTESTED_CAPTURE' for f in result['findings'])
        if case=='sdk_real_normalized':
            assert result['summary']['structured_values_schema_checked']==2
            assert result['summary']['unverified_count']==0
        if case=='mutation_error_exempt':
            assert result['summary']['unverified_count']>=1
            assert 'EXECUTION_ERROR' in {u['code'] for u in result['unverified']}
        results[case]={'codes':sorted(codes),'checked':result['summary']['structured_values_schema_checked'],
                       'unverified':result['summary']['unverified_count'],'sha256':result['capture_sha256']}
    return {'schema':'risu-p6b4-independent-observed-sdk-audit-v1',
            'status':'PASS','sample_size':4,'origin':'OFFICIAL_MCP_SDK_NORMALIZED_NOT_WIRE',
            'all_outputs_unattested':True,'positive_cases_are_injected_mutations':True,
            'no_new_external_bug_claim':True,'results':results}

if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--results',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    result=audit(a.results)
    a.out.write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    print('P6B4_INDEPENDENT_SDK_NORMALIZED_AUDIT_PASS',len(result['results']))
