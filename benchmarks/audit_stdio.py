"""Cross-check native separate-process SDK stdio frame order and expected verdicts."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

CASES={'sdk_real_stdio':set(), 'mutation_stdio_missing':{'RMC501'},'mutation_stdio_wrong':{'RMC502'}}

def audit(folder:Path)->dict:
    meta=json.loads((folder/'stdio_origin.json').read_text())
    assert meta['schema']=='risu-p6b4-native-mcp-stdio-v1'
    assert meta['official_sdk']=='mcp==2.1.0, mcp-types==2.1.0'
    assert meta['negotiated_protocol']=='2025-11-25'
    assert meta['transport']=='LITERAL_SEPARATE_PROCESS_STDIO_JSONRPC'
    assert meta['original_bytes_captured'] is True
    assert meta['external_network_called'] is False
    assert meta['secret_data_used'] is False
    assert meta['mutated_controls_are_real_wire'] is False
    summary={}
    baseline=None
    for name,rules in CASES.items():
        raw=(folder/(name+'.jsonl')).read_bytes()
        rows=[json.loads(line) for line in raw.splitlines() if line.strip()]
        assert len(rows)==9, (name,len(rows))
        assert [r['id'] for r in rows if 'id' in r and 'method' in r]==[100,101,102,103]
        assert [r['id'] for r in rows if 'id' in r and ('result' in r or 'error' in r)]==[100,101,102,103]
        assert rows[2]['method']=='notifications/initialized'
        assert rows[1]['result']['protocolVersion']=='2025-11-25'
        catalog=rows[4]['result']['tools']
        assert {'get_count','get_total'}<={t['name'] for t in catalog}
        assert all('outputSchema' in t for t in catalog)
        assert rows[6]['result'].get('isError',False) is False
        assert rows[8]['result'].get('isError',False) is False
        if name=='sdk_real_stdio':
            baseline=rows
            assert meta['original_sha256']==hashlib.sha256(raw).hexdigest()
        else:
            assert rows[:6]==baseline[:6] and rows[7]==baseline[7]
        record=json.loads((folder/(name+'_audit.json')).read_text())
        assert record['origin_integrity']=='UNATTESTED_LOCAL_CAPTURE'
        assert record['capture_sha256']==hashlib.sha256(raw).hexdigest()
        found={x['rule_id'] for x in record['findings']}
        assert found==rules,(name,found,rules)
        assert record['summary']['tool_call_responses_matched']==2
        assert record['summary']['unverified_count']==0
        assert record['source_analysis']=='NOT_PERFORMED'
        summary[name]={'rules':sorted(found),'schema_checks':record['summary']['structured_values_schema_checked'],
                       'sha256':record['capture_sha256']}
    return {'schema':'risu-p6b4-native-stdio-independent-audit-v1', 'status':'PASS',
            'actual_wire_sample':'LOCAL_SYNTHETIC_SEPARATE_PROCESS_STDIO',
            'negative_samples':'SYNTHETIC_MUTATION_NOT_REAL_SERVER_OUTPUT',
            'no_external_bug_claim':True,'cases':summary}

if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--results',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    result=audit(a.results)
    a.out.write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    print('P6B4_REAL_STDIO_INDEPENDENT_AUDIT_PASS',len(result['cases']))
