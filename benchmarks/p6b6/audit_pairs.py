"""Independent old-vs-official-fix audit of genuine upstream MCP Memory Server.

This scorer separately applies a standard JSON Schema Draft-07 validator to the
raw captured stdio bytes. It never infers defects solely from RISU output.
The three read operations arise from ONE independently reported upstream bug.
"""
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path
from jsonschema import Draft7Validator

COMMITS={'old':'861c11b786b3efbc87eb2e878a4039d33846a031',
         'fixed':'72e11113edff5919e74de1d69b71203991fe2f05'}
READS=('read_graph','search_nodes','open_nodes')
EXPECTED_OLD_COUNTS={'read_graph':3,'search_nodes':3,'open_nodes':1}
DRAFT7='http://json-schema.org/draft-07/schema#'

def evaluate(root:Path)->dict:
    scored={}
    lock=None
    for mode in COMMITS:
        for scenario in ('seeded','empty'):
            src=root/(mode+'-'+scenario)
            origin=json.loads((src/'origin.json').read_text())
            raw=(src/'raw_stdio.jsonl').read_bytes()
            report=json.loads((src/'risu_report.json').read_text())
            rows=[json.loads(x) for x in raw.splitlines() if x.strip()]
            assert origin['schema']=='risu-p6b6-upstream-memory-raw-stdio-v1'
            assert origin['commit']==COMMITS[mode] and origin['mode']==mode
            assert origin['scenario']==scenario and origin['actual_stdio'] is True
            assert origin['synthetic_data_only'] is True
            assert origin['repository']=='https://github.com/modelcontextprotocol/servers'
            assert origin['package']=='@modelcontextprotocol/server-memory'
            assert origin['package_version']=='0.6.3'
            assert len(origin['lock_sha256'])==64
            if lock is None:lock=origin['lock_sha256']
            assert lock==origin['lock_sha256'],'dependency lock changed across comparisons'
            assert origin['trace_sha256']==report['capture_sha256']==hashlib.sha256(raw).hexdigest()
            assert origin['message_count']==len(rows)==(11 if scenario=='seeded' else 7)
            assert rows[0]['method']=='initialize'
            assert rows[2]['method']=='notifications/initialized'
            assert rows[3]['method']=='tools/list' and rows[4]['id']==2
            assert origin['negotiated_protocol']==rows[1]['result']['protocolVersion']
            assert report['origin_integrity']=='UNATTESTED_LOCAL_CAPTURE'
            assert report['capture_status']=='PARSED_BOUNDED_JSONRPC'
            catalog={t['name']:t for t in rows[4]['result']['tools']}
            outcomes=origin['tool_outcomes']
            expected=READS if scenario=='seeded' else ('read_graph',)
            assert set(outcomes)==set(expected)
            raw_names=[x['params']['name'] for x in rows if x.get('method')=='tools/call']
            assert tuple(raw_names)==expected
            independent={}
            for index,name in enumerate(expected,10):
                response=next(x for x in rows if x.get('id')==index and 'result' in x)
                schema=catalog[name]['outputSchema']
                assert schema['$schema']==DRAFT7
                Draft7Validator.check_schema(schema)
                value=response['result']['structuredContent']
                assert response['result'].get('isError',False) is False
                assert outcomes[name]['kind']=='MCP_RESULT'
                assert outcomes[name]['is_error'] is False
                assert outcomes[name]['structured_content_present'] is True
                # This is the independent oracle, NOT RISU's verdict.
                errors=list(Draft7Validator(schema).iter_errors(value))
                independent[name]=len(errors)
                if mode=='old' and scenario=='seeded':
                    assert len(errors)==EXPECTED_OLD_COUNTS[name]
                    assert all(e.validator=='additionalProperties' for e in errors)
                    # Stored type discriminator is forbidden by declared schema.
                    assert all('type' in e.instance for e in errors)
                else:
                    assert not errors
            expected_count=3 if scenario=='seeded' else 1
            assert report['summary']['tool_call_responses_matched']==expected_count
            assert report['summary']['structured_values_schema_checked']==expected_count
            assert report['summary']['unverified_count']==0,report['unverified']
            assert report['origin_integrity']=='UNATTESTED_LOCAL_CAPTURE'
            expected_rules=['RMC502']*3 if mode=='old' and scenario=='seeded' else []
            actual_rules=[x['rule_id'] for x in report['findings']]
            assert actual_rules==expected_rules,(mode,scenario,actual_rules)
            if mode=='old' and scenario=='seeded':
                assert report['semantic_verification']=='OBSERVED_MISMATCHES_IN_CAPTURE'
            else:
                assert report['semantic_verification']=='CHECKED_NO_MISMATCHES'
            scored[mode+'-'+scenario]={
                'source_commit':origin['commit'],'calls':len(expected),
                'independent_schema_violation_instances':sum(independent.values()),
                'independent_schema_errors_by_tool':independent,
                'risu_schema_checked':report['summary']['structured_values_schema_checked'],
                'risu_issue_related_findings':len(actual_rules),
                'risu_unverified':report['summary']['unverified_count'],
                'trace_sha256':origin['trace_sha256']}
    assert scored['old-seeded']['independent_schema_violation_instances']==7
    assert scored['old-seeded']['risu_issue_related_findings']==3
    assert scored['fixed-seeded']['independent_schema_violation_instances']==0
    assert scored['fixed-seeded']['risu_issue_related_findings']==0
    for control in ('old-empty','fixed-empty'):
        assert scored[control]['independent_schema_violation_instances']==0
        assert scored[control]['risu_issue_related_findings']==0
    return {
        'schema':'risu-p6b6-official-real-server-fix-independent-oracle-v2',
        'status':'PASS',
        'issue':'https://github.com/modelcontextprotocol/servers/issues/3074',
        'official_merged_pr':'https://github.com/modelcontextprotocol/servers/pull/3213',
        'upstream_defect_families':1,
        'before_buggy_operations':3,'after_buggy_operations':0,
        'independent_schema_errors_before':7,'independent_schema_errors_after':0,
        'targeted_risu_RMC502_old':3,'targeted_risu_RMC502_fixed':0,
        'empty_store_negative_controls':2,
        'independent_holdout_score':None,
        'qualification':'Targeted Draft-07 compatibility repair motivated by this known defect. NOT an unseen-bug recall estimate.',
        'raw_transport':'REAL_SEPARATE_PROCESS_STDIO_JSONRPC',
        'synthetic_file_only':True,'results':scored}

if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--root',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    output=evaluate(a.root)
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(output,sort_keys=True,indent=2)+'\n')
    print('P6B6_PINNED_MEMORY_REAL_STDIO_INDEPENDENT_ORACLE',output['status'],
          'independent_errors',output['independent_schema_errors_before'],'->',
          output['independent_schema_errors_after'],flush=True)
