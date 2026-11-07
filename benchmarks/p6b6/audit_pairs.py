"""Independent, falsifiable audit of official MCP Memory Server PR 3213.

One defect family, three affected read operations; empty-store controls.
"""
import argparse,hashlib,json
from pathlib import Path
COMMITS={'old':'861c11b786b3efbc87eb2e878a4039d33846a031',
         'fixed':'72e11113edff5919e74de1d69b71203991fe2f05'}

def evaluate(root:Path)->dict:
    results={}
    for mode in COMMITS:
        for scenario in ('seeded','empty'):
            src=root/(mode+'-'+scenario)
            origin=json.loads((src/'origin.json').read_text())
            raw=(src/'raw_stdio.jsonl').read_bytes()
            report=json.loads((src/'risu_report.json').read_text())
            rows=[json.loads(x) for x in raw.splitlines() if x]
            assert origin['schema']=='risu-p6b6-upstream-memory-raw-stdio-v1'
            assert origin['commit']==COMMITS[mode] and origin['mode']==mode
            assert origin['scenario']==scenario and origin['actual_stdio'] is True
            assert origin['synthetic_data_only'] is True
            assert origin['package']=='@modelcontextprotocol/server-memory'
            assert origin['package_version']=='0.6.3'
            assert origin['trace_sha256']==report['capture_sha256']==hashlib.sha256(raw).hexdigest()
            assert origin['message_count']==len(rows)==(11 if scenario=='seeded' else 7)
            assert rows[0]['method']=='initialize'
            assert rows[2]['method']=='notifications/initialized'
            assert rows[3]['method']=='tools/list'
            assert rows[4]['id']==2 and rows[4]['result']['tools']
            assert origin['negotiated_protocol']==rows[1]['result']['protocolVersion']
            assert report['origin_integrity']=='UNATTESTED_LOCAL_CAPTURE'
            assert report['summary']['findings']==0
            outputs=origin['tool_outcomes']
            if scenario=='seeded':
                assert list(outputs)==['read_graph','search_nodes','open_nodes']
                if mode=='old':
                    assert all(x['kind']=='JSONRPC_ERROR' and x['reported_output_schema_rejection']
                               for x in outputs.values()),outputs
                    assert report['summary']['unverified_count']>=3
                    assert report['summary']['structured_values_schema_checked']==0
                else:
                    assert all(x['kind']=='MCP_RESULT' and x['is_error'] is False and
                               x['structured_content_present'] is True for x in outputs.values()),outputs
                    assert report['summary']['structured_values_schema_checked']==3
            else:
                assert list(outputs)==['read_graph']
                assert outputs['read_graph']['kind']=='MCP_RESULT'
                assert report['summary']['structured_values_schema_checked']==1
            results[mode+'-'+scenario]={
                'commit':origin['commit'],'trace_sha256':origin['trace_sha256'],
                'calls':len(outputs),'schema_checked':report['summary']['structured_values_schema_checked'],
                'reported_schema_rejections':sum(bool(x.get('reported_output_schema_rejection')) for x in outputs.values()),
                'risu_findings':report['summary']['findings'],
                'risu_unverified':report['summary']['unverified_count']}
    assert results['old-seeded']['reported_schema_rejections']==3
    assert results['fixed-seeded']['reported_schema_rejections']==0
    assert results['old-empty']['reported_schema_rejections']==0
    assert results['fixed-empty']['reported_schema_rejections']==0
    return {'schema':'risu-p6b6-external-upstream-fix-audit-v1','status':'PASS',
        'issue':'https://github.com/modelcontextprotocol/servers/issues/3074',
        'merged_pr':'https://github.com/modelcontextprotocol/servers/pull/3213',
        'independent_upstream_defect_families':1,
        'affected_operations':3,
        'negative_controls':2,
        'baseline_risu_true_positive_on_schema_mismatch':0,
        'baseline_risu_server_error_state':'PROTOCOL_ERROR_UNVERIFIED',
        'comment':'One known upstream defect; 3 dependent call observations, not 3 independent defects.',
        'results':results}

if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--root',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    result=evaluate(a.root)
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    print('P6B6_OFFICIAL_FIX_REAL_STDIO_AUDIT',result['status'],flush=True)
