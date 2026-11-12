"""Convert frozen B14 development artifacts into explicit B15 product contracts.

Development-only transformation. No claim B14 was a heldout test of B15.
Produces state witnesses from *original* independently captured SQLite snapshots,
never from the MCP server's success/error text, and verifies every raw message.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

BASE = {'SP':'a6a6f196b315b11e17929aeeb274821f5a0e6ed0',
        'ME':'05191e95d1ca74f7c26312ae071f5fab42c19601'}

def digest(x):
    return hashlib.sha256(json.dumps(x,ensure_ascii=False,
                    sort_keys=True,separators=(',',':')).encode('utf-8')).hexdigest()

def generate(case: str, root: Path, destination: Path):
    capture = root/'.b14-evidence'
    origin=json.loads((capture/'origin.json').read_text('utf-8'))
    calls=json.loads((capture/'unmodified_calls.json').read_text('utf-8'))
    raw=(capture/'original_stdio.jsonl').read_bytes()
    assert origin['case']==case and origin['source_commit']==BASE[case]
    assert origin['status']=='CAPTURED_NATIVE_STDIO'
    trace_sha=hashlib.sha256(raw).hexdigest()
    assert origin['stdout_sha256']==trace_sha
    assert len(calls)==6
    lines={}
    for no, line in enumerate(raw.splitlines(),1):
        msg=json.loads(line)
        if 'id' not in msg:continue
        ident=msg['id']
        direction='request' if 'method' in msg else 'response'
        lines[(ident,direction)]=no
    witnesses=[]
    for item in calls:
        n=item['call_id']
        assert item['response']==json.loads(raw.splitlines()[lines[(n,'response')]-1])
        assert item['tool']==json.loads(raw.splitlines()[lines[(n,'request')]-1])['params']['name']
        witnesses.append({
            'session':'default','request_line':lines[(n,'request')],
            'response_line':lines[(n,'response')],'tool':item['tool'],
            'before_sha256':digest(item['before']),'after_sha256':digest(item['after'])
        })
    if case=='SP':
        rules=[
            {'id':'sp_readonly_guard','tool':'execute_read_query',
             'kind':'state-unchanged',
             'when':{'query':'DELETE FROM records WHERE id=1 RETURNING id'}},
            {'id':'sp_page_json','tool':'execute_read_query',
             'kind':'json-object','when':{'offset':0,
                'query':'SELECT id,label FROM records ORDER BY id'},
             'carrier':'single-text-json',
             'required':{'/result/rows':'array'}}
        ]
    else:
        rules=[
            {'id':'me_query_guard','tool':'query','kind':'state-unchanged',
             'when':{'sql':"UPDATE records SET label='RISU_B14_WRONG_PATH' WHERE id=1"}},
            {'id':'me_positive_writer','tool':'update_data','kind':'state-changed',
             'when':{'table':'records','sql':"UPDATE records SET label='RISU_B14_POSITIVE' WHERE id=2"}},
            {'id':'me_valid_stats','tool':'analyze_table','kind':'json-object',
             'when':{'table':'records','analysis_type':'basic'},
             'carrier':'single-text-json',
             'required':{'/row_count':'integer','/null_counts':'object'}}
        ]
    destination.mkdir(parents=True,exist_ok=False)
    (destination/'original_stdio.jsonl').write_bytes(raw)
    (destination/'observation_contract.json').write_text(
        json.dumps({'schema':'risu-mcp-observation-contract-v1','rules':rules},
                  indent=2,ensure_ascii=False)+'\n')
    (destination/'state_witness.json').write_text(
        json.dumps({'schema':'risu-mcp-state-witness-v1',
                    'trace_sha256':trace_sha,'records':witnesses},
                   indent=2,ensure_ascii=False)+'\n')
    print('B15_DEV_B14_SOURCE_PREPARED',case,trace_sha)

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--case',choices=sorted(BASE),required=True)
    p.add_argument('--source',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    generate(a.case,a.source,a.out)
if __name__=='__main__':main()
