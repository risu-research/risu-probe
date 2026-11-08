"""P6-B9 GO1139 upstream-origin catalog/response adapter and independent scoring."""
from __future__ import annotations
import argparse
import json
from pathlib import Path

def read(path:Path)->dict:
    data=json.loads(path.read_text())
    assert data['schema']=='risu-p6b9-go1139-real-mcpserver-jsonrpc-v1'
    assert data['source']=='REAL_UPSTREAM_GO_MCP_SERVER_HANDLEMESSAGE'
    assert set(data['cases'])=={'catalog','bad_raw','good_raw'}
    for key in data['cases']:
        assert data['cases'][key].get('jsonrpc')=='2.0'
    return data

def make_trace(source:dict)->list[dict]:
    c=source['cases']
    catalog=c['catalog']
    assert isinstance(catalog.get('result'),dict)
    listed={x['name'] for x in catalog['result']['tools']}
    assert {'bad_raw','good_raw'}.issubset(listed)
    rows=[
      {'jsonrpc':'2.0','id':1,'method':'tools/list','params':{}},
      {'jsonrpc':'2.0','id':1,'result':catalog['result']},
    ]
    for i,key in enumerate(('bad_raw','good_raw'),2):
        response=c[key]
        rows.append({'jsonrpc':'2.0','id':i,'method':'tools/call',
                     'params':{'name':key,'arguments':{'id':2}}})
        if 'result' in response:
            rows.append({'jsonrpc':'2.0','id':i,'result':response['result']})
        elif 'error' in response:
            rows.append({'jsonrpc':'2.0','id':i,'error':response['error']})
        else:
            raise ValueError('Real SDK result has neither result nor error')
    return rows

def adjudicate(before:dict,after:dict,old_risu:dict,fixed_risu:dict)->dict:
    def result(source,key):
        return source['cases'][key].get('result',{})
    o=result(before,'bad_raw');f=result(after,'bad_raw')
    og=result(before,'good_raw');fg=result(after,'good_raw')
    upstream_failure=(o.get('isError') is not True and
        isinstance(o.get('structuredContent'),dict) and
        o['structuredContent'].get('temperature')=='not-a-number' and
        f.get('isError') is True)
    normal_control=(og.get('isError') is not True and fg.get('isError') is not True and
        og.get('structuredContent',{}).get('temperature')==21 and
        fg.get('structuredContent',{}).get('temperature')==21)
    old_findings=[x['rule_id'] for x in old_risu.get('findings',[])]
    new_findings=[x['rule_id'] for x in fixed_risu.get('findings',[])]
    detected=upstream_failure and normal_control and 'RMC502' in old_findings and not new_findings
    return {
        'schema':'risu-p6b9-go1139-independently-scored-v1',
        'family':'GO1139', 'role':'PRELOCKED_NEW_INDEPENDENT_FAMILY',
        'upstream_bugfix_reproduced':bool(upstream_failure),
        'normal_control_pass':bool(normal_control),
        'old_findings':old_findings,'fixed_findings':new_findings,
        'detected_family':bool(detected),
        'direct_schema_mismatch_detected':bool(detected),
        'provenance':'ACTUAL_GO_MCP_SERVER_HANDLER_RESPONSES_WITH_ADAPTER_IDS_NOT_VERBATIM_STDIO',
        'limitation':'One Go root cause tested using invalid RawStructuredContent and valid control, not the large-integer input sub-case. Source tools/list originated in SDK.'
    }

def main():
    a=argparse.ArgumentParser()
    a.add_argument('mode',choices=['trace','score'])
    a.add_argument('files',nargs='+',type=Path)
    args=a.parse_args()
    if args.mode=='trace':
        assert len(args.files)==2
        rows=make_trace(read(args.files[0]))
        args.files[1].write_text(''.join(json.dumps(x,sort_keys=True)+'\n' for x in rows))
    else:
        assert len(args.files)==5
        o,f,ro,rf,out=args.files
        verdict=adjudicate(read(o),read(f),json.loads(ro.read_text()),json.loads(rf.read_text()))
        out.write_text(json.dumps(verdict,indent=2,sort_keys=True)+'\n')
        print(json.dumps(verdict,indent=2,sort_keys=True))
        if not verdict['normal_control_pass']:
            raise SystemExit('Normal-control regression/invalid execution: do not score this family')
if __name__=='__main__':main()
