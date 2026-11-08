"""P6B9 AG2 real toolkit discovery, normalized SDK JSONRPC records and heldout score."""
import argparse
import json
from pathlib import Path

def read(p):
    a=json.loads(p.read_text())
    assert a['schema']=='risu-p6b9-ag23262-real-upstream-client-v1'
    assert a['source']=='ACTUAL_AG2_TOOLKIT_LOGIC_WITH_IN_MEMORY_MCP_SESSION_TEST_DOUBLE'
    return a

def trace(data,key):
    return data[key]['captured_sdk_method_values']

def adjudicate(old,new,orig_o,orig_n,ctrl_o,ctrl_n):
    a=old['paginated'];b=new['paginated']
    c=old['single_page_normal'];d=new['single_page_normal']
    old_reproduced=(a['registered_tool_names']==['first'] and a['actual_list_requests']==1
                  and b['registered_tool_names']==['first','second'] and b['actual_list_requests']==2)
    controls=(c['registered_tool_names']==d['registered_tool_names']==['first']
             and c['actual_list_requests']==d['actual_list_requests']==1
             and not ctrl_o['findings'] and not ctrl_n['findings']
             and not ctrl_o['unverified'] and not ctrl_n['unverified'])
    old_gap={e['code'] for e in orig_o['unverified']}
    new_gap={e['code'] for e in orig_n['unverified']}
    symptom=('INCOMPLETE_CATALOG_PAGINATION' in old_gap and
             'INCOMPLETE_CATALOG_PAGINATION' not in new_gap and
             orig_n['summary']['latest_catalog_declarations_indexed']==2)
    return {
      'schema':'risu-p6b9-ag23262-eval-v1',
      'family':'AG23262','role':'PRELOCKED_NEW_INDEPENDENT_FAMILY',
      'upstream_bugfix_reproduced':bool(old_reproduced),
      'single_page_normal_control':bool(controls),
      'old_unverified':sorted(old_gap),'fixed_unverified':sorted(new_gap),
      'incomplete_catalog_symptom_detected':bool(old_reproduced and symptom and controls),
      'root_cause_inferred_by_risu':False,
      'evidence':'REAL_PINNED_AG2_DISCOVERY_LOGIC_MOCKED_IN_MEMORY_SDK_SESSION_NOT_WIRE',
      'limitation':'The tool-discovery session is a test double returning genuine MCP SDK ListToolsResult objects. Cursor calls are actual library logic, but test recorded synthetic JSONRPC messages.'
    }

def main():
    p=argparse.ArgumentParser()
    p.add_argument('mode',choices=('trace','score'))
    p.add_argument('files',type=Path,nargs='+')
    p.add_argument('--segment',choices=('paginated','single_page_normal'),default='paginated')
    a=p.parse_args()
    if a.mode=='trace':
        assert len(a.files)==2
        rows=trace(read(a.files[0]),a.segment)
        a.files[1].write_text(''.join(json.dumps(r,sort_keys=True)+'\n' for r in rows))
    else:
        assert len(a.files)==7
        o,f,ro,rf,co,cf,out=a.files
        r=adjudicate(read(o),read(f),*(json.loads(p.read_text()) for p in [ro,rf,co,cf]))
        out.write_text(json.dumps(r,indent=2,sort_keys=True)+'\n')
        print(json.dumps(r,indent=2,sort_keys=True))
        if not r['single_page_normal_control']:
            raise SystemExit('Normal control failed')
if __name__=='__main__':main()
