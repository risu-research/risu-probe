"""P6-B9 PHP673 replay adapter: real SDK serializer bytes, synthetic envelope, independent pair adjudication."""
from __future__ import annotations
import argparse
import json
from pathlib import Path

OUTPUT_SCHEMAS={
    'explicit_null':{'type':'null'},
    'from_array_null':{'type':'null'},
    'explicit_false':{'type':'boolean'},
    'explicit_zero':{'type':'integer'},
    'explicit_empty':{'type':'string'},
}

def read(path:Path)->dict:
    x=json.loads(path.read_text(encoding='utf-8'))
    assert x['schema']=='p6b9-php673-actual-upstream-serializer-v1'
    assert x['origin']=='ACTUAL_PHP_SDK_SERIALIZED_OBJECT'
    assert set(x['cases'])==set(OUTPUT_SCHEMAS)|{'omitted'}
    return x

def trace(capture:dict)->list[dict]:
    tools=[{'name':key,'inputSchema':{'type':'object'},
            'outputSchema':schema} for key,schema in OUTPUT_SCHEMAS.items()]
    rows=[
        {'jsonrpc':'2.0','id':1,'method':'tools/list','params':{}},
        {'jsonrpc':'2.0','id':1,'result':{'tools':tools}},
    ]
    for i,key in enumerate(OUTPUT_SCHEMAS,2):
        rows += [
            {'jsonrpc':'2.0','id':i,'method':'tools/call','params':{'name':key,'arguments':{}}},
            {'jsonrpc':'2.0','id':i,'result':capture['cases'][key]},
        ]
    return rows

def write_trace(capture_path:Path,out:Path)->None:
    rows=trace(read(capture_path))
    out.write_text(''.join(json.dumps(v,sort_keys=True,ensure_ascii=False)+'\n' for v in rows))
    
def adjudicate(old:dict,fixed:dict,ro:dict,rf:dict)->dict:
    o=old['cases'];f=fixed['cases']
    def present(data,k): return 'structuredContent' in data[k]
    null_old=not present(o,'explicit_null')
    null_fixed=present(f,'explicit_null') and f['explicit_null']['structuredContent'] is None
    roundtrip=not present(o,'from_array_null') and present(f,'from_array_null') and f['from_array_null']['structuredContent'] is None
    ctrl={
      'omitted_absent_both':not present(o,'omitted') and not present(f,'omitted'),
      'boolean_false_both':o['explicit_false'].get('structuredContent') is False and f['explicit_false'].get('structuredContent') is False,
      'integer_zero_both':type(o['explicit_zero'].get('structuredContent')) is int and o['explicit_zero']['structuredContent']==0 and type(f['explicit_zero'].get('structuredContent')) is int and f['explicit_zero']['structuredContent']==0,
      'empty_string_both':o['explicit_empty'].get('structuredContent')=='' and f['explicit_empty'].get('structuredContent')=='',
    }
    verified=null_old and null_fixed and roundtrip and all(ctrl.values())
    old_codes=[v['rule_id'] for v in ro.get('findings',[])]
    fixed_codes=[v['rule_id'] for v in rf.get('findings',[])]
    old_bad=old_codes.count('RMC501')
    fixed_bad=fixed_codes.count('RMC501')
    detected=verified and old_bad==2 and fixed_bad==0 and len(fixed_codes)==0
    return {
       'schema':'risu-p6b9-php673-adjudicated-result-v1',
       'family':'PHP673', 'role':'PRELOCKED_NEW_INDEPENDENT_FAMILY',
       'evidence_transport':'REAL_SDK_SERIALIZATION_AND_RECONSTRUCTED_JSONRPC_ENVELOPE_NOT_ORIGINAL_STDIO',
       'upstream_reproduction':'VERIFIED_BUG_FIX' if verified else 'NOT_VERIFIED',
       'source_normal_controls':ctrl,
       'old_missing_null_count':sum(not present(o,k) for k in ('explicit_null','from_array_null')),
       'fixed_missing_null_count':sum(not present(f,k) for k in ('explicit_null','from_array_null')),
       'old_findings':old_codes,'fixed_findings':fixed_codes,
       'detected_family':bool(detected),
       'confirmed_direct_schema_finding':bool(detected),
       'family_count':1 if verified else 0,
       'claim_boundary':'One root cause; two manifestations. PHP SDK serializer executed, but no actual MCP wire bytes captured.'
    }

def main():
    p=argparse.ArgumentParser()
    p.add_argument('mode',choices=('trace','score'))
    p.add_argument('files',nargs='+',type=Path)
    a=p.parse_args()
    if a.mode=='trace':
        assert len(a.files)==2
        write_trace(*a.files)
    else:
        assert len(a.files)==5
        old,fixed,ro,rf,out=a.files
        result=adjudicate(read(old),read(fixed),json.loads(ro.read_text()),json.loads(rf.read_text()))
        out.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
        print(json.dumps(result,indent=2,sort_keys=True))
        if result['upstream_reproduction']!='VERIFIED_BUG_FIX' or not result['detected_family']:
            raise SystemExit('PHP673 independent adjudication/detection failed')
if __name__=='__main__':main()
