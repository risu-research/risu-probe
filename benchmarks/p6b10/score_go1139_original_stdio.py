"""Confirm former B9 source-level GO1139 now reproduced on original stdio bytes.

This is *provenance strengthening of a development family*, not new heldout.
"""
import argparse
import hashlib
import json
from pathlib import Path

def read(p:Path):
    o=json.loads((p/'origin.json').read_text())
    raw=(p/'original_stdio.jsonl').read_bytes()
    assert hashlib.sha256(raw).hexdigest()==o['trace_sha256']
    assert o['evidence_type']=='RAW_STDIO_ORIGINAL_SERVER_JSONRPC_RESPONSE_BYTES'
    messages=[json.loads(x) for x in raw.splitlines() if x.strip()]
    return o,messages

def tool_result(messages,id):
    results=[v for v in messages if v.get('id')==id and 'method' not in v]
    assert len(results)==1
    return results[0].get('result',{})

def score(old:Path,fixed:Path,oldr:Path,fixedr:Path)->dict:
    o,om=read(old);f,fm=read(fixed)
    assert o['revision']=='old' and f['revision']=='fixed'
    bad_old=tool_result(om,3);bad_fixed=tool_result(fm,3)
    normal_old=tool_result(om,4);normal_fixed=tool_result(fm,4)
    original_repro=(not bad_old.get('isError',False) and
                    bad_old.get('structuredContent',{}).get('temperature')=='not-a-number'
                    and bad_fixed.get('isError') is True)
    normal=(normal_old.get('isError') is not True and
            normal_fixed.get('isError') is not True and
            normal_old.get('structuredContent',{}).get('temperature')==21 and
            normal_fixed.get('structuredContent',{}).get('temperature')==21)
    a=json.loads(oldr.read_text());b=json.loads(fixedr.read_text())
    old_codes=[v['rule_id'] for v in a['findings']]
    fix_codes=[v['rule_id'] for v in b['findings']]
    detection=(old_codes==['RMC502'] and fix_codes==[] and
               a['summary']['structured_values_schema_checked']==2 and
               b['summary']['structured_values_schema_checked']==1)
    return {'schema':'risu-p6b10-go1139-original-stdio-confirmation-v1',
            'family':'GO1139','role':'PROVENANCE_UPGRADE_OF_PREVIOUSLY_USED_B9_NOT_NEW_HOLDOUT',
            'old_original_stdout_trace_sha256':o['trace_sha256'],
            'fixed_original_stdout_trace_sha256':f['trace_sha256'],
            'real_pinned_sdk_source_before_fix_reproduced':bool(original_repro),
            'normal_control_passed':bool(normal),
            'frozen_risu_original_stdio_detected':bool(detection),
            'old_findings':old_codes,'fixed_findings':fix_codes,
            'protocol_negotiated_old':o['protocol_negotiated'],
            'protocol_negotiated_fixed':f['protocol_negotiated'],
            'provenance':'REAL_UPSTREAM_MCP_GO_STDIO_SDK_WITH_SYNTHETIC_GO_TEST_SERVER',
            'limits':'Test wrapper registers synthetic tools in pinned upstream SDK. No production server, external remote endpoint or user data.'}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('old',type=Path);ap.add_argument('fixed',type=Path)
    ap.add_argument('old_risu',type=Path);ap.add_argument('fixed_risu',type=Path)
    ap.add_argument('output',type=Path)
    a=ap.parse_args()
    r=score(a.old,a.fixed,a.old_risu,a.fixed_risu)
    a.output.write_text(json.dumps(r,indent=2,sort_keys=True)+'\n')
    print(json.dumps(r,indent=2,sort_keys=True))
    if not(r['real_pinned_sdk_source_before_fix_reproduced'] and
           r['normal_control_passed'] and r['frozen_risu_original_stdio_detected']):
        raise SystemExit('Original stdio provenance upgrade is NOT verified')
if __name__=='__main__':main()
