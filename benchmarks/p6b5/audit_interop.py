"""Audit FastMCP raw stdio output independently; controls never count as novel bugs."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

def audit(source: Path, report: Path, out: Path) -> None:
    raw=(source/'raw_stdio.jsonl').read_bytes()
    origin=json.loads((source/'origin.json').read_text())
    result=json.loads(report.read_text())
    assert origin['schema']=='risu-p6b5-interop-origin-v1'
    assert (origin['framework'],origin['version']) in (('fastmcp','2.13.2'),('fastmcp','3.1.1'),('mcp','1.29.1'))
    assert origin['transport']=='SEPARATE_PROCESS_LITERAL_STDIO_JSONRPC'
    assert origin['trace_sha256']==hashlib.sha256(raw).hexdigest()
    assert origin['messages']==11
    assert origin['data']=='PUBLIC_SYNTHETIC_ONLY'
    assert origin['remote_connections'] is False and origin['no_untrusted_servers'] is True
    assert result['capture_sha256']==origin['trace_sha256']
    assert result['origin_integrity']=='UNATTESTED_LOCAL_CAPTURE'
    assert result['summary']['messages_parsed']==11
    assert result['summary']['tool_call_responses_matched']==3
    assert result['summary']['successful_tool_calls_with_catalog']==2
    assert result['summary']['structured_values_schema_checked']==2
    assert result['summary']['findings']==0
    assert result['summary']['unverified_count']==1
    assert result['unverified'][0]['code']=='EXECUTION_ERROR'
    assert result['semantic_verification']=='INCOMPLETE_MEANING_CHECK'
    # Actual bidirectional JSON-RPC, not a re-serialized SDK object
    messages=[json.loads(x) for x in raw.splitlines() if x.strip()]
    assert len(messages)==11
    assert messages[0]['method']=='initialize'
    assert messages[1]['id']==messages[0]['id']
    assert messages[1]['result']['protocolVersion']==origin['negotiated_protocol']
    assert messages[3]['method']=='tools/list'
    assert messages[4]['id']==messages[3]['id']
    assert messages[-1]['result']['isError'] is True
    names=[x['params']['name'] for x in messages if x.get('method')=='tools/call']
    assert names==['get_count','get_label','get_error']
    audit_record={
      'schema':'risu-p6b5-crossframework-v1','status':'PASS',
      'framework':origin['framework'],'framework_version':origin['version'],
      'negotiated_protocol':origin['negotiated_protocol'],'actual_stdio':True,
      'known_good_schema_checks':2,'normal_tool_error_exempted':1,
      'observed_findings':0,'false_alarm_for_these_controls':0,
      'not_scored_as_global_fpr':True,
      'trace_sha256':origin['trace_sha256'],
      'not_claimed':'No independent production bug discovery or certified real-world FPR'
    }
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(audit_record,indent=2,sort_keys=True)+'\n')
    print('P6B5_ACTUAL_EXTERNAL_STDIO_AUDIT',json.dumps(audit_record,sort_keys=True),flush=True)

if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--source',type=Path,required=True)
    p.add_argument('--report',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    audit(a.source,a.report,a.out)
