"""Generate a reproducible, explicit MODEL-ONLY consumer-contract counterexample.

The built-in offline CLI cannot certify that a real generated server will
output the minimized case. That separate confirmation is done by the
isolated actual-MCP server runner (apps/run_live.py).
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys

from risu_diagnostics import _strict_same
from risu_evidence import _parse_json
from risu_minimize import minimize,canonical
from risu_repair import promote_text_json
from risu_witness import witness

class ReproductionError(ValueError):pass

def envelope(mcp):
    content=mcp.get('content')
    if not isinstance(content,list):raise ReproductionError('MCP_CONTENT_NOT_LIST')
    first=next((x.get('text') for x in content
                if isinstance(x,dict) and x.get('type')=='text'),None)
    if not isinstance(first,str):raise ReproductionError('FIRST_TEXT_NOT_AVAILABLE')
    try:root=_parse_json(first)
    except ValueError:raise ReproductionError('FIRST_TEXT_INVALID_JSON') from None
    if (not isinstance(root,dict) or type(root.get('status_code')) is not int
            or not isinstance(root.get('data'),(dict,list))):
        raise ReproductionError('UNSUPPORTED_ENVELOPE')
    return root

def modeled_variant(mcp,body):
    out=copy.deepcopy(mcp)
    value=envelope(mcp)
    value['data']=copy.deepcopy(body)
    for item in out['content']:
        if isinstance(item,dict) and item.get('type')=='text':
            item['text']=canonical(value)
            break
    return out

def reproduce(source,mcp,paths,*,max_checks=350):
    if not isinstance(source,dict) or not isinstance(mcp,dict):
        raise ReproductionError('EXPECTED_SOURCE_AND_MCP_OBJECTS')
    status=source.get('status')
    if type(status) is not int or not 100<=status<=599:
        raise ReproductionError('SOURCE_STATUS_INVALID')
    if 'body' not in source:raise ReproductionError('MISSING_SOURCE_BODY')
    root=envelope(mcp)
    if root['status_code']!=status:
        raise ReproductionError('SOURCE_AND_ENVELOPE_STATUS_DIFFER')
    if not _strict_same(root['data'],source['body']):
        raise ReproductionError('SOURCE_AND_ENVELOPE_BODY_DIFFER')
    promote_text_json(mcp)
    def predicate(body):
        if not isinstance(body,dict):return False
        s={**source,'body':body}
        variant=modeled_variant(mcp,body)
        try:
            proof=witness(s,variant,paths,require_error_flag=True,require_http_status=True)
            corrected=witness(s,promote_text_json(variant),paths,
                              require_error_flag=True,require_http_status=True)
        except (ValueError,KeyError,TypeError):
            return False
        return (proof['models']['structured-only']['outcome']=='FAIL'
                and proof['models']['json-text-data']['outcome']=='PASS'
                and corrected['models']['structured-only']['outcome']=='PASS')
    reduced=minimize(source['body'],predicate,max_checks=max_checks)
    final_source={**source,'body':reduced['minimal']}
    final_mcp=modeled_variant(mcp,reduced['minimal'])
    assert predicate(reduced['minimal'])
    proof=witness(final_source,final_mcp,paths,
                  require_error_flag=True,require_http_status=True)
    return {
        'schema':'risu-reproducer-v1',
        'verification_scope':'MODEL_ONLY_NOT_LIVE_REPLAY',
        'minimality':reduced['minimality'],
        'original_bytes':reduced['original_bytes'],
        'minimal_bytes':reduced['minimal_bytes'],
        'minimization_checks':reduced['checks'],
        'accepted_deletions':reduced['accepted_deletions'],
        'required_paths':paths,
        'consumer_witness':proof,
        'source':final_source,
        'mcp_result':final_mcp,
    }

def main(argv=None):
    p=argparse.ArgumentParser(
      description='Minimize an exact saved synthetic MCPGen text-envelope consumer failure; no execution')
    p.add_argument('pair',type=Path,help='JSON object with source and mcp_result')
    p.add_argument('--path',action='append',required=True)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--max-checks',type=int,default=350)
    p.add_argument('--allow-synthetic-export',action='store_true',
                   help='explicitly allow writing raw synthetic source and MCP data into the replay folder')
    a=p.parse_args(argv)
    try:
        if not a.allow_synthetic_export:
            raise ReproductionError('RAW_FIXTURE_EXPORT_REQUIRES_EXPLICIT_SYNTHETIC_APPROVAL')
        if a.pair.stat().st_size>1_000_000:
            raise ReproductionError('INPUT_EXCEEDS_1MB')
        obj=json.loads(a.pair.read_text(encoding='utf-8'))
        result=reproduce(obj['source'],obj['mcp_result'],a.path,max_checks=a.max_checks)
        a.out.mkdir(parents=True,exist_ok=False)
        fixture=a.out/'synthetic_minimal_pair.json'
        fixture.write_text(json.dumps({
            'source':result['source'],'mcp_result':result['mcp_result']},
            indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
        metadata={k:v for k,v in result.items() if k not in ('source','mcp_result')}
        metadata['fixture_sha256']=hashlib.sha256(fixture.read_bytes()).hexdigest()
        (a.out/'reproduction_report.json').write_text(json.dumps(metadata,indent=2)+'\n')
        (a.out/'README.md').write_text(
            '# RISU local modeled reproducer\n\n'
            'This is an OFFLINE MODEL-ONLY counterexample: the recorded status_code/data '
            'envelope was regenerated with a smaller synthetic body. '
            'It has NOT yet been replayed through an actual generator or server. '
            'Run an authorized isolated MCP server with the minimized payload '
            'and confirm it reproduces before proposing an upstream fix.\n\n'
            'To repair the text carrier for explicitly compatible consumers, '
            'call risu_repair.promote_text_json on the MCP result. '
            'It never modifies existing structuredContent and rejects conflicts.\n',
            encoding='utf-8')
        print(json.dumps({'status':'GENERATED_MODEL_ONLY',
                          'bytes_before':result['original_bytes'],
                          'bytes_after':result['minimal_bytes'],
                          'minimality':result['minimality'],
                          'output_directory':str(a.out)}))
        return 0
    except (OSError,ValueError,KeyError,TypeError) as exc:
        print('RISU Probe reproduce: '+str(exc),file=sys.stderr)
        return 2

if __name__=='__main__':
    raise SystemExit(main())
