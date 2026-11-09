"""Independent fixture oracles for predeclared real-server B12 probes.

Source-derived and SDK-derived transports are not conflated. A static or
schema finding is a candidate until separately confirmed. A checked oracle is
only about the specifically declared operation and its fresh synthetic input.
"""
from __future__ import annotations
import argparse,hashlib,json,re
from pathlib import Path
from typing import Any

def text_content(result:dict)->str:
    return '\n'.join(x.get('text','') for x in result.get('content',[])
                    if isinstance(x,dict) and x.get('type')=='text'
                    and isinstance(x.get('text'),str))

def parse_rows(result:dict)->list|None:
    structured=result.get('structuredContent')
    if isinstance(structured,list):
        return structured
    if isinstance(structured,dict):
        for k in ('result','rows','data','items'):
            if isinstance(structured.get(k),list):return structured[k]
    independent_objects=[]
    for block in result.get('content',[]):
        if not isinstance(block,dict) or block.get('type')!='text':continue
        raw=block.get('text')
        if not isinstance(raw,str) or len(raw)>8192:continue
        try:doc=json.loads(raw)
        except (ValueError,TypeError):continue
        if isinstance(doc,list):return doc
        if isinstance(doc,dict):
            for k in ('result','rows','data','items'):
                if isinstance(doc.get(k),list):return doc[k]
            independent_objects.append(doc)
        else:
            return None
    # FastMCP 0.4.1 sends one JSON text block per returned list item.
    # All blocks must be JSON objects. Never guess cardinality from prose.
    return independent_objects if independent_objects else None

def result_for(calls:list,index:int)->dict|None:
    if index>=len(calls):return None
    resp=calls[index]['response']
    return resp.get('result') if isinstance(resp.get('result'),dict) else None

def oracle(case:str,calls:list)->list[dict]:
    checks=[]
    def check(name:str,state:str,evidence:str):
        assert state in ('PASS','MISMATCH','UNVERIFIED')
        checks.append({'oracle_id':name,'outcome':state,'evidence':evidence})
    r=[result_for(calls,i) for i in range(len(calls))]
    if any(x is None for x in r):
        return [{'oracle_id':'capture_complete','outcome':'UNVERIFIED',
                 'evidence':'At least one call returned a JSON-RPC error without tool result'}]
    healthy=[x.get('isError',False) is not True for x in r]
    if case=='FS':
        goal='RISU_B12_LINE_1\nunicode-🧭-#literal_[x]\n'
        check('fixture_file_write_success','PASS' if healthy[1] else 'MISMATCH','Write to private temporary directory')
        value=text_content(r[2])
        check('fixture_exact_roundtrip',
              'PASS' if healthy[2] and goal in value else 'MISMATCH',
              'Read result includes original newline and Unicode bytes')
        check('directory_listing_consistency',
              'PASS' if healthy[3] and 'risu-b12.txt' in text_content(r[3]) else 'MISMATCH',
              'Directory listing contains just-written fixture file')
    elif case=='MEM':
        check('graph_create','PASS' if healthy[0] else 'MISMATCH',
              'Synthetic new graph accepts two entities')
        for i,label in [(1,'search'),(2,'open'),(3,'graph')]:
            obj=json.dumps(r[i].get('structuredContent',{}),ensure_ascii=False)
            text=obj+' '+text_content(r[i])
            check('entity_persists_'+label,
                  'PASS' if healthy[i] and 'RISU_B12_ALPHA' in text else 'MISMATCH',
                  'Known synthetic entity ID persists across fresh in-memory tool calls')
    elif case=='ALCHEMY':
        check('table_discovery','PASS' if healthy[0] and 'records' in text_content(r[0]) else 'MISMATCH',
              'Private SQLite table was created before server startup')
        check('table_filter','PASS' if healthy[1] and 'records' in text_content(r[1]) else 'MISMATCH',
              'Substring query rec matches records')
        q=text_content(r[2])
        check('query_preserves_known_rows','PASS' if healthy[2]
              and 'row_one' in q and 'row_eight' in q else 'MISMATCH',
              'All 8 known synthetic records requested without limit')
        check('schema_describes_table','PASS' if healthy[3] and 'label' in text_content(r[3]) else 'MISMATCH',
              'Declared fixture contains label text column')
    elif case=='GO':
        check('echo_unicode','PASS' if healthy[0] and 'RISU_B12_ECHO_lit_[x]_☯' in text_content(r[0]) else 'MISMATCH',
              'Echo should return exact synthetic user string')
        # A numeric 3.750000 is equal to 3.75; do not false-flag.
        from decimal import Decimal, InvalidOperation
        candidates=re.findall(r'(?i)\bis\s+([-+]?[0-9]+(?:\.[0-9]+)?)\b',text_content(r[1]))
        try:
            numeric_ok=bool(candidates) and Decimal(candidates[-1])==Decimal('3.75')
        except InvalidOperation:
            numeric_ok=False
        check('sum_decimal','PASS' if healthy[1] and numeric_ok else 'MISMATCH',
              '1.5 + 2.25 must equal 3.75 regardless of decimal formatting')
        links=r[2].get('content',[])
        check('resource_link_present','PASS' if healthy[2] and any(
              isinstance(v,dict) and v.get('type')=='resource_link' for v in links)
              else 'MISMATCH','Link example should produce resource_link typed MCP content')
    elif case=='SQLITE':
        check('sqlite_catalog','PASS' if healthy[0] and 'records' in text_content(r[0]) else 'MISMATCH',
              'Private test DB has a records table')
        first=parse_rows(r[1])
        second=parse_rows(r[2])
        if first is None or second is None:
            check('row_limit_plain_column','UNVERIFIED','Result not parseable as JSON rows')
            check('row_limit_identifier_substring','UNVERIFIED','Result not parseable as JSON rows')
        else:
            check('row_limit_plain_column',
                  'PASS' if healthy[1] and 0<len(first)<=2 else 'MISMATCH',
                  f'8 fixture records, row_limit 2, rows returned {len(first)}')
            check('row_limit_identifier_substring',
                  'PASS' if healthy[2] and 0<len(second)<=2 else 'MISMATCH',
                  f'8 fixture records; query selects column limit_hint; row_limit 2; rows returned {len(second)}')
        check('sqlite_describe','PASS' if healthy[3] and 'limit_hint' in text_content(r[3]) else 'MISMATCH',
              'Existing synthetic column limit_hint should be described')
    return checks

def audit(case:str,folder:Path,scanner:Path,manifest:Path)->dict:
    m=json.loads(manifest.read_text())
    c=next(v for v in m['cases'] if v['id']==case)
    meta=json.loads((folder/'origin.json').read_text())
    raw=(folder/'original_stdio.jsonl').read_bytes()
    responses=json.loads((folder/'unmodified_responses.json').read_text())
    report=json.loads(scanner.read_text())
    if meta['case']!=case or meta['source_commit']!=c['commit'] or not meta['source_stdout_unmodified']:
        raise ValueError('Unpinned or synthetic claimed original stdout')
    if hashlib.sha256(raw).hexdigest()!=meta['raw_original_stdio_sha256']:
        raise ValueError('Original server stdout evidence hash mismatch')
    if len(responses)!=len(c['tools']) or any(a['tool']!=b['name']
        or a['call_id']!=i+20 for i,(a,b) in enumerate(zip(responses,c['tools']))):
        raise ValueError('Prelocked tool probes silently replaced')
    checks=oracle(case,responses)
    finding_codes=[x.get('rule_id') for x in report.get('findings',[])]
    return {
      'schema':'risu-b12-preregistered-raw-stdio-and-independent-oracle-v1',
      'case':case,'selection':c['selection'],'repository':c['repository'],
      'original_source_commit':c['commit'],
      'capture_verified':True,'native_server_stdout_original':True,
      'raw_trace_sha256':meta['raw_original_stdio_sha256'],
      'tool_count':meta['advertised_tools'],'call_count':len(responses),
      'core_frozen_risu_findings':finding_codes,
      'core_detector_finding_count':len(finding_codes),
      'oracle_checks':checks,
      'oracle_mismatches':sum(x['outcome']=='MISMATCH' for x in checks),
      'oracle_unverified':sum(x['outcome']=='UNVERIFIED' for x in checks),
      'unreported_bug_verified':False,
      'bug_status':'NOT_YET_INDEPENDENTLY_ADJUDICATED' if any(
           x['outcome']=='MISMATCH' for x in checks) else 'NO_CANDIDATE_IN_PROBED_BEHAVIOR',
      'scanner_is_not_oracle':True,
      'limits':'Frozen first-pass public-source survey; no novelty or production claim without independent reproduction and upstream issue/history review',
    }

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--case',required=True,choices=['FS','MEM','ALCHEMY','GO','SQLITE'])
    p.add_argument('--capture',type=Path,required=True)
    p.add_argument('--scanner',type=Path,required=True)
    p.add_argument('--manifest',type=Path,default=Path('benchmarks/p6b12/prelocked_blind_servers.json'))
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    x=audit(a.case,a.capture,a.scanner,a.manifest)
    a.output.write_text(json.dumps(x,indent=2,ensure_ascii=False,sort_keys=True)+'\n')
    print('B12_PINNED_BLIND_SESSION_SCORE',json.dumps({
        k:x[k] for k in ('case','selection','core_frozen_risu_findings',
                         'oracle_mismatches','oracle_unverified','bug_status')},
                        ensure_ascii=False,sort_keys=True))
if __name__=='__main__':main()
