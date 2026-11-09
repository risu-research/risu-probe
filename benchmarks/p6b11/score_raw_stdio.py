"""Before/fix adjudicator for original raw STDIO: separate source truth from RISU rule.

Scores only the three preselected families, and explicitly distinguishes an
original native MCP server from an SDK test wrapper around actual source.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

SUPPORT={'PARTICULARS15':('workspace_status','topics_list','RMC509'),
         'ROBOT682':('literal_code','normal_code','RMC507'),
         'HITCH60':('missing_text','explicit_text','text_only','RMC509')}

def capture(path:Path,family:str,rev:str):
    metadata=json.loads((path/'origin.json').read_text())
    raw=(path/'original_stdio.jsonl').read_bytes()
    assert hashlib.sha256(raw).hexdigest()==metadata['trace_sha256']
    assert metadata['schema']=='risu-b11-original-stdout-mcp-stdio-v1'
    assert metadata['family']==family and metadata['revision']==rev
    assert metadata['evidence_transport']=='ACTUAL_SOURCE_EXECUTION_RAW_UPSTREAM_PROCESS_STDOUT'
    assert metadata['protocol_negotiated'] is not None
    assert len(raw)<3_000_000
    lines=[json.loads(s) for s in raw.splitlines() if s.strip()]
    for i,tool in enumerate(SUPPORT[family][:-1],10):
        calls=[x for x in lines if x.get('method')=='tools/call' and x.get('id')==i]
        assert len(calls)==1 and calls[0]['params']['name']==tool
    if family=='HITCH60':
        original=(path.parent/(rev+'-source.json'))
        source=json.loads(original.read_text())
        assert source['schema']=='risu-b11-hitch60-original-ruby-result-v1'
        assert source['source']=='ACTUAL_PINNED_UPSTREAM_RUBY_RESULT_NORMALIZER'
        for i,name in enumerate(SUPPORT[family][:-1],10):
            genuine=source['records'][name]
            wire=tool_result(lines,i)
            assert wire.get('content',[])==genuine.get('content',[])
            assert wire.get('structuredContent')==genuine.get('structuredContent')
            assert wire.get('isError',False)==genuine.get('isError',False)
        metadata['original_ruby_component_content_matches_wire']=True
        metadata['original_ruby_component_sha256']=hashlib.sha256(original.read_bytes()).hexdigest()
    return metadata,lines

def tool_result(messages,id):
    found=[x for x in messages if x.get('id')==id and 'method' not in x]
    assert len(found)==1 and type(found[0].get('result')) is dict
    return found[0]['result']

def textblocks(r):
    return [x['text'] for x in r.get('content',[])
            if type(x) is dict and x.get('type')=='text' and type(x.get('text')) is str]

def json_equal(x,y):
    if type(x) is not type(y):return False
    if type(x) is dict:
        return x.keys()==y.keys() and all(json_equal(x[k],y[k]) for k in x)
    if type(x) is list:
        return len(x)==len(y) and all(json_equal(a,b) for a,b in zip(x,y))
    return x==y

def has_json_mirror(result):
    src=result.get('structuredContent')
    if src is None:return False
    for t in textblocks(result):
        try:
            parsed=json.loads(t)
        except (ValueError,TypeError):
            continue
        if json_equal(parsed,src):return True
    return False

def source_truth(family,o,n,orig_meta,fix_meta):
    if family=='PARTICULARS15':
        old=[tool_result(o,i) for i in (10,11)]
        fixed=[tool_result(n,i) for i in (10,11)]
        healthy=all(x.get('isError') is not True and
                    type(x.get('structuredContent')) is dict for x in old+fixed)
        changed=healthy and all(not has_json_mirror(x) for x in old) and all(has_json_mirror(x) for x in fixed)
        control=healthy and all(len(textblocks(x))>=1 for x in old+fixed)
        return bool(changed),bool(control),
    if family=='HITCH60':
        missing_old=tool_result(o,10);missing_fixed=tool_result(n,10)
        explicit_old=tool_result(o,11);explicit_fixed=tool_result(n,11)
        text_old=tool_result(o,12);text_fixed=tool_result(n,12)
        source_verified=(orig_meta.get('original_ruby_component_content_matches_wire') is True
                         and fix_meta.get('original_ruby_component_content_matches_wire') is True)
        healthy=all(x.get('isError') is not True for x in
                    (missing_old,missing_fixed,explicit_old,explicit_fixed,text_old,text_fixed))
        reproduced=(healthy and source_verified
                    and type(missing_old.get('structuredContent')) is dict
                    and type(missing_fixed.get('structuredContent')) is dict
                    and textblocks(missing_old)==[]
                    and not has_json_mirror(missing_old)
                    and has_json_mirror(missing_fixed)
                    and missing_old.get('structuredContent')==missing_fixed.get('structuredContent'))
        controls=(healthy and
                  textblocks(explicit_old)==textblocks(explicit_fixed)==['Author supplied summary']
                  and explicit_old.get('structuredContent')==explicit_fixed.get('structuredContent')
                  and textblocks(text_old)==textblocks(text_fixed)==['Normal scalar text']
                  and 'structuredContent' not in text_old
                  and 'structuredContent' not in text_fixed)
        return bool(reproduced),bool(controls)
    bad_o=tool_result(o,10);bad_n=tool_result(n,10)
    good_o=tool_result(o,11);good_n=tool_result(n,11)
    good_text_o=textblocks(good_o);good_text_n=textblocks(good_n)
    source_ok=all(x.get('isError') is not True and
                  type(x.get('structuredContent')) is dict for x in [bad_o,bad_n,good_o,good_n])
    old_value=' '.join(textblocks(bad_o));new_value=' '.join(textblocks(bad_n))
    changed=(source_ok and bad_o['structuredContent'].get('value')=='#FF00FF'
        and bad_n['structuredContent'].get('value')=='#FF00FF'
        and '\\#FF00FF' in old_value and '`#FF00FF`' in new_value
        and '\\#FF00FF' not in new_value)
    control=(source_ok and good_o['structuredContent'].get('value')=='ordinary'
             and good_n['structuredContent'].get('value')=='ordinary'
             and good_text_o==good_text_n
             and any('ordinary' in x for x in good_text_o))
    return bool(changed),bool(control)

def adjudicate(family:str,old:Path,fixed:Path,old_risu:Path,fix_risu:Path):
    a,o=capture(old,family,'old')
    b,n=capture(fixed,family,'fixed')
    reproduced,normal=source_truth(family,o,n,a,b)
    oldp=json.loads(old_risu.read_text());fixp=json.loads(fix_risu.read_text())
    want=SUPPORT[family][-1]
    old_codes=[f['rule_id'] for f in oldp.get('findings',[])]
    new_codes=[f['rule_id'] for f in fixp.get('findings',[])]
    required=1 if family=='HITCH60' else 2
    matched=(oldp['summary']['explicit_display_rules_matched']==required and
             fixp['summary']['explicit_display_rules_matched']==required)
    checked=(oldp['summary']['explicit_display_rules_checked']==required and
             fixp['summary']['explicit_display_rules_checked']==required)
    caught=(reproduced and normal and matched and checked and
            old_codes.count(want)>=1 and set(old_codes)=={want}
            and not new_codes and fixp['summary']['explicit_display_rules_passed']==required)
    return {
      'schema':'risu-p6b11-source-real-stdio-scored-v1',
      'family':family,'role':'PRELOCKED_NEW_CROSS_ORGANIZATION_SOURCE_FAMILY',
      'upstream_original_bugfix_reproduced':reproduced,
      'normal_controls_passed':normal,
      'old_risu_findings':old_codes,'official_fixed_risu_findings':new_codes,
      'frozen_risu_detected_old_not_fixed':bool(caught),
      'old_original_trace_sha256':a['trace_sha256'],
      'fixed_original_trace_sha256':b['trace_sha256'],
      'transport':('NATIVE_ORIGINAL_MCP_CLI_RAW_STDIO' if family=='PARTICULARS15'
                   else 'Genuine_MCP_SDK_RAW_STDIO_wrapping_original_upstream_formatter'
                   if family=='ROBOT682'
                   else 'Genuine_MCP_SDK_RAW_STDIO_wrapping_actual_Ruby_normalizer'),
      'origin_is_native_mcp_server':family=='PARTICULARS15',
      'protocol_old':a['protocol_negotiated'],'protocol_fixed':b['protocol_negotiated'],
      'scope_limit':('Original upstream MCP CLI process, synthetic fresh workspace; code fix predates the later GitHub issue'
                     if family=='PARTICULARS15' else
                     'Original upstream Python formatting source executed inside a synthetic MCP SDK server, not RobotCode product server'
                     if family=='ROBOT682' else
                     'Actual pinned Hitch Ruby normalizer produced the canonical result; Python MCP SDK stdio bridge is not the native Rails HTTP server'),
    }

def main():
    p=argparse.ArgumentParser()
    p.add_argument('family',choices=tuple(SUPPORT))
    p.add_argument('old',type=Path)
    p.add_argument('fixed',type=Path)
    p.add_argument('old_risu',type=Path)
    p.add_argument('fixed_risu',type=Path)
    p.add_argument('output',type=Path)
    args=p.parse_args()
    record=adjudicate(args.family,args.old,args.fixed,args.old_risu,args.fixed_risu)
    args.output.write_text(json.dumps(record,indent=2,sort_keys=True)+'\n')
    print(json.dumps(record,indent=2,sort_keys=True))
    if not record['normal_controls_passed'] or not record['upstream_original_bugfix_reproduced']:
        raise SystemExit('PRELOCKED_UPSTREAM_REPRODUCTION_UNVERIFIED')
if __name__=='__main__':main()
