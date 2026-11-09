"""Post-freeze, bounded review of first-pass unfamiliar server outputs.

Only synthetic pinned CI data. Does not change the prelocked probes, raw outputs,
baseline detector or first-pass verdicts. This is candidate investigation only.
"""
from __future__ import annotations
import argparse,json,re,hashlib
from pathlib import Path

def analysis(case:str,base:Path)->dict:
    origin=json.loads((base/'capture/origin.json').read_text())
    raw=(base/'capture/original_stdio.jsonl').read_bytes()
    assert hashlib.sha256(raw).hexdigest()==origin['raw_original_stdio_sha256']
    calls=json.loads((base/'capture/unmodified_responses.json').read_text())
    assert origin['case']==case and len(calls)==origin['selected_call_count']
    out={'case':case,'source_commit':origin['source_commit'],
         'evidence_sha256':origin['raw_original_stdio_sha256'],
         'source_stdout_original':origin['source_stdout_unmodified'],
         'probes':[]}
    for c in calls:
        v=c['response'].get('result',{})
        blocks=v.get('content',[])
        txt='\n'.join(b.get('text','') for b in blocks
                      if type(b) is dict and b.get('type')=='text')
        out['probes'].append({'name':c['tool'],'call_id':c['call_id'],
             'jsonrpc_error':bool(c['response'].get('error')),
             'isError':v.get('isError',False),
             'content_types':[b.get('type') for b in blocks if type(b) is dict],
             'structured_type':type(v.get('structuredContent')).__name__,
             'text_prefix':txt[:1100],
             'text_sha256':hashlib.sha256(txt.encode()).hexdigest(),
             'text_length':len(txt)})
    if case=='SQLITE':
        first=out['probes'][1]['text_prefix']
        second=out['probes'][2]['text_prefix']
        f=sorted(set(re.findall(r'row_(?:one|two|three|four|five|six|seven|eight)',first)))
        s=sorted(set(re.findall(r'hint_0[1-8]',second)))
        out['candidate_check']={
            'plain_query_distinct_row_labels':f,
            'keyword_fragment_query_distinct_column_values':s,
            'recorded_explicit_row_limit':2,
            'synthetic_fixture_rows':8,
            'semantic_violation_candidate':len(f)==2 and len(s)>2}
    elif case=='GO':
        out['candidate_check']={'third_call_content_types':out['probes'][2]['content_types'],
            'third_call_text_excerpt':out['probes'][2]['text_prefix'],
            'returns_explicit_resource_link':('resource_link' in out['probes'][2]['content_types'])}
    return out

def main():
    p=argparse.ArgumentParser()
    p.add_argument('case',choices=('GO','SQLITE'))
    p.add_argument('root',type=Path)
    p.add_argument('output',type=Path)
    a=p.parse_args()
    result=analysis(a.case,a.root)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n')
    print(json.dumps(result,ensure_ascii=False,indent=2))
if __name__=='__main__':main()
