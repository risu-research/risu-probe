"""B15 independent audit of three frozen native external deployments.

Consumes already published original wire artifacts, not a fresh server rerun.
A correct contract comparison does not prove the contract is authoritative.
"""
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path

EXPECTED={
 'PA':('panasenco/mcp-sqlite','c5f46391520d9c8c5283249e5513788d4de698f7',4),
 'ZM':('zongmin-yu/sqlite-literature-management-fastmcp-mcp-server',
       'a3ceee63a34ff99de3bcfd80e0c72bf439017f4e',5),
 'FM':('fellowgeek/mcp-memory','a50a87708628d0822af439015503de47c35d7acc',5)
}
FROZEN='4314e9bf92e2ec75c421bab25eae3b43f1424a08'

def read(path):
    return json.loads(path.read_text('utf-8'))

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def state_sha(value):
    return digest(json.dumps(value,sort_keys=True,ensure_ascii=False,
                             separators=(',',':')).encode('utf-8'))

def require(truth,msg):
    if not truth:raise ValueError(msg)

def audit(manifest:Path,files:dict[str,Path]):
    origin_manifest=manifest.read_bytes()
    cohort=read(manifest)
    require(cohort['frozen_analyzer']==FROZEN and len(cohort['cases'])==3
            and cohort['denominator']['locked_tool_calls']==14,'Preselected cohort changed')
    selected=[]
    all_wire=[]
    error_status_controls=[]
    for case in ('PA','ZM','FM'):
        root=files[case]/'.b15-original'
        origin=read(root/'origin.json')
        wire=(root/'original_stdio.jsonl').read_bytes()
        calls=read(root/'per_call_state.json')
        contract=read(root/'contract.json')
        witness=read(root/'witness.json')
        product=read(root/'product_firstpass.json')
        repo,commit,n=EXPECTED[case]
        declared=next(x for x in cohort['cases'] if x['id']==case)
        require((declared['repository'],declared['commit'],len(declared['calls']))==(repo,commit,n),
                'Original source/preregistration identity changed')
        require(origin['case']==case and origin['source_commit']==commit
                and origin['repository']==repo,'Provenance differs from frozen identity')
        require(origin['status']=='CAPTURED_NATIVE','Original capture incomplete')
        require(origin['locked_calls']==n and origin['calls_recorded']==n and len(calls)==n,
                'Original selected calls missing')
        require(origin['trace_sha256']==digest(wire)==witness['trace_sha256']
                ==product['trace_sha256'],'Raw wire SHA altered or disconnected from product')
        require(contract['schema']=='risu-mcp-observation-contract-v1'
                and witness['schema']=='risu-mcp-state-witness-v1','Wrong product contract family')
        require(product['summary']['matched']==n and product['summary']['checked']==n
                and product['summary']['unverified']==0,'Incomplete product calls not marked')
        records=[json.loads(x) for x in wire.splitlines()]
        by_req={x['id']:(i,x) for i,x in enumerate(records,1)
                if x.get('method')=='tools/call' and 'id' in x}
        by_res={x['id']:(i,x) for i,x in enumerate(records,1)
                if 'id' in x and x.get('method') is None}
        require(len([x for x in records if x.get('method')=='tools/call'])==n,
                'Original wire selected calls substituted')
        witness_by_lines={(x['request_line'],x['response_line']):x
                          for x in witness['records']}
        require(len(witness_by_lines)==n,'State-witness records omitted or duplicated')
        source_classifications=[]
        for i,call in enumerate(calls):
            planned=declared['calls'][i]
            require(call['index']==i and call['tool']==planned['name']
                    and call['status']=='CAPTURED','Selected original call omitted')
            request_line,request=by_req[20+i]
            response_line,response=by_res[20+i]
            require((call['request_line'],call['response_line'])==(request_line,response_line),
                    'Derived call spans do not match original wire')
            require(request['params']['name']==planned['name']
                    and request['params']['arguments']==call['args'],'Original frozen input changed')
            require(call['response']==response,'Derived tool result differs from source wire')
            evidence=witness_by_lines.get((request_line,response_line))
            require(evidence and evidence['tool']==planned['name'],'Witness call correlation missing')
            require(evidence['before_sha256']==state_sha(call['before'])
                    and evidence['after_sha256']==state_sha(call['after']),
                    'Independent state witness not derived from preserved external capture')
            observed=call['before']!=call['after']
            expectation=planned['expect']=='state-changed'
            source_classifications.append({
                'probe':planned['label'],'expected_change_from_frozen_manifest':expectation,
                'observed_change_in_independent_sqlite_or_okf_state':observed,
                'wire_line':response_line,
                'mismatch_to_user_contract':observed!=expectation})
        mismatch_ids=[r['probe'] for r in source_classifications if r['mismatch_to_user_contract']]
        require(mismatch_ids==(['sql_documented_writer'] if case=='PA' else []),
                'Frozen evaluator first-pass results altered')
        expected_count=1 if case=='PA' else 0
        require(product['summary']['observed_mismatches']==expected_count,
                'RISU finding count changed after freeze')
        tool_catalog=[x['result']['tools'] for x in records
                      if 'result' in x and type(x['result']) is dict
                      and type(x['result'].get('tools')) is list]
        desc={}
        for page in tool_catalog:
            for t in page:
                if type(t) is dict and type(t.get('name')) is str:
                    desc[t['name']]=t.get('description','')
        if case=='PA':
            # Independent contemporaneous evidence of the incorrect *tester*
            # obligation. The source originally advertised read-only semantics.
            text=desc.get('sqlite_execute','').lower()
            require('read-only mode by default' in text
                    and 'canned queries with write: true' in text,
                    'Conflicting actual MCP tool contract not independently substantiated')
            result=calls[2]['response'].get('result',{})
            blocks=result.get('content',[])
            words=' '.join(x.get('text','') for x in blocks if x.get('type')=='text')
            require('readonly database' in words.lower()
                    and calls[2]['before']==calls[2]['after'],
                    'Original read-only refusal / independent DB preservation missing')
            require(result.get('isError') is True,
                    'Original readonly refusal must signal tool execution error')
            error_status_controls.append({'case':case,'probe':'sql_documented_writer',
                'kind':'CORRECT_MCP_TOOL_ERROR_FLAG_ON_READONLY_REFUSAL',
                'observed_isError':True,'separate_from_frozen_product_findings':True})
        if case=='ZM':
            words=' '.join(x.get('text','') for x in calls[2]['response']['result'].get('content',[])
                           if x.get('type')=='text')
            require('Only SELECT queries' in words and
                    calls[2]['response']['result'].get('isError') is True,
                    'Original read_query DDL rejection and error flag missing')
            error_status_controls.append({'case':case,'probe':'declared_read_only_ddl_guard',
                'kind':'CORRECT_MCP_TOOL_ERROR_FLAG_ON_DDL_REFUSAL',
                'observed_isError':True,'separate_from_frozen_product_findings':True})
        selected.append({'case':case,'repo':repo,'commit':commit,
                         'original_stdout_sha256':digest(wire),
                         'calls':source_classifications,
                         'frozen_product_summary':product['summary'],
                         'authoritative_inband_tool_catalog_checked':case=='PA'})
        all_wire.append(digest(wire))
    return {
        'schema':'risu-p6b15-unseen-cross-artifact-audit-v1',
        'manifest_sha256':digest(origin_manifest),
        'frozen_detector_blob':FROZEN,
        'frozen_product_development_source':'B14 only, excluded from independent heldout',
        'holdout_first_run':43290126061,
        'selected':selected,
        'report':{
            'preselected_independent_upstream_owners':3,
            'native_original_source_servers_verified':3,
            'locked_calls_verified':14,
            'frozen_product_checks_completed':14,
            'frozen_product_declared_contract_matches':13,
            'frozen_product_declared_contract_mismatches':1,
            'independently_adjudicated_upstream_behavior_bugs':0,
            'declared_contract_conflicts_with_contemporaneous_tool_description':1,
            'defensible_obligations_checked':13,
            'defensible_obligations_passed':13,
            'defensible_obligations_mismatched':0,
            'correct_mcp_tool_error_status_controls':len(error_status_controls),
            'unverified_missing_native_original_runs':0,
            'population_recall':'NOT_ESTIMABLE_NO_POSITIVE_BUG_IN_UNSEEN_COHORT',
            'false_positive_denominator_note':'14 original calls; one wrong predeclared contract (not an upstream defect). Do not report 1 upstream bug. Two correctly flagged MCP execution errors serve as native normal controls.'
        },
        'protocol_status_flag_normal_controls':error_status_controls,
        'claims_limits':[
            'All original tools executed with synthetic local fixtures and original native stdio; source originality is supported by frozen git commits and CI, not remotely attested by RISU',
            'Contract obligations are supplied by callers and may conflict with server advertised behavior; this is a real evaluation weakness',
            'No generic Error-word heuristic was used by the frozen product',
            'Two rejected writes correctly reported isError true; no success-status defect is alleged',
            'Three nonrandom sources and no independently confirmed new upstream behavior bug; no general precision or recall claim'
        ]
    }

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--manifest',type=Path,default=Path('benchmarks/p6b15/FROZEN_UNSEEN_ORIGINAL_SERVERS.json'))
    for name in EXPECTED:
        p.add_argument('--'+name.lower(),required=True,type=Path)
    p.add_argument('--out',required=True,type=Path)
    a=p.parse_args()
    data=audit(a.manifest,{'PA':a.pa,'ZM':a.zm,'FM':a.fm})
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(data,indent=2,ensure_ascii=False,sort_keys=True)+'\n')
    print('B15_INDEPENDENT_HELDOUT_CROSS_AUDIT',json.dumps(data['report'],sort_keys=True))
if __name__=='__main__':
    main()
