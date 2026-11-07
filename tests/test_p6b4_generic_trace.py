"""P6-B4: generic, protocol-aware, offline JSON-RPC trace contract tests."""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from risu_mcp_trace import verify_trace, TraceError, _sarif


def sample(schema=None, value=None, *, present=True, error=False, name='hello', version='2026-07-28'):
    if schema is None:schema={'type':'object','properties':{'value':{'type':'integer'}},'required':['value']}
    if value is None:value={'value':3}
    listed={'name':name,'inputSchema':{'type':'object'},'outputSchema':schema}
    result={'content':[{'type':'text','text':'ok'}], 'isError':error}
    if version=='2026-07-28':result['resultType']='complete'
    if present:result['structuredContent']=value
    return [
        {'jsonrpc':'2.0','id':1,'method':'tools/list','params':{}},
        {'jsonrpc':'2.0','id':1,'result':{'tools':[listed]}},
        {'jsonrpc':'2.0','id':2,'method':'tools/call','params':{'name':name,'arguments':{}}},
        {'jsonrpc':'2.0','id':2,'result':result},
    ]


def run(records,version='2026-07-28'):
    with tempfile.TemporaryDirectory() as d:
        p=Path(d)/'trace.jsonl'
        p.write_text(''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in records),encoding='utf-8')
        return verify_trace(p,version)


class TestGenericMCPTrace(unittest.TestCase):
    def assert_rule(self,report,code):
        self.assertIn(code,{x['rule_id'] for x in report['findings']})
    def test_valid_2026_structured_output(self):
        r=run(sample())
        self.assertEqual(r['summary']['structured_values_schema_checked'],1)
        self.assertEqual(r['summary']['findings'],0)
        self.assertEqual(r['summary']['unverified_count'],0)
        self.assertEqual(r['semantic_verification'],'CHECKED_NO_MISMATCHES')
    def test_mismatch_is_observation_not_authenticated(self):
        r=run(sample(value={'value':'not an int'}))
        self.assert_rule(r,'RMC502')
        self.assertEqual(r['origin_integrity'],'UNATTESTED_LOCAL_CAPTURE')
        self.assertEqual(r['findings'][0]['verdict'],'OBSERVED_IN_UNATTESTED_CAPTURE')
        self.assertNotIn('not an int',json.dumps(r))
    def test_missing_success_content(self):
        self.assert_rule(run(sample(present=False)),'RMC501')
    def test_tool_error_without_structured_is_allowed(self):
        r=run(sample(present=False,error=True))
        self.assertEqual(r['summary']['findings'],0)
        self.assertIn('EXECUTION_ERROR',{e['code'] for e in r['unverified']})
    def test_default_is_error_false(self):
        rows=sample(present=False);del rows[-1]['result']['isError']
        self.assert_rule(run(rows),'RMC501')
    def test_result_type_not_complete_not_flagged(self):
        rows=sample(present=False);rows[-1]['result']['resultType']='input_required'
        r=run(rows)
        self.assertEqual(r['summary']['findings'],0)
        self.assertIn('NONFINAL_TOOL_RESULT',{e['code'] for e in r['unverified']})
    def test_empty_catalog_does_not_invent_contract(self):
        rows=sample();rows[1]['result']['tools']=[]
        r=run(rows)
        self.assertEqual(r['summary']['findings'],0)
        self.assertIn('UNKNOWN_DECLARATION',{e['code'] for e in r['unverified']})
    def test_no_catalog(self):
        r=run(sample()[2:])
        self.assertEqual(r['summary']['findings'],0)
        self.assertIn('NO_COMPLETE_CATALOG',{e['code'] for e in r['unverified']})
    def test_bare_tool_without_output_schema(self):
        rows=sample();del rows[1]['result']['tools'][0]['outputSchema']
        r=run(rows)
        self.assertEqual(r['summary']['findings'],0)
        self.assertIn('NO_OUTPUT_SCHEMA',{e['code'] for e in r['unverified']})
    def test_schema_boolean_subschemas_accepted(self):
        schema={'type':'object','properties':{'value':True},'required':['value']}
        self.assertEqual(run(sample(schema=schema))['summary']['structured_values_schema_checked'],1)
    def test_recursive_local_ref_valid(self):
        schema={'$defs':{'Node':{'type':'object','properties':{'name':{'type':'string'},'children':{'type':'array','items':{'$ref':'#/$defs/Node'}}},'required':['name']}},'$ref':'#/$defs/Node'}
        r=run(sample(schema=schema,value={'name':'n','children':[{'name':'leaf'}]}))
        self.assertEqual(r['summary']['findings'],0)
        self.assertEqual(r['summary']['structured_values_schema_checked'],1)
    def test_legacy_root_non_object_rejected(self):
        schema={'$defs':{'N':{'type':'object'}},'$ref':'#/$defs/N'}
        self.assert_rule(run(sample(schema=schema,version='2025-11-25'),'2025-11-25'),'RMC504')
    def test_modern_root_ref_accepted(self):
        schema={'$defs':{'N':{'type':'object'}},'$ref':'#/$defs/N'}
        self.assertEqual(run(sample(schema=schema))['summary']['structured_values_schema_checked'],1)
    def test_invalid_schema_detected(self):
        schema={'type':'object','properties':{'a':{'type':'not-a-type'}}}
        self.assert_rule(run(sample(schema=schema)),'RMC503')
    def test_output_schema_not_a_dict(self):
        self.assert_rule(run(sample(schema=True)),'RMC503')
    def test_remote_reference_unverified_no_network(self):
        schema={'$ref':'https://private.example/schema.json'}
        r=run(sample(schema=schema))
        self.assertEqual(r['summary']['findings'],0)
        self.assertIn('UNSUPPORTED_SCHEMA',{x['code'] for x in r['unverified']})
    def test_regex_schema_unverified(self):
        r=run(sample(schema={'type':'string','pattern':'(a+)+$'},value='x'*2000))
        self.assertEqual(r['summary']['findings'],0)
        self.assertIn('UNSUPPORTED_SCHEMA',{x['code'] for x in r['unverified']})
    def test_format_assertion_not_claimed(self):
        r=run(sample(schema={'type':'string','format':'email'},value='n/a'))
        self.assertIn('UNSUPPORTED_SCHEMA',{x['code'] for x in r['unverified']})
    def test_protocol_error_does_not_assert_tool_failure(self):
        rows=sample();rows[-1]={'jsonrpc':'2.0','id':2,'error':{'code':-32601,'message':'Unknown tool'}}
        r=run(rows)
        self.assertEqual(r['summary']['findings'],0)
        self.assertIn('PROTOCOL_ERROR',{x['code'] for x in r['unverified']})
    def test_duplicate_tool_declaration_unverified(self):
        rows=sample();rows[1]['result']['tools']*=2
        r=run(rows)
        self.assertIn('INVALID_CATALOG',{x['code'] for x in r['unverified']})
        self.assertEqual(r['summary']['findings'],0)
    def test_incomplete_list_page_not_false_positive(self):
        rows=sample();rows[1]['result']['nextCursor']='next'
        r=run(rows)
        self.assertIn('PAGINATED_TOOLS_LIST',{x['code'] for x in r['unverified']})
        self.assertEqual(r['summary']['findings'],0)
    def test_catalog_changed_invalidates(self):
        rows=sample()
        rows.insert(2,{'jsonrpc':'2.0','method':'notifications/tools/list_changed'})
        self.assertEqual(run(rows)['summary']['findings'],0)
    def test_multiplex_sessions_prevent_cross_match(self):
        rows=sample(present=False)
        rows[0]={'session':'a','message':rows[0]}
        rows[1]={'session':'a','message':rows[1]}
        rows[2]={'session':'b','message':rows[2]}
        rows[3]={'session':'b','message':rows[3]}
        r=run(rows)
        self.assertEqual(r['summary']['findings'],0)
        self.assertEqual(r['summary']['sessions'],2)
    def test_sequential_id_reuse(self):
        rows=sample()+sample(present=False)
        self.assert_rule(run(rows),'RMC501')
    def test_concurrent_id_reuse_never_confirms(self):
        rows=sample(present=False)
        rows.insert(3,rows[2].copy())
        self.assertEqual(run(rows)['summary']['findings'],0)
    def test_missing_request_reply_not_verifiable(self):
        rows=sample()[:-1]
        self.assertIn('MISSING_RESPONSE',{x['code'] for x in run(rows)['unverified']})
    def test_invalid_iserror_type(self):
        rows=sample(present=False)
        rows[-1]['result']['isError']='false'
        r=run(rows)
        self.assertEqual(r['summary']['findings'],0)
        self.assertIn('INVALID_ERROR_FLAG',{e['code'] for e in r['unverified']})
    def test_unstructured_text_not_compared_semantically(self):
        rows=sample();rows[-1]['result']['content'][0]['text']='completely different prose'
        self.assertEqual(run(rows)['summary']['findings'],0)
    def test_null_json_value_is_valid_with_null_schema(self):
        rows=sample(schema={'type':'null'},value='unused');rows[-1]['result']['structuredContent']=None
        self.assertEqual(run(rows)['summary']['findings'],0)
    def test_output_path_refuse_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);trace=root/'a.jsonl';trace.write_text(''.join(json.dumps(x)+'\n' for x in sample()),encoding='utf-8')
            out=root/'existing.json';out.write_text('keep')
            p=subprocess.run([sys.executable,'-m','risu_mcp_trace',str(trace),'--out',str(out)],env={**os.environ,'PYTHONPATH':str(Path(__file__).resolve().parents[1]/'src')},capture_output=True,text=True)
            self.assertEqual(p.returncode,2)
            self.assertEqual(out.read_text(),'keep')
    def test_ci_gate_optin(self):
        with tempfile.TemporaryDirectory() as d:
            trace=Path(d)/'a.jsonl';trace.write_text(''.join(json.dumps(x)+'\n' for x in sample(present=False)))
            env={**os.environ,'PYTHONPATH':str(Path(__file__).resolve().parents[1]/'src')}
            for extra, expected in [((),0),(('--fail-on-observed',),1)]:
                p=subprocess.run([sys.executable,'-m','risu_mcp_trace',str(trace),'--format','json',*extra],env=env,capture_output=True,text=True)
                self.assertEqual(p.returncode,expected,p.stderr)
                self.assertEqual(json.loads(p.stdout)['summary']['findings'],1)
    def test_strict_incomplete_optin(self):
        with tempfile.TemporaryDirectory() as d:
            trace=Path(d)/'a.jsonl';trace.write_text(''.join(json.dumps(x)+'\n' for x in sample(error=True,present=False)))
            p=subprocess.run([sys.executable,'-m','risu_mcp_trace',str(trace),'--strict-incomplete'],env={**os.environ,'PYTHONPATH':str(Path(__file__).resolve().parents[1]/'src')},capture_output=True,text=True)
            self.assertEqual(p.returncode,2,p.stderr)
    def test_check_command_keeps_static_and_trace_separate(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            (root/'example.py').write_text('n=1\n')
            trace=root/'trace.jsonl'
            trace.write_text(''.join(json.dumps(x)+'\n' for x in sample(present=False)))
            env={**os.environ,'PYTHONPATH':str(Path(__file__).resolve().parents[1]/'src')}
            args=[sys.executable,'-m','risu_p5d_cli','check',str(root),'--mcp-trace',str(trace),'--mcp-protocol-version','2026-07-28','--format','json','--fail-on-observed']
            proc=subprocess.run(args,env=env,capture_output=True,text=True,timeout=20)
            self.assertEqual(proc.returncode,1,proc.stderr)
            record=json.loads(proc.stdout)
            self.assertEqual(record['source_analysis']['python_parsed'],1)
            self.assertEqual(record['mcp_semantic_verification']['semantic_verification'],'NOT_RUN')
            self.assertEqual(record['mcp_trace_verification']['summary']['findings'],1)
            self.assertEqual(record['summary']['confirmed_saved_replay'],0)
    def test_initialize_handshake_is_not_unmatched_error(self):
        rows=[{'jsonrpc':'2.0','id':'init','method':'initialize','params':{}},
              {'jsonrpc':'2.0','id':'init','result':{'protocolVersion':'2026-07-28'}}]+sample()
        record=run(rows)
        self.assertEqual(record['summary']['unverified_count'],0)
        self.assertEqual(record['summary']['structured_values_schema_checked'],1)
    def test_sarif_marks_capture_unattested(self):
        sarif=_sarif(run(sample(present=False)))
        self.assertEqual(sarif['runs'][0]['results'][0]['properties']['origin_integrity'],'UNATTESTED_LOCAL_CAPTURE')
    def test_duplicate_keys_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'a.jsonl';path.write_text('{"jsonrpc":"2.0","id":1,"id":2}\n')
            with self.assertRaises(TraceError):verify_trace(path)
    def test_malformed_json_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'a.jsonl';path.write_text('{bad}')
            with self.assertRaises(TraceError):verify_trace(path)
    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'real';p.write_text('{}')
            link=Path(d)/'link'
            try:link.symlink_to(p)
            except OSError:self.skipTest('symlink unavailable')
            with self.assertRaises(TraceError):verify_trace(link)
    def test_oversize_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'large';p.write_bytes(b' '*(4_194_304+1))
            with self.assertRaises(TraceError):verify_trace(p)
    def test_no_secret_values_echoed(self):
        secret='ACCESS_TOKEN_DO_NOT_ECHO_ABC'
        rows=sample(value={'value':secret});r=run(rows)
        self.assertNotIn(secret,json.dumps(r))
        self.assert_rule(r,'RMC502')

if __name__=='__main__':unittest.main()
