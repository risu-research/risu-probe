"""P6-B8 regression: bounded full catalogs, reported errors, opt-in behavior."""
from __future__ import annotations
import json
from pathlib import Path
import tempfile
import unittest

from risu_mcp_trace import TraceError, verify_trace, _check_behavior_contract


def run(rows, contract=None):
    with tempfile.TemporaryDirectory() as d:
        p=Path(d)/'trace.jsonl'
        p.write_text(''.join(json.dumps(row,ensure_ascii=False)+'\n' for row in rows),encoding='utf-8')
        return verify_trace(p, '2025-11-25', contract)


def trace(tools=None, *, name='target', content='', is_error=False, value=None, args=None):
    if tools is None:
        tools=[{'name':name,'inputSchema':{'type':'object'},
                'outputSchema':{'type':'object','properties':{'value':{'type':'integer'}},
                                'required':['value']}}]
    result={'isError':is_error,'content':[{'type':'text','text':content}]}
    if value is not None:
        result['structuredContent']=value
    return [
        {'jsonrpc':'2.0','id':1,'method':'tools/list','params':{}},
        {'jsonrpc':'2.0','id':1,'result':{'tools':tools}},
        {'jsonrpc':'2.0','id':2,'method':'tools/call',
         'params':{'name':name,'arguments':args if args is not None else {}}},
        {'jsonrpc':'2.0','id':2,'result':result},
    ]


def large_catalog():
    schema={'type':'object','properties':{'value':{'type':'integer'}},
            'required':['value']}
    schema['properties'].update({'extra_%02d'%i:{'type':'string'} for i in range(38)})
    return [{'name':'tool_%02d'%i,'inputSchema':{'type':'object'},
             'outputSchema':schema} for i in range(39)]


def contract():
    return {'schema':'risu-mcp-behavior-contract-v1','rules':[
        {'id':'head_zero_empty','tool':'read_text_file',
         'when':{'head':0},'text_equals':''}]}


class TestP6B8(unittest.TestCase):
    def test_genuine_full_catalog_without_projection(self):
        tools=large_catalog()
        rows=trace(tools,name='tool_38',content='ok',value={'value':7})
        r=run(rows)
        self.assertEqual(r['semantic_verification'],'CHECKED_NO_MISMATCHES')
        self.assertEqual(r['summary']['latest_catalog_declarations_indexed'],39)
        self.assertEqual(r['summary']['latest_catalog_declarations_schema_validated'],1)
        self.assertEqual(r['summary']['latest_catalog_declarations_not_validated'],38)
        self.assertEqual(r['summary']['structured_values_schema_checked'],1)
        self.assertEqual(r['summary']['catalog_snapshots_indexed'],1)
        self.assertEqual(r['summary']['findings'],0)
    def test_large_catalog_still_verifies_target_mismatch(self):
        rows=trace(large_catalog(),name='tool_38',value={'value':'wrong'})
        r=run(rows)
        self.assertEqual([f['rule_id'] for f in r['findings']],['RMC502'])
        self.assertNotIn('wrong',json.dumps(r))
    def test_duplicate_declaration_invalidates_whole_catalog(self):
        tools=large_catalog()
        rows=trace(tools+[tools[0]],name='tool_38',value={'value':7})
        r=run(rows)
        self.assertEqual(r['summary']['structured_values_schema_checked'],0)
        self.assertIn('INVALID_CATALOG',{x['code'] for x in r['unverified']})
    def test_unbounded_catalog_is_not_silently_projected(self):
        rows=trace([{'name':str(i)} for i in range(1025)],name='0')
        with self.assertRaises(TraceError):
            run(rows)
    def test_sdk_reported_output_validation_is_diagnostic_not_confirmed(self):
        rows=trace(content='Error executing tool: Output validation error: missing structuredContent',is_error=True)
        r=run(rows)
        self.assertEqual(r['summary']['findings'],0)
        self.assertIn('REPORTED_OUTPUT_VALIDATION_REJECTION',{x['code'] for x in r['unverified']})
        self.assertNotIn('missing structuredContent',json.dumps(r))
    def test_generic_error_is_not_misclassified(self):
        rows=trace(content='Not found; incorrect arguments',is_error=True)
        r=run(rows)
        self.assertEqual([x['code'] for x in r['unverified']],['EXECUTION_ERROR'])
    def test_input_rejection_is_separate_from_output_rejection(self):
        rows=trace(content='Input validation failed: invalid value',is_error=True)
        r=run(rows)
        self.assertIn('REPORTED_INPUT_VALIDATION_REJECTION',{x['code'] for x in r['unverified']})
        self.assertEqual(r['summary']['findings'],0)
    def test_explicit_head_zero_oracle_identifies_wrong_text(self):
        tools=[{'name':'read_text_file','inputSchema':{'type':'object'}}]
        rows=trace(tools,name='read_text_file',content='a\nb\nc\n',args={'head':0})
        r=run(rows,contract())
        self.assertEqual([f['rule_id'] for f in r['findings']],['RMC506'])
        self.assertEqual(r['summary']['explicit_behavior_assertions_checked'],1)
        self.assertNotIn('a\\nb',json.dumps(r))
    def test_explicit_head_zero_oracle_accepts_empty_text(self):
        tools=[{'name':'read_text_file','inputSchema':{'type':'object'}}]
        rows=trace(tools,name='read_text_file',content='',args={'head':0})
        r=run(rows,contract())
        self.assertEqual(r['summary']['findings'],0)
        self.assertEqual(r['summary']['explicit_behavior_assertions_checked'],1)
    def test_no_assertion_on_other_arguments(self):
        tools=[{'name':'read_text_file','inputSchema':{'type':'object'}}]
        r=run(trace(tools,name='read_text_file',content='data',args={'head':2}),contract())
        self.assertEqual(r['summary']['explicit_behavior_assertions_matched'],0)
        self.assertEqual(r['summary']['findings'],0)
    def test_tool_error_never_proves_behavior_mismatch(self):
        tools=[{'name':'read_text_file','inputSchema':{'type':'object'}}]
        r=run(trace(tools,name='read_text_file',content='failed',is_error=True,args={'head':0}),contract())
        self.assertEqual(r['summary']['findings'],0)
        self.assertEqual(r['summary']['explicit_behavior_assertions_checked'],0)
    def test_unstructured_envelope_does_not_invent_behavior_value(self):
        tools=[{'name':'read_text_file','inputSchema':{'type':'object'}}]
        rows=trace(tools,name='read_text_file',content='some',args={'head':0})
        rows[-1]['result']['content']=[{'type':'image','data':'x'}]
        r=run(rows,contract())
        self.assertEqual(r['summary']['findings'],0)
        self.assertIn('BEHAVIOR_OUTPUT_UNAVAILABLE',{x['code'] for x in r['unverified']})
    def test_fail_closed_behavior_contract(self):
        for bad in [
            {'schema':'wrong','rules':[]},
            {'schema':'risu-mcp-behavior-contract-v1','rules':[{'id':'a','tool':'x','when':{},'text_equals':''}]},
            {'schema':'risu-mcp-behavior-contract-v1','rules':[{'id':'a','tool':'x','when':{'head':0},'text_equals':''}]*2},
        ]:
            with self.subTest(bad=bad):
                with self.assertRaises(TraceError):
                    _check_behavior_contract(bad)


if __name__=='__main__':
    unittest.main()
