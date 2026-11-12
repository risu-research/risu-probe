"""B15 product hardening; only synthetic fixtures and stdlib unittest."""
from __future__ import annotations
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from risu_mcp_observations import (
    _load, ObservationError, validate_contract, validate_witness, verify
)

def line(msg):
    return json.dumps(msg,ensure_ascii=False,separators=(',',':'))+'\n'

def contract(*rules):
    return {'schema':'risu-mcp-observation-contract-v1','rules':list(rules)}

def state_rule(kind='state-unchanged', tool='query', when=None):
    return {'id':'state','tool':tool,'kind':kind,'when':{} if when is None else when}

def json_rule(tool='analyze_table', when=None, carrier='single-text-json'):
    return {'id':'shape','tool':tool,'kind':'json-object',
        'when':{} if when is None else when,
        'carrier':carrier,'required':{'/row_count':'integer',
            '/null_counts':'object'}}

def response(body=None, error=False, text=None):
    value={'isError':error}
    if text is not None:
        value['content']=[{'type':'text','text':text}]
    if body is not None:
        value['structuredContent']=body
    return value

class ContractTest(unittest.TestCase):
    def setUp(self):
        self.d=tempfile.TemporaryDirectory()
        self.addCleanup(self.d.cleanup)
        self.root=Path(self.d.name)

    def trace(self,tool='query',args=None,result=None,rid=20,session='default'):
        if args is None:args={'sql':'SELECT 1'}
        if result is None:result=response(text='{"row_count":2,"null_counts":{}}')
        request={'jsonrpc':'2.0','id':rid,'method':'tools/call',
                 'params':{'name':tool,'arguments':args}}
        reply={'jsonrpc':'2.0','id':rid,'result':result}
        if session!='default':
            request={'session':session,'message':request}
            reply={'session':session,'message':reply}
        p=self.root/'trace.jsonl'
        p.write_text(line(request)+line(reply),encoding='utf-8')
        return p

    def ledger(self,p,tool='query',before='0'*64,after='0'*64,session='default',
               request_line=1,response_line=2):
        return {'schema':'risu-mcp-state-witness-v1',
                'trace_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),
                'records':[{'session':session,'request_line':request_line,
                    'response_line':response_line,'tool':tool,
                    'before_sha256':before,'after_sha256':after}]}

    def test_observed_effect_change_bound_to_matching_real_wire(self):
        t=self.trace(args={'sql':'UPDATE records SET x=1'})
        w=self.ledger(t,after='1'*64)
        r=verify(t,contract(state_rule(when={'sql':'UPDATE records SET x=1'})),w)
        self.assertEqual(r['summary']['observed_mismatches'],1)
        self.assertEqual(r['findings'][0]['rule_id'],'RME610')
        self.assertEqual(r['summary']['unverified'],0)

    def test_normal_unchanged_effect_passes(self):
        t=self.trace(result=response(error=True,text='Rejected'))
        w=self.ledger(t)
        r=verify(t,contract(state_rule()),w)
        self.assertEqual((r['summary']['passed'],r['summary']['unverified']),(1,0))

    def test_positive_change_obligation_passes(self):
        t=self.trace()
        w=self.ledger(t,after='1'*64)
        r=verify(t,contract(state_rule(kind='state-changed')),w)
        self.assertEqual(r['summary']['passed'],1)

    def test_missing_witness_abstains_not_success(self):
        t=self.trace()
        r=verify(t,contract(state_rule()))
        self.assertEqual((r['summary']['checked'],r['summary']['unverified']),(0,1))
        self.assertEqual(r['findings'],[])

    def test_stale_witness_rejected(self):
        t=self.trace()
        w=self.ledger(t)
        t.write_text(t.read_text()+'\n')
        with self.assertRaises(ObservationError):
            verify(t,contract(state_rule()),w)

    def test_response_line_mismatch_is_unverified(self):
        t=self.trace()
        w=self.ledger(t,request_line=2,response_line=3)
        r=verify(t,contract(state_rule()),w)
        self.assertEqual(r['summary']['observed_mismatches'],0)
        self.assertGreaterEqual(r['summary']['unverified'],2)

    def test_json_result_contract_catches_valid_input_failed_output(self):
        t=self.trace(tool='analyze_table',result=response(text=
            'Error analyzing table: Object of type int64 is not JSON serializable'))
        r=verify(t,contract(json_rule()))
        self.assertEqual(r['summary']['observed_mismatches'],1)
        self.assertEqual(r['findings'][0]['rule_id'],'RME620')

    def test_json_contract_accepts_correct_normal_result(self):
        t=self.trace(tool='analyze_table',result=response(text=
            '{"row_count":2,"null_counts":{"id":0},"message":"Error is a column label"}'))
        r=verify(t,contract(json_rule()))
        self.assertEqual((r['summary']['passed'],r['summary']['observed_mismatches']),(1,0))

    def test_tool_properly_reports_error_abstains(self):
        t=self.trace(tool='analyze_table',result=response(error=True,text='An error occurred'))
        r=verify(t,contract(json_rule()))
        self.assertEqual((r['summary']['checked'],r['summary']['unverified']),(0,1))

    def test_without_explicit_json_contract_no_keyword_detection(self):
        t=self.trace(tool='unrelated',result=response(text='Error: help?'))
        r=verify(t,contract(json_rule()))
        self.assertEqual(r['summary']['observed_mismatches'],0)
        self.assertEqual(r['unverified'][0]['reason'],'CONTRACT_RULE_UNMATCHED')

    def test_json_invalid_field_and_boolean_vs_integer(self):
        t=self.trace(tool='analyze_table',result=response(text=
            '{"row_count":true,"null_counts":{}}'))
        r=verify(t,contract(json_rule()))
        self.assertEqual(r['summary']['observed_mismatches'],1)

    def test_typed_session_matching(self):
        t=self.trace(tool='query',session='runA',rid=8)
        w=self.ledger(t,session='runA')
        r=verify(t,contract(state_rule()),w)
        self.assertEqual(r['summary']['passed'],1)

    def test_structured_carrier(self):
        t=self.trace(tool='analyze_table',result=response(
            body={'row_count':2,'null_counts':{}},text='A nice summary'))
        r=verify(t,contract(json_rule(carrier='structured-content')))
        self.assertEqual(r['summary']['passed'],1)

    def test_match_args_filter_does_not_false_flag_control(self):
        t=self.trace(tool='analyze_table',args={'table':'text_only'},
                     result=response(text='normal human-readable summary'))
        r=verify(t,contract(json_rule(when={'table':'numeric_records'})))
        self.assertEqual(r['summary']['matched'],0)
        self.assertEqual(r['summary']['observed_mismatches'],0)

    def test_reject_json_duplicate_keys(self):
        f=self.root/'bad.json'
        f.write_text('{"schema":"x","schema":"y"}',encoding='utf-8')
        with self.assertRaises(ObservationError):
            _load(f,1000)

    def test_reject_duplicate_witness_and_ambiguous_contract(self):
        t=self.trace()
        w=self.ledger(t)
        w['records'].append(w['records'][0].copy())
        with self.assertRaises(ObservationError):
            verify(t,contract(state_rule()),w)
        with self.assertRaises(ObservationError):
            validate_contract(contract(state_rule(),state_rule()))

    def test_contract_disallows_weak_unscoped_field_regex(self):
        bad=json_rule()
        bad['required']={'/../secret':'string'}
        with self.assertRaises(ObservationError):
            validate_contract(contract(bad))

    def test_response_is_not_trusted_when_call_incomplete(self):
        p=self.root/'trace.jsonl'
        p.write_text(line({'jsonrpc':'2.0','id':1,'method':'tools/call',
            'params':{'name':'query','arguments':{}}}),encoding='utf-8')
        r=verify(p,contract(state_rule()))
        self.assertEqual(r['summary']['checked'],0)
        self.assertGreater(r['summary']['unverified'],0)


if __name__=='__main__':
    unittest.main()
