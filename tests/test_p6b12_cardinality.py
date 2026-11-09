"""P6-B12 RMC510 cardinality evidence requires an exact opt-in contract."""
from __future__ import annotations
import json,tempfile,unittest
from pathlib import Path
from risu_mcp_cardinality import validate,check,verify,CardinalityContractError,_size

def rule(mode='json-objects-per-text-block'):
    return {'id':'my_rows','tool':'read_query','limit_argument':'row_limit','mode':mode}

def doc(mode='json-objects-per-text-block'):
    return {'schema':'risu-mcp-cardinality-contract-v1','rules':[rule(mode)]}

def result(rows,is_error=False):
    return {'isError':is_error,'content':[{'type':'text','text':json.dumps({'i':i})}
        for i in range(rows)]}

def captured(calls,session='default'):
    out=[]
    for i,(args,r) in enumerate(calls,20):
        out.extend([
          {'jsonrpc':'2.0','id':i,'method':'tools/call',
           'params':{'name':'read_query','arguments':args}},
          {'jsonrpc':'2.0','id':i,'result':r}
        ])
    return out

def file_verify(msgs,contract=None):
    with tempfile.TemporaryDirectory() as d:
        p=Path(d)/'sample.jsonl'
        p.write_text(''.join(json.dumps(x,ensure_ascii=False)+'\n' for x in msgs))
        return verify(p,contract if contract is not None else doc())

class TestP6B12Cardinality(unittest.TestCase):
    def test_two_rows_pass_eight_rows_fail(self):
        x=file_verify(captured([({'row_limit':2},result(2)),({'row_limit':2},result(8))]))
        self.assertEqual(x['summary']['checked'],2)
        self.assertEqual(x['summary']['passed'],1)
        self.assertEqual([r['rule_id'] for r in x['findings']],['RMC510'])
    def test_no_values_echoed_in_report(self):
        x=file_verify(captured([({'row_limit':2,'secret':'canary_VERY_PRIVATE'},result(8))]))
        self.assertNotIn('canary_VERY_PRIVATE',json.dumps(x))
        self.assertNotIn('read_query',json.dumps(x))
    def test_non_object_block_abstains(self):
        q=result(1)
        q['content'].append({'type':'text','text':'Summary: 2'})
        x=file_verify(captured([({'row_limit':2},q)]))
        self.assertEqual(x['summary']['checked'],0)
        self.assertEqual(x['summary']['unverified'],1)
    def test_input_bool_float_string_do_not_coerce_to_limit(self):
        for arg in (True,2.0,'2',None,-1,1001):
            with self.subTest(arg=arg):
                self.assertEqual(check(result(8),{'row_limit':arg},rule())[0],'UNVERIFIED')
    def test_error_call_does_not_count_as_mismatch(self):
        x=file_verify(captured([({'row_limit':2},result(8,True))]))
        self.assertEqual(x['summary']['observed_mismatches'],0)
        self.assertEqual(x['summary']['unverified'],1)
    def test_json_array_text_carrier(self):
        ok={'content':[{'type':'text','text':'[{"i":1},{"i":2}]'}]}
        bad={'content':[{'type':'text','text':'[{"i":1},{"i":2},{"i":3}]'}]}
        x=file_verify(captured([({'row_limit':2},ok),({'row_limit':2},bad)]),doc('json-array-text'))
        self.assertEqual(x['summary']['observed_mismatches'],1)
    def test_structured_array_carrier(self):
        x=file_verify(captured([({'row_limit':1},{'structuredContent':[{'x':1},{'x':2}],'content':[]})]),doc('structured-array'))
        self.assertEqual(x['summary']['observed_mismatches'],1)
    def test_missing_result_is_unverified(self):
        x=file_verify([{'jsonrpc':'2.0','id':1,'method':'tools/call',
                        'params':{'name':'read_query','arguments':{'row_limit':2}}}])
        self.assertEqual(x['summary']['unverified'],1)
    def test_numeric_id_across_sessions_not_collapsed(self):
        messages=[]
        for s,num in [('first',2),('second',8)]:
            for m in captured([({'row_limit':2},result(num))]):
                messages.append({'session':s,'message':m})
        x=file_verify(messages)
        self.assertEqual(x['summary']['checked'],2)
        self.assertEqual(x['summary']['observed_mismatches'],1)
    def test_forged_extra_contract_field_rejected(self):
        d=doc();d['rules'][0]['unexpected']='arbitrary'
        with self.assertRaises(CardinalityContractError):validate(d)
    def test_duplicate_rule_id_rejected(self):
        d=doc();d['rules'].append(dict(rule()))
        with self.assertRaises(CardinalityContractError):validate(d)
    def test_missing_limit_unverified(self):
        x=file_verify(captured([({},result(8))]))
        self.assertEqual(x['summary']['unverified'],1)
    def test_truncated_empty_carrier_abstains(self):
        self.assertEqual(_size({'content':[]},'json-objects-per-text-block')[0],None)
    def test_oversized_block_abstains(self):
        self.assertEqual(check({'content':[{'type':'text','text':'A'*9000}]},
                           {'row_limit':2},rule())[0],'UNVERIFIED')

if __name__=='__main__':unittest.main()
