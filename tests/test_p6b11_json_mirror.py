"""B11 development-only: explicit JSON mirror, summary controls and safe gaps.

These are synthetic rule-engine checks, not independent external issue evidence.
"""
from __future__ import annotations
import json
from pathlib import Path
import tempfile
import unittest
from risu_display_fidelity import check,validate,DisplayContractError
from risu_mcp_trace import verify_trace

def rule(mode='json-text-mirror',on_error=False):
    return {'id':'explicit_json_mirror','tool':'demo','source':'','content_index':None,
            'prefix_raw':'','mode':mode,'on_error':on_error}

def sample(data,blocks):
    return {'isError':False,'structuredContent':data,
            'content':[{'type':'text','text':x} for x in blocks]}

def verify(body,dc):
    items=[
        {'jsonrpc':'2.0','id':1,'method':'tools/list','params':{}},
        {'jsonrpc':'2.0','id':1,'result':{'tools':[{'name':'demo',
            'inputSchema':{'type':'object'},
            'outputSchema':{'type':'object','properties':{
                'items':{'type':'array','items':{'type':'string'}}}}}]}},
        {'jsonrpc':'2.0','id':2,'method':'tools/call',
         'params':{'name':'demo','arguments':{}}},
        {'jsonrpc':'2.0','id':2,'result':body},
    ]
    with tempfile.TemporaryDirectory() as d:
        p=Path(d)/'trace.jsonl'
        p.write_text(''.join(json.dumps(m)+'\n' for m in items))
        return verify_trace(p,'2025-11-25',display_contract=dc)

class TestB11OptInJsonMirror(unittest.TestCase):
    def test_old_elided_json_is_confirmed_mismatch_under_explicit_obligation(self):
        actual={'items':['record_'+str(i) for i in range(150)]}
        old=sample(actual,['Structured result returned in structuredContent'])
        r=check(old,rule())
        self.assertEqual(r,('MISMATCH',''))
        full=verify(old,{'schema':'risu-mcp-display-contract-v1','rules':[rule()]})
        self.assertEqual([f['rule_id'] for f in full['findings']],['RMC509'])
    def test_summary_followed_by_full_json_is_valid(self):
        actual={'items':['record_'+str(i) for i in range(150)]}
        new=sample(actual,['Summary: 150 results',json.dumps(actual)])
        self.assertEqual(check(new,rule()),('PASS',''))
        full=verify(new,{'schema':'risu-mcp-display-contract-v1','rules':[rule()]})
        self.assertEqual(full['findings'],[])
        self.assertEqual(full['summary']['explicit_display_rules_passed'],1)
    def test_no_contract_does_not_impose_mirror_on_any_tool(self):
        actual={'items':['a','b']}
        out=verify(sample(actual,['Summary only']),None)
        self.assertEqual(out['findings'],[])
        self.assertEqual(out['summary']['explicit_display_rules_declared'],0)
    def test_json_mirror_with_different_key_order_is_equal(self):
        self.assertEqual(check(sample({'a':1,'b':2},['{"b":2,"a":1}']),rule())[0],'PASS')
    def test_json_boolean_vs_integer_is_not_equated(self):
        self.assertEqual(check(sample({'value':True},['{"value":1}']),rule())[0],'MISMATCH')
    def test_opaque_nonjson_summary_is_not_treated_as_mirror(self):
        self.assertEqual(check(sample({'a':1},['one item returned']),rule())[0],'MISMATCH')
    def test_missing_structured_content_unverified(self):
        v={'isError':False,'content':[{'type':'text','text':'{}'}]}
        self.assertEqual(check(v,rule())[0],'UNVERIFIED')
    def test_no_text_blocks_with_mirror_is_mismatch(self):
        self.assertEqual(check({'structuredContent':{'x':1},'content':[]},rule())[0],'MISMATCH')
    def test_oversized_candidate_is_unverified(self):
        self.assertEqual(check(sample({'value':'x'},['A'*5000]),rule())[0],'UNVERIFIED')
    def test_duplicate_keys_do_not_count_as_mirror(self):
        self.assertEqual(check(sample({'a':2},['{"a":1,"a":2}']),rule())[0],'MISMATCH')
    def test_nonfinite_json_refused(self):
        self.assertEqual(check(sample({'a':0},['{"a":NaN}']),rule())[0],'MISMATCH')
    def test_contract_rejects_default_scalar_mapping_for_json_mirror(self):
        for field,value in [('source','/data'),('content_index',0),('prefix_raw','Value: '),
                            ('mode',[]),('on_error','false')]:
            q=rule();q[field]=value
            with self.assertRaises(DisplayContractError):
                validate({'schema':'risu-mcp-display-contract-v1','rules':[q]})
    def test_no_payload_exposure_in_report(self):
        sentinel='SECRET_CANARY_'+('X'*30)
        m=verify(sample({'items':[sentinel]},['summary']),
                {'schema':'risu-mcp-display-contract-v1','rules':[rule()]})
        self.assertNotIn(sentinel,json.dumps(m))
        self.assertIn('RMC509',[f['rule_id'] for f in m['findings']])

if __name__=='__main__':unittest.main()
