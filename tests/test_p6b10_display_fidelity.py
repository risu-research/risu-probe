"""P6-B10 development-only CYAN760/785 and independent synthetic display controls.

B9 CYAN760/785 are now development cases; never count these as new heldout.
"""
from __future__ import annotations
import json
from pathlib import Path
import tempfile
import unittest

from risu_display_fidelity import check, validate, DisplayContractError, _render_commonmark
from risu_mcp_trace import verify_trace

def rule(tool,source,mode='markdown-rendered',prefix='Error: ',on_error=True,index=0):
    return {'id':'explicit_1','tool':tool,'source':source,'content_index':index,
            'prefix_raw':prefix,'mode':mode,'on_error':on_error}

def contract(rules):
    return {'schema':'risu-mcp-display-contract-v1','rules':rules}

def result(text,structured,is_error=False):
    return {'isError':is_error,'structuredContent':structured,
            'content':[{'type':'text','text':text}]}

def trace(toolname,body):
    entries=[
      {'jsonrpc':'2.0','id':1,'method':'tools/list','params':{}},
      {'jsonrpc':'2.0','id':1,'result':{'tools':[{'name':toolname,
             'inputSchema':{'type':'object'},
             'outputSchema':{'type':'object'}}]}},
      {'jsonrpc':'2.0','id':2,'method':'tools/call',
       'params':{'name':toolname,'arguments':{}}},
      {'jsonrpc':'2.0','id':2,'result':body},
    ]
    with tempfile.TemporaryDirectory() as d:
        p=Path(d)/'data.jsonl'
        p.write_text(''.join(json.dumps(x)+'\n' for x in entries))
        return p

def observe(toolname,body,dc):
    # Keep the temporary capture live until verify_trace returns.
    with tempfile.TemporaryDirectory() as d:
        p=Path(d)/'data.jsonl'
        entries=[
          {'jsonrpc':'2.0','id':1,'method':'tools/list','params':{}},
          {'jsonrpc':'2.0','id':1,'result':{'tools':[{'name':toolname,
                'inputSchema':{'type':'object'},'outputSchema':{'type':'object'}}]}},
          {'jsonrpc':'2.0','id':2,'method':'tools/call',
           'params':{'name':toolname,'arguments':{}}},
          {'jsonrpc':'2.0','id':2,'result':body},
        ]
        p.write_text(''.join(json.dumps(x)+'\n' for x in entries))
        return verify_trace(p,'2025-11-25',display_contract=dc)

class TestP6B10Display(unittest.TestCase):
    def test_cyan760_old_real_markdown_emphasis_drift(self):
        r=rule('cyan_error','/error/message')
        v=result('Error: No running app matches "A*p*".',
                 {'error':{'message':'No running app matches "A*p*".'}},True)
        status,_=check(v,r)
        self.assertEqual(status,'MISMATCH')
        audit=observe('cyan_error',v,contract([r]))
        self.assertIn('RMC507',[f['rule_id'] for f in audit['findings']])
    def test_cyan760_official_fix_preserves_visible_text(self):
        r=rule('cyan_error','/error/message')
        v=result('Error: No running app matches "A\\*p\\*".',
                 {'error':{'message':'No running app matches "A*p*".'}},True)
        self.assertEqual(check(v,r)[0],'PASS')
        audit=observe('cyan_error',v,contract([r]))
        self.assertNotIn('RMC507',[f['rule_id'] for f in audit['findings']])
    def test_cyan785_old_escaped_query_cannot_be_raw_copied(self):
        q='cat:astro-ph* AND submittedDate:[202601010000 TO 202602010000]'
        r=rule('cyan_query','/effectiveQuery','raw-copy','**effectiveQuery:** ',False)
        v=result('anything\n\n**effectiveQuery:** cat:astro-ph\\* AND submittedDate:\\[202601010000 TO 202602010000\\]',
                 {'effectiveQuery':q})
        self.assertEqual(check(v,r)[0],'MISMATCH')
        audit=observe('cyan_query',v,contract([r]))
        self.assertIn('RMC508',[f['rule_id'] for f in audit['findings']])
    def test_cyan785_fixed_code_span_copies_exact(self):
        q='cat:astro-ph* AND submittedDate:[202601010000 TO 202602010000]'
        r=rule('cyan_query','/effectiveQuery','raw-copy','**effectiveQuery:** ',False)
        v=result('anything\n\n**effectiveQuery:** `'+q+'`',{'effectiveQuery':q})
        self.assertEqual(check(v,r)[0],'PASS')
        self.assertFalse(observe('cyan_query',v,contract([r]))['findings'])
    def test_no_inferred_relation_when_no_contract(self):
        v=result('Error: No running app matches "A*p*".',
                 {'error':{'message':'No running app matches "A*p*".'}},True)
        audit=observe('cyan_error',v,None)
        self.assertEqual(audit['summary']['explicit_display_rules_declared'],0)
        self.assertFalse(audit['findings'])
    def test_correct_markdown_emphasis_preserved_when_expected_is_rendered(self):
        rule1=rule('a','/label')
        v=result('Error: An *emphasized* phrase',{'label':'An emphasized phrase'})
        self.assertEqual(check(v,rule1)[0],'PASS')
    def test_missing_structured_pointer_is_unverified(self):
        r=rule('a','/missing')
        self.assertEqual(check(result('Error: whatever',{}),r),
                         ('UNVERIFIED','DISPLAY_STRING_SOURCE_UNAVAILABLE'))
    def test_non_string_source_is_unverified(self):
        r=rule('a','/number')
        self.assertEqual(check(result('Error: 100',{'number':100}),r)[0],'UNVERIFIED')
    def test_unrelated_text_has_no_unique_prefix(self):
        r=rule('a','/x')
        self.assertEqual(check(result('nothing',{'x':'any'}),r)[0],'UNVERIFIED')
    def test_multiple_prefixes_are_ambiguous(self):
        r=rule('a','/x')
        self.assertEqual(check(result('Error: 1\nError: 2',{'x':'2'}),r)[0],'UNVERIFIED')
    def test_embedded_html_is_unsupported(self):
        r=rule('a','/x')
        v=result('Error: <em>test</em>',{'x':'test'})
        self.assertEqual(check(v,r)[0],'UNVERIFIED')
    def test_link_markup_is_unsupported(self):
        r=rule('a','/x')
        v=result('Error: [visible](url)',{'x':'visible'})
        self.assertEqual(check(v,r)[0],'UNVERIFIED')
    def test_oversize_value_is_unverified_without_echoing(self):
        r=rule('a','/x')
        v=result('Error: '+('A'*4100),{'x':'A'*4100})
        self.assertEqual(check(v,r)[0],'UNVERIFIED')
    def test_no_code_span_guessing_on_unclosed_ticks(self):
        r=rule('a','/x','raw-copy','**x:** ',False)
        self.assertEqual(check(result('**x:** `incomplete',{'x':'incomplete'}),r)[0],'UNVERIFIED')
    def test_json_pointer_escaped_field(self):
        r=rule('a','/a~1b/~0x')
        self.assertEqual(check(result('Error: literal',{'a/b':{'~x':'literal'}}),r)[0],'PASS')
    def test_missing_mismatch_does_not_leak_values_in_report(self):
        r=rule('a','/x')
        secret='PRIVATE_CANARY_'+('B'*77)
        r['on_error']=False
        v=result('Error: altered',{'x':secret})
        audit=observe('a',v,contract([r]))
        self.assertNotIn(secret,json.dumps(audit))
        self.assertIn('RMC507',[v['rule_id'] for v in audit['findings']])
    def test_is_error_mismatch_does_not_claim_success_output(self):
        r=rule('a','/error/message')
        v=result('Error: *alpha*',{'error':{'message':'*alpha*'}},True)
        audit=observe('a',v,contract([r]))
        self.assertIn('RMC507',[f['rule_id'] for f in audit['findings']])
        self.assertEqual(audit['summary']['structured_values_schema_checked'],0)
        self.assertIn('EXECUTION_ERROR',[g['code'] for g in audit['unverified']])
    def test_malformed_rules_fail_closed(self):
        for change in ({'mode':[]},{'source':'bad'},{'content_index':True},{'prefix_raw':''},
                       {'on_error':'true'},{'source':'/~2'},{'source':'/'*500}):
            r=rule('x','/y');r.update(change)
            with self.assertRaises(DisplayContractError):
                validate(contract([r]))
    def test_duplicate_rule_id_fails_closed(self):
        with self.assertRaises(DisplayContractError):
            validate(contract([rule('a','/x'),rule('b','/y')]))
    def test_nested_markdown_layout_is_unverified(self):
        displayed,reason=_render_commonmark('- a\n- b')
        self.assertIsNone(displayed)
        self.assertEqual(reason,'DISPLAY_MARKDOWN_LAYOUT_UNSUPPORTED')

if __name__=='__main__':unittest.main()
