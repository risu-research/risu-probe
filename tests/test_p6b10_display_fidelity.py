"""P6-B10 deterministic positive/negative controls, with no external runtime."""
import json
from pathlib import Path
import tempfile
import unittest

from risu_display_fidelity import verify_display_fidelity, _evaluate, _validate_contract
from risu_mcp_trace import TraceError


def contract(mode='markdown-literal', path='/value', name='sample', is_error=False):
    return {'schema':'risu-display-fidelity-contract-v1','rules':[{
        'id':'literal_value','tool':name,'pointer':path,
        'line_prefix':'**value:** ','mode':mode,'is_error':is_error}]}


def run(value, rendered, *, mode='markdown-literal', is_error=False,
        tool='sample', structured=None, rule_path='/value'):
    rows=[
      {'jsonrpc':'2.0','id':1,'method':'tools/call',
       'params':{'name':tool,'arguments':{}}},
      {'jsonrpc':'2.0','id':1,'result':{
          'isError':is_error,'structuredContent':structured if structured is not None else {'value':value},
          'content':[{'type':'text','text':'**value:** '+rendered}]}}
    ]
    with tempfile.TemporaryDirectory() as d:
        p=Path(d)/'trace.jsonl'
        p.write_text(''.join(json.dumps(r)+'\n' for r in rows),encoding='utf-8')
        return verify_display_fidelity(p,contract(mode,rule_path,tool,is_error))


class DisplayFidelityTests(unittest.TestCase):
    def codes(self,r):
        return [x['rule_id'] for x in r['findings']]
    def test_markdown_emphasis_corruption_detected(self):
        self.assertEqual(self.codes(run('A*p*','A*p*')),['RDF601'])
        self.assertEqual(self.codes(run('A*p*',r'A\*p\*')),[])
    def test_url_defanging_corruption_detected(self):
        self.assertEqual(self.codes(run('www.example.com',r'www\[.\]example.com')),['RDF601'])
        self.assertEqual(self.codes(run('www.example.com','www.example.com')),[])
    def test_markdown_link_injection_detected(self):
        x='SEARCH[Location](AREA[LocationCountry]"Mexico")'
        self.assertEqual(self.codes(run(x,x)),['RDF601'])
        escaped=r'SEARCH\[Location\]\(AREA\[LocationCountry\]"Mexico"\)'
        self.assertEqual(self.codes(run(x,escaped)),[])
    def test_copy_literal_dev_case(self):
        x='cat:astro-ph* AND submittedDate:[202601010000 TO 202602010000]'
        old=r'cat:astro-ph\* AND submittedDate:\[202601010000 TO 202602010000\]'
        self.assertEqual(self.codes(run(x,old,mode='code-copy')),['RDF601'])
        self.assertEqual(self.codes(run(x,chr(96)+x+chr(96),mode='code-copy')),[])
        self.assertEqual(self.codes(run('simple','simple',mode='code-copy')),[])
    def test_json_special_linebreak_new_and_old(self):
        v='line1\nline2'
        self.assertEqual(self.codes(run(v,'line1 line2',mode='json-string-special')),['RDF601'])
        self.assertEqual(self.codes(run(v,chr(96)+'"line1\\nline2"'+chr(96),mode='json-string-special')),[])
        self.assertEqual(self.codes(run('', '',mode='json-string-special')),['RDF601'])
        self.assertEqual(self.codes(run('',chr(96)+'""'+chr(96),mode='json-string-special')),[])
        self.assertEqual(self.codes(run(' simple ',chr(96)+'" simple "'+chr(96),mode='json-string-special')),[])
        self.assertEqual(self.codes(run('safe','safe',mode='json-string-special')),[])
    def test_missing_structured_is_unverified(self):
        r=run('x','x',structured={})
        self.assertEqual(r['summary']['literal_checks_completed'],0)
        self.assertEqual(self.codes(r),[])
        self.assertEqual(r['unverified'][0]['code'],'UNAVAILABLE_STRUCTURED_STRING')
    def test_html_and_image_forbidden(self):
        self.assertEqual(self.codes(run('<i>x</i>','<i>x</i>')),['RDF601'])
        self.assertEqual(self.codes(run('x','![x](https://example.test)')),['RDF601'])
    def test_correct_raw_normal_has_zero_warn(self):
        for v in ('Hello','plain-123','_identifier_', 'a*b'):
            with self.subTest(v=v):
                import re
                escaped=re.sub(r'([*_])',r'\\\1',v)
                r=run(v,escaped)
                self.assertEqual(self.codes(r),[])
                self.assertEqual(r['summary']['unverified'],0)
    def test_errors_require_opt_in(self):
        self.assertEqual(self.codes(run('A*p*','A*p*',is_error=True)),['RDF601'])
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'x.jsonl'
            p.write_text(''.join(json.dumps(x)+'\n' for x in [
                {'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'sample','arguments':{}}},
                {'jsonrpc':'2.0','id':1,'result':{'isError':False,'structuredContent':{'value':'A*p*'},
                   'content':[{'type':'text','text':'**value:** A*p*'}]}}
            ]))
            a=verify_display_fidelity(p,contract(is_error=True))
            self.assertEqual(a['summary']['applicable_assertions'],0)
            self.assertEqual(a['summary']['findings'],0)
    def test_no_sensitive_echo(self):
        value='TOKEN_DO_NOT_LEAK_A*p*'
        r=run(value,value)
        self.assertNotIn(value,json.dumps(r))
        self.assertEqual(self.codes(r),['RDF601'])
    def test_malformed_contract_fail_closed(self):
        for value in [
          {'schema':'wrong','rules':[]},
          {'schema':'risu-display-fidelity-contract-v1','rules':[]},
          {'schema':'risu-display-fidelity-contract-v1','rules':[
               {**contract()['rules'][0],'extra':'x'}]},
          {'schema':'risu-display-fidelity-contract-v1','rules':contract()['rules']*2},
        ]:
            with self.subTest(value=value):
                with self.assertRaises(TraceError):
                    _validate_contract(value)
    def test_bounded_evaluator(self):
        status,_=_evaluate('x'*4097,'x','markdown-literal')
        self.assertEqual(status,'UNVERIFIED')


if __name__=='__main__':
    unittest.main()
