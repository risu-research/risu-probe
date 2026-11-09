"""B12 postfreeze independent-oracle parser tests, intentionally not product detector tests."""
from __future__ import annotations
import importlib.util,json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("b12_oracle",ROOT/"benchmarks/p6b12/score_blind_discovery.py")
M=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)

def call(name,texts,other=None):
    items=[{'type':'text','text':t} for t in texts]
    if other:items+=other
    return {'tool':name,'response':{'result':{'content':items}}}

def go(sum_display):
    return [
        call('echo',['Echo: RISU_B12_ECHO_lit_[x]_☯']),
        call('add',[sum_display]),
        call('get_resource_link',['Provided URI.'],[{'type':'resource_link','uri':'file:///synthetic'}]),
    ]

def sqlite(items):
    return [
      call('list_tables',['records']),
      call('read_query',[json.dumps({'label':f'row_{v}'}) for v in ('one','two')]),
      call('read_query',[json.dumps({'limit_hint':f'hint_{i:02d}'}) for i in range(1,items+1)]),
      call('describe_table',[json.dumps({'name':'limit_hint','type':'TEXT'})]),
    ]

class TestB12PostfreezeNumericAndListProjections(unittest.TestCase):
    def test_go_numeric_trailing_zeroes_normal(self):
        for value in ('3.750000','3.75','3.7500'):
            a=M.oracle('GO',go('The sum of 1.500000 and 2.250000 is '+value+'.'))
            self.assertTrue(all(v['outcome']=='PASS' for v in a),a)
    def test_go_wrong_numeric_candidate(self):
        a=M.oracle('GO',go('The sum of 1.500000 and 2.250000 is 3.76.'))
        self.assertEqual([x['oracle_id'] for x in a if x['outcome']=='MISMATCH'],['sum_decimal'])
    def test_go_non_numeric_ambiguous_refused(self):
        a=M.oracle('GO',go('The result was hidden.'))
        self.assertEqual(next(x['outcome'] for x in a if x['oracle_id']=='sum_decimal'),'MISMATCH')
    def test_fastmcp_each_json_object_text_is_distinct_returned_row(self):
        a=M.oracle('SQLITE',sqlite(8))
        self.assertEqual([x['oracle_id'] for x in a if x['outcome']=='MISMATCH'],['row_limit_identifier_substring'])
        self.assertFalse(any(x['outcome']=='UNVERIFIED' for x in a))
    def test_fastmcp_normal_two_rows_not_false_positive(self):
        a=M.oracle('SQLITE',sqlite(2))
        self.assertTrue(all(x['outcome']=='PASS' for x in a))
    def test_unsupported_mixed_text_and_json_abstains(self):
        r={'content':[{'type':'text','text':'{"id":1}'},{'type':'text','text':'Human summary'}]}
        self.assertIsNone(M.parse_rows(r))
    def test_json_container_parser_is_preserved(self):
        r={'content':[{'type':'text','text':'[{"id":1},{"id":2}]'}]}
        self.assertEqual(len(M.parse_rows(r)),2)
    def test_structured_list_is_preserved(self):
        self.assertEqual(len(M.parse_rows({'structuredContent':[{'id':1}]})),1)

if __name__=='__main__':unittest.main()
