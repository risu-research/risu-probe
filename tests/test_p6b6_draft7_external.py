"""P6-B6 synthetic contract tests. Real external defect is separately tested in CI."""
from __future__ import annotations
import copy,json
from pathlib import Path
import tempfile,unittest
from risu_mcp_trace import verify_trace

DRAFT7='http://json-schema.org/draft-07/schema#'
ITEM={'type':'object','properties':{'name':{'type':'string'}},
      'required':['name'],'additionalProperties':False}
SCHEMA={'$schema':DRAFT7,'type':'object','properties':{
    'entities':{'type':'array','items':ITEM}},'required':['entities'],'additionalProperties':False}

def replay(schema:dict,payload:dict,is_error:bool=False)->dict:
    records=[
        {'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-11-25'}},
        {'jsonrpc':'2.0','id':1,'result':{'protocolVersion':'2025-11-25'}},
        {'jsonrpc':'2.0','id':2,'method':'tools/list','params':{}},
        {'jsonrpc':'2.0','id':2,'result':{'tools':[
            {'name':'memory_read','inputSchema':{'type':'object'},'outputSchema':schema}]}},
        {'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'memory_read','arguments':{}}},
        {'jsonrpc':'2.0','id':3,'result':{'isError':is_error,'structuredContent':payload}},
    ]
    with tempfile.TemporaryDirectory() as temp:
        path=Path(temp)/'synthetic.jsonl'
        path.write_text(''.join(json.dumps(x,separators=(',',':'))+'\n' for x in records))
        return verify_trace(path)

class Draft7Support(unittest.TestCase):
    def test_valid_draft7(self):
        r=replay(SCHEMA,{'entities':[{'name':'Alice'}]})
        self.assertEqual((r['summary']['structured_values_schema_checked'],
                          r['summary']['findings'],r['summary']['unverified_count']),(1,0,0))

    def test_discriminator_is_real_schema_mismatch(self):
        r=replay(SCHEMA,{'entities':[{'name':'Alice','type':'entity'}]})
        self.assertEqual([x['rule_id'] for x in r['findings']],['RMC502'])
        self.assertEqual(r['summary']['unverified_count'],0)
        self.assertNotIn('Alice',json.dumps(r))
        self.assertNotIn('"type": "entity"',json.dumps(r))

    def test_empty_negative_control(self):
        self.assertEqual(replay(SCHEMA,{'entities':[]})['summary']['findings'],0)

    def test_tool_error_is_not_success_data(self):
        r=replay(SCHEMA,{'entities':[{'name':'A','type':'entity'}]},is_error=True)
        self.assertEqual(r['summary']['findings'],0)
        self.assertEqual(r['unverified'][0]['code'],'EXECUTION_ERROR')

    def test_draft7_local_definitions_ref(self):
        s={'$schema':DRAFT7,'definitions':{'X':ITEM},'type':'object',
           'properties':{'entities':{'type':'array','items':{'$ref':'#/definitions/X'}}}}
        self.assertEqual(replay(s,{'entities':[{'name':'A'}]})['summary']['structured_values_schema_checked'],1)

    def test_supported_aliases(self):
        for uri in (DRAFT7,'https://json-schema.org/draft-07/schema','https://json-schema.org/draft-07/schema#'):
            with self.subTest(uri=uri):
                self.assertEqual(replay({**SCHEMA,'$schema':uri},{'entities':[]})['summary']['structured_values_schema_checked'],1)

    def test_other_dialect_stays_unverified(self):
        r=replay({**SCHEMA,'$schema':'http://json-schema.org/draft-06/schema#'},
                 {'entities':[{'name':'A','type':'entity'}]})
        self.assertEqual(r['summary']['findings'],0)
        self.assertEqual(r['unverified'][0]['code'],'UNSUPPORTED_SCHEMA')

    def test_mixed_dialect_abstention(self):
        s=copy.deepcopy(SCHEMA)
        s['properties']['entities']['items']['$schema']='https://json-schema.org/draft/2020-12/schema'
        r=replay(s,{'entities':[{'name':'A','type':'entity'}]})
        self.assertEqual(r['summary']['findings'],0)
        self.assertEqual(r['unverified'][0]['code'],'UNSUPPORTED_SCHEMA')

    def test_remote_ref_or_regex_are_not_evaluated(self):
        for s in ({'$schema':DRAFT7,'$ref':'https://private.invalid/schema'},
                  {'$schema':DRAFT7,'type':'string','pattern':'(a+)+$'}):
            with self.subTest(schema=s):
                r=replay(s,{'entities':[]})
                self.assertEqual(r['summary']['findings'],0)
                self.assertEqual(r['unverified'][0]['code'],'UNSUPPORTED_SCHEMA')

if __name__=='__main__':unittest.main()
