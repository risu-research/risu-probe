"""P6-B16 source-catalog authority and conservative quarantine regression suite."""
from __future__ import annotations
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from risu_mcp_authority import correlate,verify,assess_authority
from risu_mcp_observations import ObservationError

def line(msg):
    return json.dumps(msg,ensure_ascii=False,separators=(',',':'))+'\n'
def request(id,method,params=None,session=None):
    msg={'jsonrpc':'2.0','id':id,'method':method,'params':params or {}}
    return {'session':session,'message':msg} if session else msg
def reply(id,result,session=None):
    msg={'jsonrpc':'2.0','id':id,'result':result}
    return {'session':session,'message':msg} if session else msg
def desc(name='audit',annotations=None,output=None):
    obj={'name':name,'description':'Read-only by default, this text is not machine evidence',
         'inputSchema':{'type':'object','properties':{}}}
    if annotations is not None:obj['annotations']=annotations
    if output is not None:obj['outputSchema']=output
    return obj
def output_schema():
    return {'type':'object','properties':{
        'row_count':{'type':'integer'},'null_counts':{'type':'object'}},
        'required':['row_count','null_counts']}
def contract(rule=None):
    if rule is None:rule={'id':'json','tool':'audit','kind':'json-object','when':{},
                          'carrier':'structured-content',
                          'required':{'/row_count':'integer','/null_counts':'object'}}
    return {'schema':'risu-mcp-observation-contract-v1','rules':[rule]}
def state_rule(kind='state-unchanged',tool='audit',where=None):
    return {'id':'state','tool':tool,'kind':kind,'when':where or {}}
def result(valid=True):
    return {'content':[{'type':'text','text':'Error is just a legitimate column label'}],
            'isError':False,
            'structuredContent':{'row_count':2,'null_counts':{}} if valid else {'row_count':'two'}}
def observed_path(root,wire):
    p=root/'original.jsonl'
    p.write_text(''.join(line(x) for x in wire),encoding='utf-8')
    return p

class B16CatalogTest(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)

    def capture(self,descriptor=None,output=None,more=None,change=False,session=None):
        descriptor=descriptor if descriptor is not None else desc(output=output_schema())
        wire=[request(1,'initialize',{'protocolVersion':'2025-11-25'},session),
              reply(1,{'protocolVersion':'2025-11-25','capabilities':{'tools':{}}},session),
              request(2,'tools/list',{},session),
              reply(2,{'tools':[descriptor]},session)]
        if change:wire.append({'jsonrpc':'2.0','method':'notifications/tools/list_changed'})
        wire.extend([request(20,'tools/call',{'name':'audit','arguments':{}},session),
                     reply(20,output if output is not None else result(),session)])
        if more:wire+=more
        return observed_path(self.root,wire)

    def witness(self,p,before='0'*64,after='1'*64,start=5,end=6,session='default'):
        return {'schema':'risu-mcp-state-witness-v1',
                'trace_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),
                'records':[{'session':session,'request_line':start,'response_line':end,
                            'tool':'audit','before_sha256':before,'after_sha256':after}]}

    def test_declared_structured_output_true_mismatch_is_qualified(self):
        p=self.capture(output=result(valid=False))
        r=verify(p,contract())
        self.assertEqual(r['summary']['qualified_mismatches'],1)
        self.assertEqual(r['summary']['quarantined_mismatches'],0)
        self.assertEqual(r['checks'][0]['authority_grade'],'CATALOG_NORMATIVE')
        self.assertIsNotNone(r['checks'][0]['tool_descriptor_sha256'])

    def test_declared_structured_output_passes(self):
        p=self.capture()
        r=verify(p,contract())
        self.assertEqual((r['summary']['qualified_passes'],r['summary']['qualified_mismatches']),(1,0))

    def test_human_readable_description_never_promotes(self):
        p=self.capture(descriptor=desc(output=None),output=result(valid=False))
        r=verify(p,contract())
        self.assertEqual(r['summary']['qualified_mismatches'],0)
        self.assertEqual(r['summary']['quarantined_mismatches'],1)
        self.assertEqual(r['checks'][0]['authority_reason'],'NO_DECLARED_OUTPUT_SCHEMA')

    def test_text_json_rule_not_mistaken_for_structured_output_schema(self):
        p=self.capture(output={'content':[{'type':'text','text':'error!'}],'isError':False})
        rule=contract()['rules'][0].copy()
        rule['carrier']='single-text-json'
        r=verify(p,contract(rule))
        self.assertEqual((r['summary']['qualified_mismatches'],
                          r['summary']['quarantined_mismatches']),(0,1))

    def test_advisory_readonly_hint_cannot_qualify_state(self):
        p=self.capture(descriptor=desc(annotations={'readOnlyHint':True}),
                       output={'content':[],'isError':False})
        r=verify(p,contract(state_rule()),self.witness(p))
        self.assertEqual(r['summary']['quarantined_mismatches'],1)
        self.assertEqual(r['checks'][0]['authority_grade'],'CATALOG_ADVISORY')

    def test_contradictory_change_hint_blocks_writable_assumption(self):
        p=self.capture(descriptor=desc(annotations={'readOnlyHint':True}),
                       output={'content':[],'isError':False})
        r=verify(p,contract(state_rule(kind='state-changed')),
                 self.witness(p,before='0'*64,after='0'*64))
        self.assertEqual(r['summary']['qualified_mismatches'],0)
        self.assertEqual(r['checks'][0]['authority_grade'],'CONFLICT')

    def test_b15_pa_wrong_contract_quarantined_without_hint(self):
        p=self.capture(descriptor=desc(),output={'content':[],'isError':True})
        r=verify(p,contract(state_rule(kind='state-changed')),
                 self.witness(p,before='0'*64,after='0'*64))
        self.assertEqual(r['summary']['quarantined_mismatches'],1)
        self.assertEqual(r['summary']['qualified_mismatches'],0)

    def test_no_tools_list_blocks_even_valid_json_schema_claim(self):
        p=observed_path(self.root,[request(20,'tools/call',{'name':'audit','arguments':{}}),
                                  reply(20,result(valid=False))])
        r=verify(p,contract())
        self.assertEqual((r['summary']['qualified_mismatches'],
                          r['summary']['quarantined_mismatches']),(0,1))
        self.assertEqual(r['checks'][0]['authority_reason'],'NO_COMPLETE_CATALOG')

    def test_change_notification_invalidates_stale_snapshot(self):
        p=self.capture(change=True,output=result(valid=False))
        r=verify(p,contract())
        self.assertEqual(r['summary']['qualified_mismatches'],0)
        self.assertEqual(r['summary']['quarantined_mismatches'],1)
        self.assertEqual(r['checks'][0]['authority_reason'],'CATALOG_CHANGED_NOTIFICATION')

    def test_partial_catalog_cursor_cannot_establish_authority(self):
        p=observed_path(self.root,[
            request(2,'tools/list',{}),reply(2,{'tools':[desc(output=output_schema())],'nextCursor':'opaque'}),
            request(20,'tools/call',{'name':'audit','arguments':{}}),reply(20,result(valid=False))])
        r=verify(p,contract())
        self.assertEqual(r['summary']['qualified_mismatches'],0)

    def test_finished_two_page_catalog_can_validate(self):
        p=observed_path(self.root,[
            request(2,'tools/list',{}),
            reply(2,{'tools':[desc(name='other')],'nextCursor':'opaque'}),
            request(3,'tools/list',{'cursor':'opaque'}),
            reply(3,{'tools':[desc(output=output_schema())]}),
            request(20,'tools/call',{'name':'audit','arguments':{}}),
            reply(20,result(valid=False))])
        r=verify(p,contract())
        self.assertEqual(r['summary']['qualified_mismatches'],1)
        self.assertEqual(r['checks'][0]['catalog_completed_line'],4)

    def test_duplicate_tool_names_in_pages_blocks_support(self):
        p=observed_path(self.root,[
            request(2,'tools/list',{}),
            reply(2,{'tools':[desc(output=output_schema())],'nextCursor':'opaque'}),
            request(3,'tools/list',{'cursor':'opaque'}),
            reply(3,{'tools':[desc(output=output_schema())]}),
            request(20,'tools/call',{'name':'audit','arguments':{}}),
            reply(20,result(valid=False))])
        r=verify(p,contract())
        self.assertEqual(r['summary']['qualified_mismatches'],0)
        self.assertEqual(r['checks'][0]['authority_reason'],'DUPLICATE_OR_EXCESS_TOOL_NAME')

    def test_output_schema_without_required_fields_blocks(self):
        bad={'type':'object','properties':{'row_count':{'type':'integer'}}}
        p=self.capture(descriptor=desc(output=bad),output=result(valid=False))
        r=verify(p,contract())
        self.assertEqual(r['checks'][0]['authority_reason'],'OUTPUT_PATH_NOT_MANDATORY')
        self.assertEqual(r['summary']['qualified_mismatches'],0)

    def test_dynamic_output_schema_abstains(self):
        p=self.capture(descriptor=desc(output={'$ref':'https://external/schema'}),output=result(valid=False))
        r=verify(p,contract())
        self.assertEqual(r['checks'][0]['authority_reason'],'UNSUPPORTED_COMPLEX_OUTPUT_SCHEMA')
        self.assertEqual(r['summary']['qualified_mismatches'],0)

    def test_schema_nested_paths_and_int_imply_number(self):
        sc={'type':'object','properties':{'payload':{
            'type':'object','properties':{'count':{'type':'integer'}},'required':['count']}},
            'required':['payload']}
        d=desc(output=sc)
        rule={'id':'nested','tool':'audit','kind':'json-object','when':{},
              'carrier':'structured-content','required':{'/payload/count':'number'}}
        p=self.capture(descriptor=d,output={'isError':False,
               'structuredContent':{'payload':{'count':2}}})
        r=verify(p,contract(rule))
        self.assertEqual(r['summary']['qualified_passes'],1)

    def test_per_session_catalog_isolation(self):
        p=self.capture(session='runA',output=result(valid=False))
        r=verify(p,contract())
        self.assertEqual(r['summary']['qualified_mismatches'],1)

    def test_witness_sha_tampering_is_global_error(self):
        p=self.capture()
        w=self.witness(p)
        w['trace_sha256']='1'*64
        with self.assertRaises(ObservationError):
            verify(p,contract(state_rule()),w)

    def test_original_source_with_error_flag_is_abstention_for_json(self):
        p=self.capture(output={'isError':True,
             'content':[{'type':'text','text':'no data'}]})
        r=verify(p,contract())
        self.assertEqual(r['summary']['qualified_mismatches'],0)
        self.assertEqual(r['summary']['unverified_observations'],1)

    def test_unmatched_rule_does_not_infer_tool_from_text(self):
        p=self.capture()
        r=verify(p,contract(state_rule(tool='other')))
        self.assertEqual(r['summary']['matched_obligations'],0)
        self.assertEqual(r['unverified'][0]['reason'],'UNMATCHED_DECLARED_RULE')

if __name__=='__main__':
    unittest.main()
