from __future__ import annotations
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
from risu_nested_schema import compare,SchemaLens
from risu_compat import analyze,load_output_schema,cli

class TestAdversarialBackwardCompatibility(unittest.TestCase):
    def test_closed_old_rejects_new_optional_field(self):
        old={'type':'object','properties':{'ok':{'type':'boolean'}},'required':['ok'],'additionalProperties':False}
        new=copy.deepcopy(old);new['properties']['extra']={'type':'string'}
        r=compare(old,new)
        self.assertEqual(r['summary']['unconditionally_required_new_fields'],0)
        self.assertEqual(r['events'][0]['kind'],'FIELD_ADDED')
        self.assertEqual(r['consumer_output_compatibility']['status'],'POTENTIAL_VALIDATOR_BREAK')
        self.assertEqual(r['consumer_output_compatibility']['witnesses'][0]['closed_old_parent'],'/')
        self.assertFalse(r['consumer_output_compatibility']['guaranteed_safe'])
    def test_open_object_has_no_witness_but_not_proven_safe(self):
        old={'type':'object','properties':{'ok':{'type':'boolean'}}}
        new=copy.deepcopy(old);new['properties']['extra']={'type':'string'}
        r=compare(old,new)
        self.assertEqual(r['summary']['unconditionally_required_new_fields'],0)
        self.assertEqual(r['consumer_output_compatibility']['status'],'NOT_PROVEN_COMPATIBLE')
    def test_existing_nested_closed_object(self):
        old={'type':'object','properties':{'outer':{'type':'object','properties':{'a':{'type':'integer'}},'additionalProperties':False}},'required':['outer']}
        new=copy.deepcopy(old);new['properties']['outer']['properties']['b']={'type':'string'}
        r=compare(old,new)
        self.assertEqual(r['consumer_output_compatibility']['witnesses'][0]['closed_old_parent'],'/outer')
    def test_closed_array_item(self):
        old={'type':'array','items':{'type':'object','properties':{'id':{'type':'string'}},'additionalProperties':False}}
        new=copy.deepcopy(old);new['items']['properties']['new']={'type':'string'}
        r=compare(old,new)
        self.assertEqual(r['consumer_output_compatibility']['witnesses'][0]['closed_old_parent'],'/@items')
    def test_closed_old_branch_with_anyof(self):
        old={'type':'object','properties':{'item':{'anyOf':[{'type':'null'},{'type':'object','properties':{'a':{'type':'string'}},'additionalProperties':False}]}}}
        new=copy.deepcopy(old);new['properties']['item']['anyOf'][1]['properties']['extra']={'type':'string'}
        r=compare(old,new)
        self.assertEqual(r['consumer_output_compatibility']['status'],'POTENTIAL_VALIDATOR_BREAK')
    def test_optionalize_required_field_is_risk(self):
        old={'type':'object','properties':{'x':{'type':'string'}},'required':['x']}
        new=copy.deepcopy(old);new['required']=[]
        r=compare(old,new)
        self.assertEqual(r['consumer_output_compatibility']['status'],'POTENTIAL_VALIDATOR_BREAK')
    def test_root_type_change(self):
        old={'type':'array','items':{'type':'string'}}
        new={'type':'object','properties':{'x':{'type':'string'}}}
        r=compare(old,new)
        self.assertEqual(r['consumer_output_compatibility']['status'],'POTENTIAL_VALIDATOR_BREAK')
    def test_same_schema_no_false_guarantee(self):
        same={'type':'object','properties':{'x':{'type':'string'}}}
        r=compare(same,same)
        self.assertEqual(r['consumer_output_compatibility']['status'],'NOT_PROVEN_COMPATIBLE')
        self.assertEqual(r['summary']['independent_events'],0)
    def test_invalid_type_fails_closed(self):
        with self.assertRaisesRegex(ValueError,'Invalid JSON Schema type'):
            SchemaLens({'type':'object','properties':{'x':{'type':'nonsense'}}}).scan()
    def test_unsupported_schema_fails_closed(self):
        with self.assertRaisesRegex(ValueError,'Unsupported'):
            compare({'type':'object','allOf':[{'type':'object'}]},{'type':'object'})
    def test_cyclic_ref_fails_closed(self):
        with self.assertRaisesRegex(ValueError,'Cyclic'):
            SchemaLens({'$defs':{'x':{'$ref':'#/$defs/x'}},'properties':{'a':{'$ref':'#/$defs/x'}}}).scan()

class TestEvidenceAndCLI(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.dir=Path(self.temp.name)
        self.old=self.dir/'old.json';self.new=self.dir/'new.json'
        old={'type':'object','properties':{'x':{'type':'string'}},'additionalProperties':False}
        new=copy.deepcopy(old);new['properties']['y']={'type':'string'}
        self.old.write_text(json.dumps(old));self.new.write_text(json.dumps(new))
    def test_schema_files_detect(self):
        result=analyze(str(self.old),str(self.new))
        self.assertEqual(result['consumer_output_compatibility']['status'],'POTENTIAL_VALIDATOR_BREAK')
        self.assertEqual(result['source_evidence']['old_kind'],'independent-schema')
    def test_cli_zero_one_two_exit_codes(self):
        self.assertEqual(cli(['--old',str(self.old),'--new',str(self.new),'--out',str(self.dir/'r.json'),'--fail-on-possible-break']),1)
        self.assertEqual(cli(['--old',str(self.old),'--new',str(self.new),'--out',str(self.dir/'r.json')]),2)
        self.assertEqual(cli(['--old',str(self.old),'--new',str(self.old),'--fail-on-possible-break']),0)
    def test_snapshot_hash_tamper_rejected(self):
        from risu_contract_history import create_snapshot
        old={'type':'object','properties':{'x':{'type':'string'}}}
        self.old.write_text(json.dumps(old))
        snap=create_snapshot(str(self.old),None,'1',None)
        orig=self.dir/'snapshot.json';orig.write_text(json.dumps(snap))
        result,prov=load_output_schema(str(orig),None)
        self.assertEqual(prov,'verified-P4T-snapshot')
        snap['schema']['properties']['x']['type']='integer';orig.write_text(json.dumps(snap))
        with self.assertRaisesRegex(ValueError,'hash mismatch'):
            load_output_schema(str(orig),None)
    def test_multi_tool_requires_name(self):
        record={'jsonrpc':'2.0','id':2,'result':{'tools':[{'name':'one','outputSchema':{'type':'object'}},{'name':'two','outputSchema':{'type':'array'}}]}}
        self.old.write_text(json.dumps(record))
        with self.assertRaisesRegex(ValueError,'--tool'):
            load_output_schema(str(self.old),None)
        result,source=load_output_schema(str(self.old),'two')
        self.assertEqual(result['type'],'array');self.assertEqual(source,'recorded-tools-list')
    def test_old_arrays_accepted_by_new_comparator(self):
        self.old.write_text('{"type":"array","items":{"type":"string"}}')
        self.new.write_text('{"type":"array","items":{"type":"number"}}')
        r=analyze(str(self.old),str(self.new))
        self.assertEqual(r['events'][0]['kind'],'TYPE_SET_CHANGED')
    def test_wire_wrapped_tools_list(self):
        record={'jsonrpc':'2.0','id':2,'result':{'tools':[{'name':'a','outputSchema':{'type':'object'}}]}}
        self.old.write_text(json.dumps({'direction':'server_to_client','wire_utf8':json.dumps(record)}))
        self.assertEqual(load_output_schema(str(self.old),'a')[1],'recorded-tools-list')

if __name__=='__main__':unittest.main()
