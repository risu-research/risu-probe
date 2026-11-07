"""Portable synthetic P4-V/P5-A schema safety tests.
No raw release records: those stay in the research repository.
"""
from __future__ import annotations
import copy
import unittest
from risu_nested_schema import SchemaLens,compare

class TestFailClosed(unittest.TestCase):
    def test_unresolved_local_ref(self):
        with self.assertRaisesRegex(ValueError,'Unresolved'):
            SchemaLens({'type':'object','properties':{'x':{'$ref':'#/$defs/Unseen'}}}).scan()
    def test_remote_ref(self):
        with self.assertRaisesRegex(ValueError,'External'):
            SchemaLens({'type':'object','properties':{'x':{'$ref':'https://example.org/Schema'}}}).scan()
    def test_cyclic_ref(self):
        x={'type':'object','$defs':{'Loop':{'type':'object','properties':{'next':{'$ref':'#/$defs/Loop'}}}},'properties':{'root':{'$ref':'#/$defs/Loop'}}}
        with self.assertRaisesRegex(ValueError,'Cyclic'):
            SchemaLens(x).scan()
    def test_ambiguous_branch_objects(self):
        x={'type':'object','properties':{'x':{'anyOf':[{'type':'object','properties':{'a':{'type':'string'}}},{'type':'object','properties':{'b':{'type':'boolean'}}}]}}}
        with self.assertRaisesRegex(ValueError,'Ambiguous'):
            SchemaLens(x).scan()
    def test_duplicate_required(self):
        x={'type':'object','properties':{'a':{'type':'string'}},'required':['a','a']}
        with self.assertRaisesRegex(ValueError,'duplicate|duplicated'):
            SchemaLens(x).scan()
    def test_nonexistent_required(self):
        with self.assertRaises(ValueError):SchemaLens({'type':'object','required':['x']}).scan()
    def test_union_duplicate_type(self):
        with self.assertRaises(ValueError):SchemaLens({'properties':{'x':{'anyOf':[{'type':'null'},{'type':'null'}]}}}).scan()
    def test_ref_with_constrained_sibling(self):
        x={'$defs':{'T':{'type':'string'}},'properties':{'a':{'$ref':'#/$defs/T','minLength':2}}}
        with self.assertRaisesRegex(ValueError,'sibling'):
            SchemaLens(x).scan()
    def test_allof_review_boundary(self):
        x={'properties':{'x':{'allOf':[{'type':'string'}]}}}
        with self.assertRaisesRegex(ValueError,'Unsupported'):
            SchemaLens(x).scan()
    def test_if_then_review_boundary(self):
        x={'properties':{'x':{'if':{'type':'object'},'then':{'required':['a']}}}}
        with self.assertRaisesRegex(ValueError,'Unsupported'):
            SchemaLens(x).scan()
    def test_invalid_type_list(self):
        with self.assertRaises(ValueError):SchemaLens({'properties':{'x':{'type':['string','string']}}}).scan()
    def test_array_items_nested(self):
        x={'type':'object','properties':{'rows':{'type':'array','items':{'type':'object','properties':{'id':{'type':'string'}},'required':['id']}}},'required':['rows']}
        d=SchemaLens(x).scan()['fields']
        self.assertIn('/rows/@items/id',d)
        self.assertFalse(d['/rows/@items/id']['unconditionally_required'])
    def test_json_pointer_escaping(self):
        x={'$defs':{'A/B':{'type':'object','properties':{'a/b~c':{'type':'string'}}}},'properties':{'x':{'$ref':'#/$defs/A~1B'}}}
        self.assertIn('/x/a~1b~0c',SchemaLens(x).scan()['fields'])
    def test_too_deep_review(self):
        d={'type':'string'}
        for _ in range(40):d={'type':'object','properties':{'next':d}}
        with self.assertRaisesRegex(ValueError,'depth|complex'):
            SchemaLens(d).scan()
    def test_unsupported_prefix_schema_safely(self):
        # Old P4-T cannot see prefixItems. P4-V needs to explicitly refuse instead of treating as no change.
        x={'type':'array','prefixItems':[{'type':'string'}]}
        with self.assertRaises(ValueError):SchemaLens(x).scan()



class TestValidationConstraints(unittest.TestCase):
    def test_deeper_min_length_changed(self):
        original={'type':'object','$defs':{'X':{'type':'object','properties':{'id':{'type':'string','minLength':2}},'required':['id']}},'properties':{'payload':{'$ref':'#/$defs/X'}},'required':['payload']}
        modified=copy.deepcopy(original)
        modified['$defs']['X']['properties']['id']['minLength']=4
        result=compare(original,modified)
        self.assertEqual([(e['kind'],e['path']) for e in result['events']],[('VALIDATION_CONSTRAINT_CHANGED_REVIEW','/payload/id')])
    def test_description_title_default_are_not_mandatory_change(self):
        original={'type':'object','properties':{'x':{'type':'string','description':'old','title':'Title','default':'a'}}}
        modified=copy.deepcopy(original);modified['properties']['x'].update({'description':'new','title':'Other','default':'b'})
        self.assertEqual(compare(original,modified)['summary']['independent_events'],0)
    def test_additional_properties_boolean_changed(self):
        old={'type':'object','properties':{'x':{'type':'object','additionalProperties':False}}}
        new=copy.deepcopy(old);new['properties']['x']['additionalProperties']=True
        self.assertEqual(compare(old,new)['events'][0]['kind'],'VALIDATION_CONSTRAINT_CHANGED_REVIEW')
    def test_unsupported_arbitrary_keyword_is_review_not_silently_ignored(self):
        with self.assertRaisesRegex(ValueError,'Unknown semantic constraint'):
            SchemaLens({'type':'object','properties':{'x':{'type':'string','minGarbage':2}}}).scan()
    def test_untyped_ref_target_with_properties(self):
        x={'$defs':{'X':{'properties':{'x':{'type':'string'}}}},'properties':{'a':{'$ref':'#/$defs/X'}}}
        self.assertIn('/a/x',SchemaLens(x).scan()['fields'])
    def test_validating_sibling_ref_annotation_does_not_change_behavior(self):
        x={'$defs':{'X':{'type':'string'}},'properties':{'a':{'$ref':'#/$defs/X','description':'some'}}}
        self.assertEqual(SchemaLens(x).scan()['fields']['/a']['types'],['string'])
    def test_unknown_root_constraint_fails(self):
        with self.assertRaises(ValueError):SchemaLens({'type':'object','unevaluatedProperties':False}).scan()
