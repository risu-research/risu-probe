"""Cross-implementation protocol negotiation and redaction safety contract."""
from __future__ import annotations
import json, tempfile, unittest
from pathlib import Path
from risu_mcp_trace import verify_trace

def trace(protocol='2025-06-18', schema=None, value=None):
    if schema is None:
        schema={'type':'object','properties':{'x':{'type':'integer'}},'required':['x']}
    if value is None:value={'x':8}
    return [
        {'jsonrpc':'2.0','id':100,'method':'initialize','params':{'protocolVersion':'2025-11-25'}},
        {'jsonrpc':'2.0','id':100,'result':{'protocolVersion':protocol}},
        {'jsonrpc':'2.0','method':'notifications/initialized'},
        {'jsonrpc':'2.0','id':1,'method':'tools/list','params':{}},
        {'jsonrpc':'2.0','id':1,'result':{'tools':[{'name':'secretTool','outputSchema':schema}]}},
        {'jsonrpc':'2.0','id':2,'method':'tools/call','params':{'name':'secretTool','arguments':{}}},
        {'jsonrpc':'2.0','id':2,'result':{'content':[{'type':'text','text':'ok'}], 'structuredContent':value}},
    ]

def analyze(rows,version='unknown'):
    with tempfile.TemporaryDirectory() as t:
        p=Path(t)/'trace.jsonl'
        p.write_text(''.join(json.dumps(x)+'\n' for x in rows))
        return verify_trace(p,version)

class TestP6B5(unittest.TestCase):
    def test_infer_actual_2025_06_18_protocol(self):
        r=analyze(trace())
        self.assertEqual(r['session_protocols'][0]['effective_protocol'],'2025-06-18')
        self.assertEqual(r['session_protocols'][0]['evidence'],'CAPTURED_INITIALIZE_RESULT')
        self.assertEqual(r['summary']['structured_values_schema_checked'],1)
        self.assertEqual(r['summary']['findings'],0)

    def test_declared_conflicts_negotiated_version(self):
        nonobject={'$defs':{'N':{'type':'object'}},'$ref':'#/$defs/N'}
        r=analyze(trace('2026-07-28',nonobject,{'x':1}),'2025-11-25')
        self.assertIn('PROTOCOL_VERSION_CONFLICT',{x['code'] for x in r['unverified']})
        self.assertEqual(r['session_protocols'][0]['effective_protocol'],'unknown')
        self.assertNotIn('RMC504',{x['rule_id'] for x in r['findings']})

    def test_legacy_schema_root_violation_auto_detects(self):
        nonobject={'$defs':{'N':{'type':'object'}},'$ref':'#/$defs/N'}
        r=analyze(trace('2025-06-18',nonobject,{'x':1}))
        self.assertIn('RMC504',{x['rule_id'] for x in r['findings']})

    def test_2026_modern_root_ref_allowed(self):
        nonobject={'$defs':{'N':{'type':'object'}},'$ref':'#/$defs/N'}
        r=analyze(trace('2026-07-28',nonobject,{}))
        self.assertNotIn('RMC504',{x['rule_id'] for x in r['findings']})
        self.assertEqual(r['summary']['structured_values_schema_checked'],1)

    def test_actual_tool_name_never_echoed(self):
        rows=trace()
        rows[4]['result']['tools'][0]['name']='SUPER_SECRET_321'
        rows[5]['params']['name']='SUPER_SECRET_321'
        rows[6]['result'].pop('structuredContent')
        r=analyze(rows)
        self.assertEqual({x['rule_id'] for x in r['findings']},{'RMC501'})
        self.assertNotIn('SUPER_SECRET_321',json.dumps(r))
        self.assertIn('tool_sha256',r['findings'][0]['tool'])

    def test_output_key_never_echoed(self):
        secret='SSN_PRIVATE_KEY_BEARER_abcdef'
        schema={'type':'object','properties':{secret:{'type':'integer'}},'required':[secret]}
        r=analyze(trace(schema=schema,value={secret:'oops'}))
        self.assertIn('RMC502',{x['rule_id'] for x in r['findings']})
        self.assertNotIn(secret,json.dumps(r))

    def test_missing_initialize_no_protocol_claim(self):
        r=analyze(trace()[2:])
        self.assertEqual(r['session_protocols'][0]['effective_protocol'],'unknown')
        self.assertEqual(r['session_protocols'][0]['evidence'],'NOT_OBSERVED')

    def test_unrecognized_protocol_unverified(self):
        r=analyze(trace('2022-01-01'))
        self.assertEqual(r['session_protocols'][0]['effective_protocol'],'unknown')
        self.assertIn('UNSUPPORTED_NEGOTIATED_PROTOCOL',{x['code'] for x in r['unverified']})

    def test_2025_03_26_supported(self):
        r=analyze(trace('2025-03-26'))
        self.assertEqual(r['session_protocols'][0]['effective_protocol'],'2025-03-26')
        self.assertEqual(r['summary']['findings'],0)

if __name__=='__main__':unittest.main()
