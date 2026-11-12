"""B17 offline-origin pinning adversarial tests; only disposable synthetic git repo."""
from __future__ import annotations
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from risu_mcp_origin import (
    OriginError, validate_manifest, pinned_sources, static_tool_declaration,
    verify, SCHEMA
)

ORIGINAL = """import mcp.types as types
def list_tools():
    return [
        types.Tool(
            name="report",
            inputSchema={"type": "object"},
            outputSchema={"type":"object",
              "properties":{"ok":{"type":"boolean"},"count":{"type":"integer"}},
              "required":["ok","count"]},
        )
    ]
"""


def wire(name='report', output=None, schema=None, changed=False):
    if output is None:output={'ok':True,'count':3}
    if schema is None:schema={'type':'object','properties':{
        'ok':{'type':'boolean'},'count':{'type':'integer'}},
        'required':['ok','count']}
    tool={'name':name,'inputSchema':{'type':'object'},'outputSchema':schema}
    q=[
      {'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-11-25'}},
      {'jsonrpc':'2.0','id':1,'result':{'protocolVersion':'2025-11-25','capabilities':{'tools':{}}}},
      {'jsonrpc':'2.0','id':2,'method':'tools/list','params':{}},
      {'jsonrpc':'2.0','id':2,'result':{'tools':[tool]}},
    ]
    if changed:q.append({'jsonrpc':'2.0','method':'notifications/tools/list_changed'})
    q.extend([
      {'jsonrpc':'2.0','id':20,'method':'tools/call','params':{'name':name,'arguments':{}}},
      {'jsonrpc':'2.0','id':20,'result':{'content':[{'type':'text','text':'summary'}],
                                    'structuredContent':output,'isError':False}},
    ])
    return (''.join(json.dumps(x,ensure_ascii=False,separators=(',',':'))+'\n' for x in q)).encode()


def contract(tool='report'):
    return {'schema':'risu-mcp-observation-contract-v1','rules':[{
        'id':'result','tool':tool,'kind':'json-object','when':{},
        'carrier':'structured-content','required':{'/ok':'boolean','/count':'integer'}}]}


class B17OriginTest(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root=Path(tmp.name)
        self.repo=root/'source'
        self.repo.mkdir()
        self.trace=root/'capture.jsonl'
        (self.repo/'server.py').write_text(ORIGINAL,encoding='utf-8')
        def git(*args):
            r=subprocess.run(['git','-C',str(self.repo),*args],check=True,
                             stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            return r.stdout.decode().strip()
        git('init','-q')
        git('add','server.py')
        git('-c','user.name=RISU Synthetic','-c','user.email=test@invalid.example',
            'commit','-qm','synthetic author independent')
        self.rev=git('rev-parse','HEAD')
        self.blob=git('rev-parse','HEAD:server.py')
        self.manifest={'schema':SCHEMA,'repository':'synthetic/test-only',
            'revision':self.rev,
            'sources':[{'tool':'report','path':'server.py','git_blob_sha1':self.blob}]}
        self.trace.write_bytes(wire())

    def test_source_and_same_session_catalog_match(self):
        res=verify(self.trace,contract(),self.manifest,self.repo)
        self.assertEqual(res['summary']['SOURCE_CORROBORATED_PASS'],1)
        self.assertEqual(res['sources_verified_against_local_git_objects'],1)
        self.assertEqual(res['checks'][0]['source_level'],'SOURCE_DECLARATION_CORROBORATED')

    def test_real_structured_type_mismatch_source_corroborated(self):
        self.trace.write_bytes(wire(output={'ok':'yes','count':3}))
        res=verify(self.trace,contract(),self.manifest,self.repo)
        self.assertEqual(res['summary']['SOURCE_CORROBORATED_MISMATCH'],1)

    def test_source_inband_conflict_quarantined(self):
        schema={'type':'object','properties':{
            'ok':{'type':'boolean'},'count':{'type':'integer'},'unexpected':{'type':'string'}},
            'required':['ok','count']}
        self.trace.write_bytes(wire(schema=schema,output={'ok':'bad','count':3}))
        res=verify(self.trace,contract(),self.manifest,self.repo)
        self.assertEqual(res['summary']['QUARANTINED_SOURCE_CONFLICT'],1)
        self.assertEqual(res['checks'][0]['source_reason'],
                         'PINNED_SOURCE_SCHEMA_DISAGREES_WITH_CATALOG')

    def test_stale_catalog_cannot_be_promoted_by_git_source(self):
        self.trace.write_bytes(wire(changed=True,output={'ok':'bad','count':3}))
        res=verify(self.trace,contract(),self.manifest,self.repo)
        self.assertEqual(res['summary']['NOT_PROMOTED'],1)
        self.assertEqual(res['summary']['SOURCE_CORROBORATED_MISMATCH'],0)

    def test_wrong_git_revision_fails_closed(self):
        self.manifest['revision']='f'*40
        with self.assertRaises(OriginError):
            verify(self.trace,contract(),self.manifest,self.repo)

    def test_wrong_git_blob_pin_fails_closed(self):
        self.manifest['sources'][0]['git_blob_sha1']='a'*40
        with self.assertRaises(OriginError):
            verify(self.trace,contract(),self.manifest,self.repo)

    def test_modified_worktree_rejected_even_if_committed_object_exists(self):
        (self.repo/'server.py').write_text(ORIGINAL+'\n# malicious edit\n')
        with self.assertRaises(OriginError):
            verify(self.trace,contract(),self.manifest,self.repo)

    def test_path_escape_and_tool_duplicates_rejected(self):
        self.manifest['sources'][0]['path']='../secret.txt'
        with self.assertRaises(OriginError):
            validate_manifest(self.manifest)
        self.manifest['sources'][0]['path']='server.py'
        self.manifest['sources'].append(self.manifest['sources'][0].copy())
        with self.assertRaises(OriginError):
            validate_manifest(self.manifest)

    def test_symlink_source_rejected(self):
        original=self.repo/'server.py'
        twin=self.repo/'twin.py'
        twin.write_bytes(original.read_bytes())
        original.unlink()
        try:original.symlink_to(twin)
        except (NotImplementedError,OSError):self.skipTest('Symlink privileges unavailable')
        with self.assertRaises(OriginError):
            verify(self.trace,contract(),self.manifest,self.repo)

    def test_dynamic_output_source_never_qualified(self):
        s=b'''import mcp.types as types
SCHEMA = {"type":"object"}
def tools():
    return [types.Tool(name="report",outputSchema=SCHEMA)]
'''
        extracted,why=static_tool_declaration(s,'report')
        self.assertIsNone(extracted)
        self.assertEqual(why,'DYNAMIC_SCHEMA_SOURCE_NOT_ATTESTABLE')

    def test_schema_missing_is_not_authority(self):
        s=b'import mcp.types as types\ntypes.Tool(name="report",inputSchema={"type":"object"})'
        v,why=static_tool_declaration(s,'report')
        self.assertIsNone(v)
        self.assertEqual(why,'SOURCE_TOOL_HAS_NO_EXPLICIT_OUTPUT_SCHEMA')

    def test_other_tool_source_not_mistaken_for_target(self):
        val,why=static_tool_declaration(ORIGINAL.encode(),'unlisted')
        self.assertIsNone(val)
        self.assertEqual(why,'SOURCE_TOOL_LITERAL_NOT_PRESENT')

if __name__=='__main__':
    unittest.main()
