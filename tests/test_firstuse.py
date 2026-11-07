from __future__ import annotations
from pathlib import Path
import json,os,platform,subprocess,sys,tempfile,unittest
from unittest.mock import patch
from risu_firstuse import cli,doctor,_explain,InputIssue
from risu_quickcheck import check
from risu_static import ScanError

class FirstUse(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='RISU spaces ü 目録 ')
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
    def test_missing_path_actionable(self):
        err=_explain(ValueError('project does not exist or is symlink'))
        self.assertEqual(err.code,'RCHK101');self.assertIn('risu-probe check .',err.remedy)
    def test_scan_limit_actionable(self):
        err=_explain(ScanError('scan limit exceeded (3000 eligible files); narrow the project directory'))
        self.assertEqual(err.code,'RCHK103');self.assertIn('smaller',err.remedy)
    def test_missing_evidence_actionable(self):
        err=_explain(ValueError('explicit evidence report unavailable'))
        self.assertEqual(err.code,'RCHK104');self.assertIn('full_chain.json',err.remedy)
    def test_report_file_no_overwrite(self):
        (self.root/'ok.py').write_text('x=1\n');out=self.root/'existing.json';out.write_text('SAFE')
        self.assertEqual(cli([str(self.root),'--out',str(out)]),2)
        self.assertEqual(out.read_text(),'SAFE')
    def test_no_target_import_or_execution(self):
        (self.root/'evil.py').write_text("from pathlib import Path\nPath('DANGEROUS_CALLED').write_text('bad')\n")
        with patch('subprocess.Popen',side_effect=AssertionError('subprocess forbidden')), patch('socket.socket',side_effect=AssertionError('socket forbidden')):
            r=check(self.root)
        self.assertEqual(r['summary']['python_parsed'],1)
        self.assertFalse((self.root/'DANGEROUS_CALLED').exists())
    def test_path_spaces_and_unicode(self):
        d=self.root/'space and ü 雨';d.mkdir();(d/'file.py').write_text('def greet():\n  return "hi"\n')
        r=check(d);self.assertEqual(r['summary']['python_parsed'],1)
        self.assertEqual(cli([str(d)]),0)
    def test_doctor_exposes_platform(self):
        d=doctor();self.assertEqual(d['platform'],platform.system())
        self.assertEqual(d['default_scope'],'STATIC_ONLY_NO_PROJECT_IMPORT_OR_NETWORK')
        self.assertIn('default RISU Probe installation includes PyYAML',d['help'])
    def test_cli_is_timed_and_json_safe(self):
        (self.root/'x.py').write_text('a=1\n')
        self.assertEqual(cli([str(self.root),'--format','json','--timing','--out',str(self.root/'report.json')]),0)
        d=json.loads((self.root/'report.json').read_text())
        self.assertGreaterEqual(d['performance']['scan_wall_ms'],0)
        self.assertTrue(d['performance']['excludes_process_startup'])
    def test_unknown_project_not_safe(self):
        r=check(self.root)
        self.assertEqual(r['status'],'INCOMPLETE_EVIDENCE')
        self.assertEqual(cli([str(self.root)]),2)
    def test_legacy_config_detection_preserved(self):
        from risu_p5c_cli import _is_legacy_project
        (self.root/'risu-probe.json').write_text('{}')
        self.assertTrue(_is_legacy_project([str(self.root)]))
    def test_yaml_openapi_works_in_default_install(self):
        import importlib.util
        self.assertIsNotNone(importlib.util.find_spec('yaml'))
        text="""openapi: 3.0.3
info:
  title: Example
  version: 1
paths:
  /health:
    get:
      operationId: getHealth
      responses:
        '200':
          description: ok
"""
        (self.root/'openapi-example.yaml').write_text(text)
        r=check(self.root)
        self.assertEqual(r['summary']['openapi_parsed'],1)
        self.assertEqual(r['summary']['unverified'],0)

    def test_check_success_uses_installed_wheel(self):
        from importlib import metadata
        self.assertEqual(metadata.version('risu-probe-preview'),'0.9.24.dev0')
        (self.root/'p.py').write_text('x=1\n')
        self.assertEqual(cli([str(self.root)]),0)
    def test_sarif_supported(self):
        (self.root/'p.py').write_text('x=1\n')
        p=self.root/'output.sarif'
        self.assertEqual(cli([str(self.root),'--format','sarif','--out',str(p)]),0)
        d=json.loads(p.read_text());self.assertEqual(d['version'],'2.1.0')
    def test_explicit_bad_evidence_returns_two(self):
        (self.root/'p.py').write_text('x=1\n')
        self.assertEqual(cli([str(self.root),'--evidence','missing/full_chain.json']),2)

if __name__=='__main__':unittest.main()
