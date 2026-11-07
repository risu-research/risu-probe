"""P6-A smoke tests against a fresh installed candidate wheel, no user code execution."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

CLI=os.environ.get('RISU_P6A_TEST_CLI')

class Smoke(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not CLI:raise RuntimeError('RISU_P6A_TEST_CLI must refer to a freshly installed wheel CLI')
    def call(self,*args,expected=0):
        result=subprocess.run([CLI,*args],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=35)
        self.assertEqual(result.returncode,expected,(result.stdout,result.stderr));return result
    def test_version(self):
        self.assertIn('0.9.20',self.call('--version').stdout)
    def test_doctor(self):
        output=json.loads(self.call('doctor','--format','json').stdout)
        self.assertTrue(output['pypi_yaml_support_installed'])
        self.assertIn('STATIC_ONLY',output['default_scope'])
    def test_zero_config_without_execution(self):
        with tempfile.TemporaryDirectory(prefix='risu p6a üñí ') as tmp:
            path=Path(tmp);sentinel=path/'NEVER_EXECUTED.txt'
            (path/'module.py').write_text(f"from pathlib import Path\nPath({str(sentinel)!r}).write_text('bad')\ndef show_error(x):\n    return x[:100]\n",encoding='utf-8')
            out=json.loads(self.call('check',str(path),'--format','json').stdout)
            self.assertFalse(sentinel.exists(),'static scan executed scanned code')
            self.assertGreater(out['summary']['python_parsed'],0)
            self.assertEqual(out['summary']['unverified'],0)
    def test_sarif(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp,'a.py').write_text('x=1\n')
            data=json.loads(self.call('check',tmp,'--format','sarif').stdout)
            self.assertEqual(data['version'],'2.1.0')
    def test_legacy_commands(self):
        for args in [('analyze','--help'),('reproduce','--help'),('schema-compat','--help'),('contract-history','--help')]:
            with self.subTest(args=args):self.call(*args)
    def test_missing_path_error_clear(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'missing'
            err=self.call('check',str(p),expected=2).stderr
            self.assertIn('RCHK101',err)
            self.assertIn('Next:',err)

if __name__=='__main__':unittest.main()
