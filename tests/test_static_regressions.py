"""Synthetic static-analysis regressions. Input files are never imported."""
from pathlib import Path
import tempfile
import unittest
from risu_static import scan

SNIPPETS=[
 ('details_client.py', 'def make_api_request():\n    return (False, {"error":"bad","details":{"code":"X"}})\n'),
 ('client.py', 'from stuff.api.client import make_api_request\nasync def get_thing():\n    ok, response = await make_api_request()\n    if not ok:\n        return {"error": response.get("error")}\n'),
 ('bounded.py', 'def shorten_error_body(response):\n    return response.text[:100] + " ... truncated"\n'),
 ('http_error.py', 'def thing():\n    try:\n        return 3\n    except HTTPStatusError as err:\n        return {"error": str(err)}\n'),
 ('clean.py', 'def greet():\n    return "hello"\n')
]

class StaticRegression(unittest.TestCase):
 def test_detect_expected_error_patterns(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)
   for name,code in SNIPPETS: (p/name).write_text(code,encoding='utf-8')
   verdict=scan(p)
   ids={f['rule_id'] for f in verdict['findings']}
   self.assertTrue({'RPY201','RPY202','RPY203'}.issubset(ids),ids)
 def test_never_execute_target(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d);sentinel=p/'SHOULD_NOT_EXIST'
   (p/'payload.py').write_text(f"from pathlib import Path\nPath({str(sentinel)!r}).write_text('fail')\n")
   scan(p)
   self.assertFalse(sentinel.exists())
 def test_unparseable_is_not_clean_certification(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d);(p/'invalid.py').write_text('def malformed(\n')
   result=scan(p)
   self.assertTrue(result.get('unverified') or result.get('status')!='PASS',result)

if __name__=='__main__':unittest.main()
