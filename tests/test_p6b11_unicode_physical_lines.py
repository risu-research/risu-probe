"""B11 Unicode separator regression, frozen B10 behavior preserved for audit."""
from __future__ import annotations
import json
from pathlib import Path
import tempfile
import unittest

from risu_display_fidelity import verify_display_fidelity as old_engine
from risu_display_fidelity_b11 import verify_display_fidelity as repaired_engine

POLICY={"schema":"risu-display-fidelity-contract-v1","rules":[{
 "id":"unicode-line","tool":"echo","pointer":"/value",
 "line_prefix":"**value:** ","mode":"json-string-special","is_error":False
}]}

def evaluate(value:str,rendered:str,engine,*,include_prefix=True):
    rows=[
      {"jsonrpc":"2.0","id":1,"method":"tools/call",
       "params":{"name":"echo","arguments":{}}},
      {"jsonrpc":"2.0","id":1,"result":{"isError":False,
       "content":[{"type":"text","text":("**value:** " if include_prefix else "")+rendered}],
       "structuredContent":{"value":value}}}
    ]
    with tempfile.TemporaryDirectory() as folder:
        file=Path(folder)/"trace.jsonl"
        file.write_text(''.join(json.dumps(row,ensure_ascii=False)+"\n" for row in rows))
        return engine(file,POLICY)

class B11PhysicalLineTests(unittest.TestCase):
    def test_unicode_separators_inside_valid_inline_code_remain_literal(self):
        for marker in ("\u0085","\u2028","\u2029"):
            with self.subTest(marker=hex(ord(marker))):
                raw="a"+marker+"b"
                text="`"+json.dumps(raw,ensure_ascii=False)+"`"
                new=evaluate(raw,text,repaired_engine)
                self.assertEqual(new["summary"]["findings"],0)
                self.assertEqual(new["summary"]["unverified"],0)
                self.assertEqual(new["summary"]["literal_checks_completed"],1)
    def test_original_b10_ls_false_positive_remains_reproducible(self):
        raw="a\u2028b"
        text="`"+json.dumps(raw,ensure_ascii=False)+"`"
        a=evaluate(raw,text,old_engine)
        b=evaluate(raw,text,repaired_engine)
        self.assertEqual(a["summary"]["findings"],1)
        self.assertEqual(b["summary"]["findings"],0)
    def test_actual_ascii_linebreak_corruption_still_detected(self):
        for raw in ("a\nb","a\r\nb","a\rb"):
            with self.subTest(raw=raw):
                observed=evaluate(raw,"a b",repaired_engine)
                self.assertEqual(observed["summary"]["findings"],1)
    def test_correct_json_encoded_linebreaks(self):
        for raw in ("a\nb","a\r\nb","\ttext", "", " padded "):
            with self.subTest(raw=raw):
                out=evaluate(raw,"`"+json.dumps(raw,ensure_ascii=False)+"`",repaired_engine)
                self.assertEqual(out["summary"]["findings"],0)
                self.assertEqual(out["summary"]["unverified"],0)
    def test_missing_literal_never_claims_pass(self):
        out=evaluate("value","unrelated code literal",repaired_engine,include_prefix=False)
        self.assertEqual(out["summary"]["literal_checks_completed"],0)
        self.assertEqual(out["summary"]["unverified"],1)

if __name__=="__main__": unittest.main()
