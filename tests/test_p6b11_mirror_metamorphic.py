"""B11 synthetic source-to-text mirror metamorphic stress (never external holdout).

A fixed 2026-11-08 seed; 600 healthy mirror/summaries and 600 deliberate
single-value mutations, with all JSON source objects within bounded limits.
"""
from __future__ import annotations
import json
import random
import unittest
from risu_display_fidelity import check

R={
 "id":"synthetic_json_mirror","tool":"synthetic",
 "source":"","content_index":None,"prefix_raw":"",
 "mode":"json-text-mirror","on_error":False,
}
SEED=20261108

def sample(data,blocks):
    return {"isError":False,"structuredContent":data,
            "content":[{"type":"text","text":s} for s in blocks]}

class TestB11MirrorMetamorphic(unittest.TestCase):
    def test_600_healthy_mirrors_and_600_minimal_mutations(self):
        rng=random.Random(SEED)
        for i in range(600):
            raw={
                "topic":"topic_"+str(i),
                "items":[{"id":j,"label":"x_*(A)[B]\\号_"+str(j)}
                         for j in range(rng.randint(0,8))],
                "meta":{"flag":bool(i%2),"number":i,"zero":0,
                        "optional":None,"token":"name_😊_"+str(i)}
            }
            text=json.dumps(raw,ensure_ascii=(i%2==0),
                            separators=(",",":") if i%3==0 else None,
                            sort_keys=(i%4==0))
            blocks=["Human summary: "+str(len(raw["items"]))+" entries",text]
            with self.subTest(case=i,mode="normal"):
                self.assertEqual(check(sample(raw,blocks),R)[0],"PASS")
            changed=json.loads(json.dumps(raw))
            changed["meta"]["number"]+=1
            with self.subTest(case=i,mode="mutated"):
                self.assertEqual(check(sample(changed,blocks),R)[0],"MISMATCH")
    def test_unrelated_summary_remains_unverified_without_declaration(self):
        obj={"count":5,"entries":["alpha"]}
        self.assertEqual(check(sample(obj,["5 entries only"]),R)[0],"MISMATCH")
    def test_mirror_after_an_unrelated_summary(self):
        obj={"count":5,"entries":["alpha"]}
        self.assertEqual(check(sample(obj,["5 entries only",json.dumps(obj)]),R)[0],"PASS")
    def test_big_mirror_fails_closed_not_content_loss(self):
        obj={"content":"A"*5000}
        self.assertEqual(check(sample(obj,[json.dumps(obj)]),R)[0],"UNVERIFIED")
    def test_multiple_different_json_texts_with_one_exact_mirror(self):
        obj={"count":5,"entries":["alpha"]}
        self.assertEqual(check(sample(obj,['{"count":9}',json.dumps(obj)]),R)[0],"PASS")
    def test_json_string_does_not_coerce_to_integer(self):
        self.assertEqual(check(sample({"n":12},['{"n":"12"}']),R)[0],"MISMATCH")
    def test_null_and_absent_are_distinct(self):
        self.assertEqual(check(sample({"n":None},['{}']),R)[0],"MISMATCH")

if __name__=="__main__":unittest.main()
