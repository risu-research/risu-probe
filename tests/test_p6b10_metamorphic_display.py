"""B10 deterministic metamorphic healthy rendering and mutation controls.

Synthetic, not a new independent sample: 600 pairs exercising the explicit
CommonMark and literal-copy relation under a fixed random seed.
"""
from __future__ import annotations
import random
import unittest
from risu_display_fidelity import check

ALPHABET='abcdEFG0123_-*[]()!~+.:'
SEED=20261108

def pair(value,display,mode):
    return {'structuredContent':{'value':value},
            'content':[{'type':'text','text':'Marker: '+display}]},{
            'id':'metamorphic_1','tool':'synthetic',
            'source':'/value','content_index':0,'prefix_raw':'Marker: ',
            'mode':mode,'on_error':False}

def code_literal(value):
    runs=[len(m) for m in __import__('re').findall(r'`+',value)]
    delimiter='`'*max([1]+[n+1 for n in runs])
    return delimiter+value+delimiter

class TestB10MetamorphicDisplay(unittest.TestCase):
    def test_600_copy_controls_and_escapes_without_false_alert(self):
        rng=random.Random(SEED)
        for i in range(600):
            s='X'+''.join(rng.choice(ALPHABET) for _ in range(rng.randint(1,60)))+'Y'
            # Markdown literal in a code span is always independent of the
            # punctuation's syntactic role in surrounding Markdown.
            result,rule=pair(s,code_literal(s),'raw-copy')
            with self.subTest(index=i):
                self.assertEqual(check(result,rule)[0],'PASS')
                # A loss introduced by the adapter is an actual scalar change,
                # regardless of whether a Markdown renderer could hide it.
                broken,br=pair(s+'z',code_literal(s),'raw-copy')
                self.assertEqual(check(broken,br)[0],'MISMATCH')
    def test_400_emphasis_mutations_and_correct_escapes(self):
        rng=random.Random(SEED+1)
        for i in range(400):
            left=''.join(rng.choice('abcdef123') for _ in range(4))
            mid=''.join(rng.choice('qwerty456') for _ in range(3))
            right=''.join(rng.choice('abcdef789') for _ in range(4))
            source=left+'*'+mid+'*'+right
            broken,r=pair(source,left+'*'+mid+'*'+right,'markdown-rendered')
            repaired,rr=pair(source,left+'\\*'+mid+'\\*'+right,'markdown-rendered')
            with self.subTest(index=i):
                self.assertEqual(check(broken,r)[0],'MISMATCH')
                self.assertEqual(check(repaired,rr)[0],'PASS')
    def test_preformatted_html_stays_unverified(self):
        result,rule=pair('raw','<b>raw</b>','markdown-rendered')
        self.assertEqual(check(result,rule)[0],'UNVERIFIED')
    def test_markdown_links_stay_unverified(self):
        result,rule=pair('link','[link](dest)','markdown-rendered')
        self.assertEqual(check(result,rule)[0],'UNVERIFIED')

if __name__=='__main__':
    unittest.main()
