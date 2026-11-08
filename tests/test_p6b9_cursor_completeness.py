"""P6-B9 cursor-aware catalog handling: no partial success, loops, or fabricated declarations."""
from __future__ import annotations
import json
import random
from pathlib import Path
import tempfile
import unittest

from risu_mcp_trace import verify_trace, TraceError


def tool(name):
    return {'name':name, 'inputSchema':{'type':'object'},
            'outputSchema':{'type':'object','properties':{'ok':{'type':'boolean'}},'required':['ok']}}


def page(rows, idx, entries, next_cursor=None, cursor=None, session='default'):
    params={} if cursor is None else {'cursor':cursor}
    result={'tools':entries}
    if next_cursor is not None: result['nextCursor']=next_cursor
    rows.extend([
        {'session':session,'message':{'jsonrpc':'2.0','id':idx,'method':'tools/list','params':params}},
        {'session':session,'message':{'jsonrpc':'2.0','id':idx,'result':result}},
    ])


def call(rows, idx, name, value=None, session='default'):
    if value is None:value={'ok':True}
    rows.extend([
        {'session':session,'message':{'jsonrpc':'2.0','id':idx,'method':'tools/call',
                                     'params':{'name':name,'arguments':{}}}},
        {'session':session,'message':{'jsonrpc':'2.0','id':idx,'result':{
            'isError':False,'structuredContent':value,'content':[{'type':'text','text':'ok'}]}}},
    ])


def run(rows):
    with tempfile.TemporaryDirectory() as d:
        f=Path(d)/'trace.jsonl'
        f.write_text(''.join(json.dumps(row)+'\n' for row in rows),encoding='utf-8')
        return verify_trace(f,'2025-11-25')


def codes(r):
    return {v['code'] for v in r['unverified']}


class TestP6B9CursorCompleteness(unittest.TestCase):
    def test_two_pages_reach_second_tool(self):
        rows=[]
        page(rows,1,[tool('first')],'opaque-2')
        page(rows,2,[tool('second')],cursor='opaque-2')
        call(rows,3,'second')
        r=run(rows)
        self.assertEqual(r['semantic_verification'],'CHECKED_NO_MISMATCHES')
        self.assertEqual(r['summary']['catalog_snapshots_indexed'],1)
        self.assertEqual(r['summary']['catalog_pages_recorded'],2)
        self.assertEqual(r['summary']['latest_catalog_declarations_indexed'],2)
        self.assertEqual(r['summary']['structured_values_schema_checked'],1)
        self.assertEqual(r['summary']['findings'],0)
        self.assertEqual(r['summary']['unverified_count'],0)
    def test_partial_catalog_cannot_authorize_first_page_tool(self):
        rows=[]
        page(rows,1,[tool('first')],'opaque-2')
        call(rows,2,'first')
        r=run(rows)
        self.assertIn('INCOMPLETE_CATALOG_PAGINATION',codes(r))
        self.assertIn('NO_COMPLETE_CATALOG',codes(r))
        self.assertEqual(r['summary']['structured_values_schema_checked'],0)
    def test_mismatch_cursor_is_not_silently_accepted(self):
        rows=[]
        page(rows,1,[tool('first')],'correct')
        page(rows,2,[tool('second')],cursor='wrong')
        call(rows,3,'second')
        r=run(rows)
        self.assertIn('CATALOG_CURSOR_MISMATCH',codes(r))
        self.assertEqual(r['summary']['structured_values_schema_checked'],0)
    def test_cursor_cycle_refused_and_no_success(self):
        rows=[]
        page(rows,1,[tool('first')],'a')
        page(rows,2,[tool('second')],'b',cursor='a')
        page(rows,3,[tool('third')],'a',cursor='b')
        call(rows,4,'third')
        r=run(rows)
        self.assertIn('CATALOG_CURSOR_CYCLE',codes(r))
        self.assertEqual(r['summary']['structured_values_schema_checked'],0)
    def test_duplicate_name_across_pages_refused(self):
        rows=[]
        page(rows,1,[tool('repeated')],'next')
        page(rows,2,[tool('repeated')],cursor='next')
        r=run(rows)
        self.assertIn('INVALID_CATALOG',codes(r))
        self.assertEqual(r['summary']['catalog_snapshots_indexed'],0)
    def test_orphan_cursor_never_proves_complete(self):
        rows=[]
        page(rows,1,[tool('second')],cursor='skipped-first')
        call(rows,2,'second')
        r=run(rows)
        self.assertIn('ORPHAN_CATALOG_CURSOR',codes(r))
        self.assertEqual(r['summary']['structured_values_schema_checked'],0)
    def test_last_page_has_empty_tools_but_is_complete(self):
        rows=[]
        page(rows,1,[tool('first')],'cursor')
        page(rows,2,[],cursor='cursor')
        call(rows,3,'first')
        r=run(rows)
        self.assertEqual(r['summary']['structured_values_schema_checked'],1)
    def test_changed_catalog_resets_old_chain(self):
        rows=[]
        page(rows,1,[tool('old')],'cursor')
        rows.append({'jsonrpc':'2.0','method':'notifications/tools/list_changed'})
        page(rows,2,[tool('new')])
        call(rows,3,'new')
        r=run(rows)
        self.assertEqual(r['summary']['structured_values_schema_checked'],1)
        self.assertIn('CATALOG_INVALIDATED',codes(r))
    def test_invalid_long_cursor_is_rejected_no_secret_echo(self):
        secret='DO_NOT_ECHO_'+'T'*300
        rows=[]
        page(rows,1,[tool('first')],secret)
        r=run(rows)
        self.assertIn('INVALID_TOOLS_LIST',codes(r))
        self.assertNotIn(secret,json.dumps(r))
    def test_more_than_100_pages_refused(self):
        rows=[]
        for i in range(101):
            page(rows,i+1,[tool('t'+str(i))],
                 'c'+str(i+1) if i<100 else None,
                 'c'+str(i) if i else None)
        r=run(rows)
        self.assertEqual(r['summary']['catalog_snapshots_indexed'],0)
        self.assertIn('CATALOG_COMPLEXITY_LIMIT',codes(r))
    def test_100_pages_terminal_valid(self):
        rows=[]
        for i in range(100):
            page(rows,i+1,[tool('t'+str(i))],
                 'c'+str(i+1) if i<99 else None,
                 'c'+str(i) if i else None)
        call(rows,101,'t99')
        r=run(rows)
        self.assertEqual(r['summary']['latest_catalog_declarations_indexed'],100)
        self.assertEqual(r['summary']['structured_values_schema_checked'],1)
        self.assertEqual(r['summary']['unverified_count'],0)
    def test_two_sessions_cursor_isolation(self):
        rows=[]
        page(rows,1,[tool('a')],'a2',session='a')
        page(rows,1,[tool('b')],session='b')
        call(rows,2,'b',session='b')
        page(rows,2,[tool('a2')],cursor='a2',session='a')
        call(rows,3,'a2',session='a')
        r=run(rows)
        self.assertEqual(r['summary']['sessions'],2)
        self.assertEqual(r['summary']['structured_values_schema_checked'],2)
        self.assertEqual(r['summary']['catalog_snapshots_indexed'],2)
    def test_100_seeded_page_partitions_match_one_page(self):
        rng=random.Random(20261108)
        for _ in range(100):
            n=rng.randint(2,36)
            parts=[]
            while n:
                k=rng.randint(1,min(n,8));parts.append(k);n-=k
            rows=[];num=0
            for i,size in enumerate(parts):
                data=[tool('t'+str(z)) for z in range(num,num+size)]
                num+=size
                page(rows,i+1,data,('cursor'+str(i+1)) if i+1<len(parts) else None,
                     ('cursor'+str(i)) if i else None)
            call(rows,len(parts)+1,'t'+str(num-1),{'ok':False})
            r=run(rows)
            self.assertEqual(r['summary']['structured_values_schema_checked'],1)
            self.assertEqual(r['summary']['latest_catalog_declarations_indexed'],num)
            self.assertEqual(r['summary']['findings'],0)
            self.assertEqual(r['summary']['unverified_count'],0)


if __name__=='__main__':
    unittest.main()
