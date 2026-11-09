"""Conservative, opt-in display/copy fidelity evidence for captured MCP tool results.

No inferred equality between arbitrary structuredContent and content[]. Requires
a caller-declared source JSON pointer and an exact text segment marker. Uses a
local CommonMark implementation, never HTML execution, live calls or remote data.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
from typing import Any

class DisplayContractError(ValueError):
    pass

MODES=frozenset(('markdown-rendered','raw-copy'))
MAX_RULES=48
MAX_TEXT=4096
MAX_CONTRACT_BYTES=32768
MISSING=object()


def validate(contract: Any) -> list[dict]:
    if type(contract) is not dict or set(contract)!={'schema','rules'} or contract['schema']!='risu-mcp-display-contract-v1':
        raise DisplayContractError('Unsupported display contract; expected schema and rules')
    rules=contract['rules']
    if type(rules) is not list or len(rules)>MAX_RULES:
        raise DisplayContractError('Display contract must have a bounded rules array')
    ids=set()
    for rule in rules:
        if type(rule) is not dict or set(rule)!={'id','tool','source','content_index','prefix_raw','mode','on_error'}:
            raise DisplayContractError('Display rule fields must be explicit and exact')
        name=rule['id']
        if type(name) is not str or not re.fullmatch(r'[A-Za-z0-9_-]{1,40}',name) or name in ids:
            raise DisplayContractError('Invalid or repeated display rule ID')
        ids.add(name)
        if type(rule['tool']) is not str or not (1<=len(rule['tool'])<=128):
            raise DisplayContractError('Invalid display rule tool')
        if type(rule['content_index']) is not int or not 0<=rule['content_index']<16:
            raise DisplayContractError('Invalid text content index')
        prefix=rule['prefix_raw']
        if type(prefix) is not str or not (1<=len(prefix)<=128) or '\n' in prefix or '\r' in prefix:
            raise DisplayContractError('Explicit single-line prefix required')
        if rule['mode'] not in MODES or type(rule['on_error']) is not bool:
            raise DisplayContractError('Invalid mode or isError match')
        ptr=rule['source']
        if type(ptr) is not str or not ptr.startswith('/') or len(ptr)>384:
            raise DisplayContractError('Source must be absolute structuredContent JSON pointer')
        parts=ptr[1:].split('/')
        if len(parts)>12 or any(len(p)>96 or re.search(r'~(?![01])',p) for p in parts):
            raise DisplayContractError('JSON pointer exceeds safe scope or has invalid escape')
    return rules


def load(path: Path) -> dict:
    path=path.expanduser().absolute()
    if path.is_symlink() or not path.is_file() or path.stat().st_size>MAX_CONTRACT_BYTES:
        raise DisplayContractError('Display contract must be a regular small local JSON file')
    try:
        # Reject duplicate keys to avoid attacker-chosen interpretation.
        def pairs(items):
            out={}
            for k,v in items:
                if k in out:raise DisplayContractError('Duplicate display JSON key')
                out[k]=v
            return out
        obj=json.loads(path.read_text(encoding='utf-8'),object_pairs_hook=pairs)
    except (UnicodeError, RecursionError, ValueError) as e:
        raise DisplayContractError('Invalid display JSON contract') from e
    validate(obj)
    return obj


def _pointer(obj: Any, pointer: str) -> Any:
    value=obj
    for raw in pointer[1:].split('/'):
        key=raw.replace('~1','/').replace('~0','~')
        if type(value) is dict:
            value=value.get(key,MISSING)
        elif type(value) is list and re.fullmatch(r'0|[1-9][0-9]*',key):
            index=int(key)
            value=value[index] if index<len(value) else MISSING
        else:
            return MISSING
        if value is MISSING:return MISSING
    return value


def _render_commonmark(text: str) -> tuple[str|None,str]:
    try:
        from markdown_it import MarkdownIt
    except ImportError:
        return None,'MARKDOWN_PARSER_UNAVAILABLE'
    if len(text)>MAX_TEXT:
        return None,'DISPLAY_VALUE_TOO_LARGE'
    try:
        tokens=MarkdownIt('commonmark',{'html':False}).parse(text)
    except (RecursionError,ValueError,TypeError):
        return None,'MARKDOWN_PARSER_FAILED'
    # Only a single simple paragraph is safe to interpret; arbitrary authored
    # headings, tables, lists, links, embedded HTML and images are unverified.
    if len(tokens)!=3 or [t.type for t in tokens]!=['paragraph_open','inline','paragraph_close']:
        return None,'DISPLAY_MARKDOWN_LAYOUT_UNSUPPORTED'
    children=tokens[1].children or []
    if len(children)>1024:
        return None,'DISPLAY_MARKDOWN_COMPLEXITY'
    parts=[]
    allowed={'text','code_inline','softbreak','hardbreak','em_open','em_close','strong_open','strong_close','s_open','s_close'}
    for child in children:
        if child.type not in allowed:
            return None,'DISPLAY_MARKDOWN_MARKUP_UNSUPPORTED'
        if child.type in ('text','code_inline'):
            parts.append(child.content)
        elif child.type in ('softbreak','hardbreak'):
            parts.append('\n')
    return ''.join(parts),''


def _copy_literal(text: str) -> tuple[str|None,str]:
    if len(text)>MAX_TEXT:
        return None,'DISPLAY_VALUE_TOO_LARGE'
    # Only an entire single CommonMark code span is stripped of its delimiters.
    # Otherwise this mode models copying the raw tool-output text literally,
    # as some model-facing consumers do, not copying from a rendered HTML view.
    if text.startswith('`'):
        try:
            from markdown_it import MarkdownIt
        except ImportError:
            return None,'MARKDOWN_PARSER_UNAVAILABLE'
        tokens=MarkdownIt('commonmark',{'html':False}).parse(text)
        if len(tokens)==3 and tokens[1].type=='inline':
            ch=tokens[1].children or []
            if len(ch)==1 and ch[0].type=='code_inline':
                return ch[0].content,''
        return None,'DISPLAY_CODE_SPAN_UNSUPPORTED'
    return text,''


def check(result: dict, rule: dict) -> tuple[str,str]:
    """Result is ('PASS'|'MISMATCH'|'UNVERIFIED', fixed structural reason)."""
    source=_pointer(result.get('structuredContent',MISSING),rule['source'])
    if type(source) is not str:
        return 'UNVERIFIED','DISPLAY_STRING_SOURCE_UNAVAILABLE'
    if len(source)>MAX_TEXT:
        return 'UNVERIFIED','DISPLAY_VALUE_TOO_LARGE'
    blocks=result.get('content')
    index=rule['content_index']
    if (type(blocks) is not list or index>=len(blocks) or type(blocks[index]) is not dict
            or blocks[index].get('type')!='text' or type(blocks[index].get('text')) is not str):
        return 'UNVERIFIED','DISPLAY_TEXT_BLOCK_UNAVAILABLE'
    text=blocks[index]['text']
    prefix=rule['prefix_raw']
    if text.count(prefix)!=1:
        return 'UNVERIFIED','DISPLAY_PREFIX_NOT_UNIQUE'
    # A declared segment ends at the first blank line; this is appropriate
    # for an Error: paragraph or single enrichment trailer line. Reject extra
    # content rather than guessing whether it belongs to the same scalar.
    segment=text.split(prefix,1)[1].split('\n\n',1)[0]
    if segment.endswith('\n'):
        segment=segment[:-1]
    if rule['mode']=='markdown-rendered':
        displayed,reason=_render_commonmark(segment)
    else:
        displayed,reason=_copy_literal(segment)
    if reason:
        return 'UNVERIFIED',reason
    expected=source.replace('\r\n','\n').replace('\r','\n') if rule['mode']=='markdown-rendered' else source
    return ('PASS' if displayed==expected else 'MISMATCH'),''


def rule_hash(ident: str) -> str:
    return hashlib.sha256(ident.encode('utf-8')).hexdigest()[:12]
