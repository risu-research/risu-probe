"""Offline, opt-in fidelity checks between recorded structured output and Markdown text.

No remote requests, third-party project imports, regex evaluation or tool execution.
Contracts are user-supplied semantic assertions, not inferred MCP obligations.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any

from risu_mcp_trace import TraceError, _label, _read_trace, _unique

CONTRACT_SCHEMA = 'risu-display-fidelity-contract-v1'
MAX_CONTRACT_BYTES = 32_768
MAX_RULES = 64
MAX_LINES = 256
MAX_OUTPUT_LEN = 4096
ALLOWED_MODES = frozenset(('markdown-literal', 'code-copy', 'json-string-special'))
MISSING = object()


def _pointer(root: Any, pointer: str) -> Any:
    if not isinstance(pointer, str) or not pointer.startswith('/') or len(pointer) > 256:
        raise TraceError('Invalid structured JSON pointer')
    value = root
    for raw in pointer.split('/')[1:]:
        key = raw.replace('~1', '/').replace('~0', '~')
        if type(value) is dict and key in value:
            value = value[key]
        elif type(value) is list and key.isdigit() and int(key) < len(value):
            value = value[int(key)]
        else:
            return MISSING
    return value


def _validate_contract(data: Any) -> dict:
    if type(data) is not dict or set(data) != {'schema', 'rules'} or data['schema'] != CONTRACT_SCHEMA:
        raise TraceError('Unknown or malformed display-fidelity contract')
    rules = data['rules']
    if type(rules) is not list or not 1 <= len(rules) <= MAX_RULES:
        raise TraceError('Display-fidelity contract requires 1-64 rules')
    names = set()
    for rule in rules:
        if type(rule) is not dict or set(rule) != {'id', 'tool', 'pointer', 'line_prefix', 'mode', 'is_error'}:
            raise TraceError('Invalid display-fidelity rule fields')
        ident = rule['id']
        if type(ident) is not str or not re.fullmatch(r'[A-Za-z0-9_-]{1,40}', ident) or ident in names:
            raise TraceError('Invalid or duplicated display-fidelity rule identifier')
        names.add(ident)
        if type(rule['tool']) is not str or not (1 <= len(rule['tool']) <= 128):
            raise TraceError('Invalid tool name in display-fidelity rule')
        _pointer({}, rule['pointer'])
        p = rule['line_prefix']
        if type(p) is not str or not (1 <= len(p) <= 160) or '\n' in p or '\r' in p:
            raise TraceError('Invalid display line prefix')
        if rule['mode'] not in ALLOWED_MODES or rule['is_error'] not in (True, False, None):
            raise TraceError('Unsupported display mode or is_error condition')
    return data


def load_contract(path: Path) -> dict:
    path = path.expanduser().absolute()
    if path.is_symlink() or not path.is_file() or not (1 <= path.stat().st_size <= MAX_CONTRACT_BYTES):
        raise TraceError('Contract must be a small regular file, not a symlink')
    try:
        data = json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=_unique)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise TraceError('Invalid contract JSON') from exc
    return _validate_contract(data)


def _parse_markdown_inline(value: str) -> tuple[list, str | None]:
    try:
        from markdown_it import MarkdownIt
    except ImportError:
        return [], 'markdown-it-py optional dependency is not installed'
    try:
        block = MarkdownIt('commonmark').parseInline(value)
        children = block[0].children or [] if block else []
        return children, None
    except (ValueError, RecursionError, TypeError):
        return [], 'Bounded Markdown parsing did not complete'


def _evaluate(expected: str, line: str, mode: str) -> tuple[str, str]:
    if len(line) > MAX_OUTPUT_LEN or len(expected) > MAX_OUTPUT_LEN:
        return 'UNVERIFIED', 'Text value exceeds bounded fidelity checker budget'
    tokens, reason = _parse_markdown_inline(line)
    if reason is not None:
        return 'UNVERIFIED', reason
    forbidden = {'html_inline', 'link_open', 'image'}
    if any(t.type in forbidden for t in tokens):
        return 'MISMATCH', 'Active Markdown link/HTML/image in declared literal value'
    if mode == 'code-copy':
        nonempty = [t for t in tokens if t.type != 'text' or t.content.strip()]
        if len(nonempty) == 1 and nonempty[0].type == 'code_inline':
            actual = nonempty[0].content
            return ('PASS', '') if actual == expected else ('MISMATCH', 'Code literal changed expected value')
        # A plain safe token can also be copied exactly; escaping must not introduce data.
        if re.fullmatch(r'[A-Za-z0-9 .,:/+@-]+', expected) and ''.join(t.content for t in tokens if t.type == 'text') == expected:
            return 'PASS', ''
        return 'MISMATCH', 'Copy-required value not rendered as one exact code literal'
    if mode == 'json-string-special':
        special = (not expected or expected != expected.strip()
                   or any(c in expected for c in '\r\n\t\u0085\u2028\u2029'))
        if special:
            meaningful = [t for t in tokens if t.type != 'text' or t.content.strip()]
            if len(meaningful) != 1 or meaningful[0].type != 'code_inline':
                return 'MISMATCH', 'Special string needs unambiguous JSON code literal'
            try:
                decoded = json.loads(meaningful[0].content)
            except (ValueError, UnicodeError):
                return 'MISMATCH', 'Code literal is not valid JSON string'
            return ('PASS', '') if type(decoded) is str and decoded == expected else ('MISMATCH', 'JSON code literal lost original string')
        mode = 'markdown-literal'
    if mode == 'markdown-literal':
        collected = []
        allowed = {'text', 'code_inline', 'softbreak', 'hardbreak', 'em_open', 'em_close',
                   'strong_open', 'strong_close', 's_open', 's_close'}
        for t in tokens:
            if t.type not in allowed:
                return 'UNVERIFIED', 'Unsupported Markdown construct in literal-value segment'
            if t.type in ('text', 'code_inline'):
                collected.append(t.content)
            elif t.type in ('softbreak', 'hardbreak'):
                collected.append('\n')
        return ('PASS', '') if ''.join(collected) == expected else ('MISMATCH', 'Rendered Markdown changed declared literal value')
    return 'UNVERIFIED', 'Unsupported mode'


def verify_display_fidelity(path: Path, contract: dict) -> dict:
    rules = _validate_contract(contract)['rules']
    records, digest = _read_trace(path)
    pending: dict[tuple[str, str], tuple[str, int]] = {}
    uncertain: set[tuple[str, str]] = set()
    findings: list[dict] = []
    gaps: list[dict] = []
    checked = matched = 0
    def gap(code: str, line: int, reason: str):
        if len(gaps) < MAX_LINES:
            gaps.append({'code': code, 'line': line, 'reason': reason})
    for line_no, session, msg in records:
        req_id = msg.get('id')
        if req_id is None:
            continue
        key = (session, str(req_id))
        method = msg.get('method')
        if method is not None:
            if key in pending:
                pending.pop(key, None)
                uncertain.add(key)
                gap('AMBIGUOUS_ID', line_no, 'Overlapping request identifier')
            elif method == 'tools/call':
                params = msg.get('params')
                if type(params) is dict and type(params.get('name')) is str:
                    pending[key] = (params['name'], line_no)
                else:
                    gap('INVALID_CALL', line_no, 'Tool name not captured')
            continue
        if key in uncertain:
            continue
        current = pending.pop(key, None)
        if current is None:
            continue
        tool, _ = current
        applicable = [r for r in rules if r['tool'] == tool]
        if not applicable:
            continue
        if 'error' in msg or type(msg.get('result')) is not dict:
            gap('NONRESULT', line_no, 'Captured call lacks a successful JSON-RPC result')
            continue
        result = msg['result']
        is_error = result.get('isError', False)
        if type(is_error) is not bool:
            gap('INVALID_ERROR_FLAG', line_no, 'Tool isError is not boolean')
            continue
        if result.get('resultType', 'complete') != 'complete':
            gap('NONFINAL_RESULT', line_no, 'Only complete results supported')
            continue
        blocks = result.get('content')
        if type(blocks) is not list or len(blocks) > 32:
            gap('UNAVAILABLE_TEXT', line_no, 'No bounded content array')
            continue
        for rule in applicable:
            if rule['is_error'] is not None and rule['is_error'] != is_error:
                continue
            matched += 1
            value = _pointer(result.get('structuredContent', MISSING), rule['pointer'])
            if type(value) is not str:
                gap('UNAVAILABLE_STRUCTURED_STRING', line_no, 'Declared structured string path missing or non-string')
                continue
            lines = []
            for block in blocks:
                if type(block) is dict and block.get('type') == 'text' and type(block.get('text')) is str:
                    if len(block['text']) > MAX_OUTPUT_LEN * 4:
                        continue
                    lines.extend(l for l in block['text'].splitlines() if l.startswith(rule['line_prefix']))
            if len(lines) != 1:
                gap('AMBIGUOUS_OR_MISSING_LINE', line_no, 'Expected exactly one named literal output line')
                continue
            segment = lines[0][len(rule['line_prefix']):]
            result_kind, detail = _evaluate(value, segment, rule['mode'])
            if result_kind == 'UNVERIFIED':
                gap('UNVERIFIED_MARKDOWN', line_no, detail)
            else:
                checked += 1
                if result_kind == 'MISMATCH' and len(findings) < MAX_LINES:
                    findings.append({'rule_id':'RDF601', 'verdict':'OBSERVED_IN_UNATTESTED_CAPTURE',
                        'tool':_label(tool), 'rule_sha256':hashlib.sha256(rule['id'].encode()).hexdigest()[:12],
                        'line':line_no, 'message':detail})
    for _, line_no in pending.values():
        gap('MISSING_RESPONSE', line_no, 'Unmatched captured tool call')
    return {
        'schema':'risu-display-fidelity-audit-v1',
        'origin_integrity':'UNATTESTED_LOCAL_CAPTURE',
        'capture_sha256':digest,
        'semantic_verification':('OBSERVED_FIDELITY_MISMATCHES' if findings else
           'INCOMPLETE_FIDELITY_CHECK' if gaps else 'CHECKED_NO_FIDELITY_MISMATCHES' if checked else 'NOT_CHECKED'),
        'summary':{'rules_declared':len(rules), 'applicable_assertions':matched,
           'literal_checks_completed':checked, 'findings':len(findings),
           'unverified':len(gaps)},
        'findings':findings, 'unverified':gaps,
        'claim_boundary':'Only explicit caller-defined relationships between captured structured strings and a named Markdown line; no automatic inference of tool semantics, user intent, live incident, or root cause.',
        'safety':'Offline; no raw structured values or untrusted result texts copied into reports.'
    }


def cli(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog='risu-probe verify-display-fidelity')
    p.add_argument('trace', type=Path)
    p.add_argument('--contract', required=True, type=Path)
    p.add_argument('--format', choices=('json','text'), default='text')
    p.add_argument('--fail-on-observed', action='store_true')
    p.add_argument('--strict-incomplete', action='store_true')
    a=p.parse_args(argv)
    try:
        result=verify_display_fidelity(a.trace,load_contract(a.contract))
        if a.format == 'json':
            print(json.dumps(result,indent=2,sort_keys=True))
        else:
            print('RISU DISPLAY FIDELITY | '+result['semantic_verification'])
            print('Checked: '+str(result['summary']['literal_checks_completed'])+
                  ' | Findings: '+str(result['summary']['findings'])+
                  ' | Unverified: '+str(result['summary']['unverified']))
        if a.strict_incomplete and result['summary']['unverified']:
            return 2
        if a.fail_on_observed and result['summary']['findings']:
            return 1
        return 0
    except (TraceError, OSError, ValueError, TypeError, RecursionError) as exc:
        print('RDF600 INVALID_OR_UNSUPPORTED_INPUT: '+type(exc).__name__,file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(cli())
