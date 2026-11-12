"""Evidence-graded, explicit-contract MCP result and state-effect checker.

Does not execute a server, import target code, infer permissions from annotations,
trust error-sounding prose, or attest external witnesses. Evidence obligations
are selected *before* observing a held-out target. Trace and witness are bounded
independent user-supplied inputs. Counts distinguish pass/mismatch/unverified.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any
from risu_mcp_trace import _read_trace, TraceError

CONTRACT_SCHEMA = 'risu-mcp-observation-contract-v1'
WITNESS_SCHEMA = 'risu-mcp-state-witness-v1'
MAX_CONTRACT = 32768
MAX_WITNESS = 65536
MAX_RULES = 32
MAX_RECORDS = 128
MAX_FIELDS = 16
MAX_TEXT = 16384
PATTERN = re.compile(r'[A-Za-z0-9_-]{1,48}\Z')
HEX = re.compile(r'[0-9a-f]{64}\Z')
KIND = frozenset(('state-unchanged', 'state-changed', 'json-object'))
TYPES = frozenset(('string', 'integer', 'number', 'boolean', 'object', 'array', 'null'))


class ObservationError(ValueError):
    pass


def _unique(pairs: list[tuple[str, Any]]) -> dict:
    out = {}
    for k, v in pairs:
        if k in out:
            raise ObservationError('Duplicate JSON object key')
        out[k] = v
    return out


def _load(path: Path, limit: int) -> dict:
    p = path.expanduser().absolute()
    if p.is_symlink() or not p.is_file() or p.stat().st_size > limit:
        raise ObservationError('Invalid, symlinked or oversized local evidence file')
    try:
        doc = json.loads(p.read_text(encoding='utf-8'), object_pairs_hook=_unique,
                         parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite')))
    except (ValueError, UnicodeError, RecursionError) as e:
        raise ObservationError('Invalid JSON evidence') from e
    if type(doc) is not dict:
        raise ObservationError('Evidence root must be a JSON object')
    return doc


def _typed(value: Any, target: str) -> bool:
    return {
        'string': type(value) is str,
        'integer': type(value) is int,
        'number': type(value) in (int, float),
        'boolean': type(value) is bool,
        'object': type(value) is dict,
        'array': type(value) is list,
        'null': value is None
    }[target]


def _path_value(doc: dict, pointer: str) -> tuple[bool, Any]:
    value: Any = doc
    for part in pointer.split('/')[1:]:
        if type(value) is not dict or part not in value:
            return False, None
        value = value[part]
    return True, value


def _valid_pointer(pointer: Any) -> bool:
    return (type(pointer) is str and 2 <= len(pointer) <= 100
            and pointer.startswith('/') and 1 <= pointer.count('/') <= 6
            and all(re.fullmatch('[a-zA-Z_][a-zA-Z0-9_]{0,39}', part)
                    for part in pointer.split('/')[1:]))


def validate_contract(contract: dict) -> list[dict]:
    if set(contract) != {'schema', 'rules'} or contract['schema'] != CONTRACT_SCHEMA:
        raise ObservationError('Unsupported strict observation contract')
    rules = contract['rules']
    if type(rules) is not list or not 1 <= len(rules) <= MAX_RULES:
        raise ObservationError('Expected 1 to 32 rules')
    ids = set()
    for rule in rules:
        if type(rule) is not dict or rule.get('kind') not in KIND:
            raise ObservationError('Unsupported contract rule')
        expected = {'id', 'tool', 'kind', 'when'}
        if rule['kind'] == 'json-object':
            expected |= {'carrier', 'required'}
        if set(rule) != expected:
            raise ObservationError('Unexpected contract fields')
        ident, tool = rule['id'], rule['tool']
        if type(ident) is not str or not PATTERN.fullmatch(ident) or ident in ids:
            raise ObservationError('Invalid or duplicate rule ID')
        ids.add(ident)
        if type(tool) is not str or not 1 <= len(tool) <= 128:
            raise ObservationError('Invalid tool name')
        when = rule['when']
        if type(when) is not dict or len(when) > 8:
            raise ObservationError('Expected bounded argument predicates')
        for k, v in when.items():
            if type(k) is not str or not re.fullmatch('[a-zA-Z_][a-zA-Z0-9_]{0,63}', k):
                raise ObservationError('Invalid predicate key')
            if type(v) not in (str, int, float, bool, type(None)) or (type(v) is str and len(v) > 1024):
                raise ObservationError('Only bounded exact scalar predicates supported')
        if rule['kind'] == 'json-object':
            if rule['carrier'] not in ('single-text-json', 'structured-content'):
                raise ObservationError('Ambiguous or unsupported result carrier')
            required = rule['required']
            if type(required) is not dict or not 1 <= len(required) <= MAX_FIELDS:
                raise ObservationError('Expected 1 to 16 JSON path assertions')
            if not all(_valid_pointer(p) and t in TYPES
                       for p, t in required.items()):
                raise ObservationError('Unsupported JSON pointer or assertion type')
    return rules


def validate_witness(witness: dict, trace_sha256: str) -> dict:
    if set(witness) != {'schema', 'trace_sha256', 'records'} or witness['schema'] != WITNESS_SCHEMA:
        raise ObservationError('Unsupported strict state witness')
    if witness['trace_sha256'] != trace_sha256:
        raise ObservationError('Witness is not bound to these exact trace bytes')
    records = witness['records']
    if type(records) is not list or len(records) > MAX_RECORDS:
        raise ObservationError('Witness record budget exceeded')
    found = {}
    for rec in records:
        if type(rec) is not dict or set(rec) != {'session', 'request_line', 'response_line',
                                                'tool', 'before_sha256', 'after_sha256'}:
            raise ObservationError('Unsupported witness record fields')
        if type(rec['session']) is not str or not 1 <= len(rec['session']) <= 64:
            raise ObservationError('Invalid witness session')
        if (type(rec['request_line']) is not int or type(rec['response_line']) is not int or
            not 1 <= rec['request_line'] < rec['response_line'] <= 4096):
            raise ObservationError('Invalid witness correlation lines')
        if type(rec['tool']) is not str or not 1 <= len(rec['tool']) <= 128:
            raise ObservationError('Invalid witness tool name')
        if any(type(rec[x]) is not str or not HEX.fullmatch(rec[x])
               for x in ('before_sha256', 'after_sha256')):
            raise ObservationError('Invalid independent snapshot hash')
        key = (rec['session'], rec['request_line'], rec['response_line'])
        if key in found:
            raise ObservationError('Ambiguous duplicate witness for matched call')
        found[key] = rec
    return found


def _extract_json(result: dict, carrier: str) -> tuple[Any, str]:
    if carrier == 'structured-content':
        value = result.get('structuredContent')
        if type(value) is not dict:
            return None, 'STRUCTURED_RESULT_UNAVAILABLE'
        return value, ''
    blocks = result.get('content')
    if type(blocks) is not list or len(blocks) != 1 or type(blocks[0]) is not dict:
        return None, 'SINGLE_TEXT_BLOCK_REQUIRED'
    block = blocks[0]
    raw = block.get('text')
    if block.get('type') != 'text' or type(raw) is not str or len(raw) > MAX_TEXT:
        return None, 'SINGLE_BOUNDED_TEXT_REQUIRED'
    try:
        value = json.loads(raw, object_pairs_hook=_unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite')))
    except (ValueError, RecursionError):
        return None, 'DECLARED_JSON_CARRIER_INVALID'
    if type(value) is not dict:
        return None, 'DECLARED_JSON_OBJECT_REQUIRED'
    return value, ''


def _check(rule: dict, result: Any, witness: dict | None) -> tuple[str, str]:
    if type(result) is not dict:
        return 'UNVERIFIED', 'TOOL_RESULT_MISSING'
    if rule['kind'].startswith('state-'):
        if witness is None:
            return 'UNVERIFIED', 'INDEPENDENT_STATE_WITNESS_MISSING'
        changed = witness['before_sha256'] != witness['after_sha256']
        expects_change = rule['kind'] == 'state-changed'
        if changed != expects_change:
            return 'MISMATCH', 'INDEPENDENT_LOGICAL_STATE_DISAGREES_WITH_EXPLICIT_CONTRACT'
        return 'PASS', ''
    # JSON result assertions only hold if a normal completion is declared.
    if result.get('isError') is True:
        return 'UNVERIFIED', 'TOOL_REPORTED_ERROR'
    if result.get('isError') not in (False, None):
        return 'UNVERIFIED', 'NONBOOLEAN_ERROR_FLAG'
    obj, reason = _extract_json(result, rule['carrier'])
    if reason:
        return 'MISMATCH', reason
    for ptr, kind in rule['required'].items():
        exists, value = _path_value(obj, ptr)
        if not exists or not _typed(value, kind):
            return 'MISMATCH', 'DECLARED_JSON_FIELD_MISSING_OR_WRONG_TYPE'
    return 'PASS', ''


def verify(trace: Path, contract: dict, witness: dict | None = None) -> dict:
    rules = validate_contract(contract)
    records, trace_hash = _read_trace(trace)
    witnesses = validate_witness(witness, trace_hash) if witness is not None else {}
    # Pair only exact session, JSON-RPC ID type, and one live request.
    pending: dict[tuple, tuple[int, str, dict]] = {}
    calls = []
    violations = []
    for line, session, msg in records:
        method = msg.get('method')
        rid = msg.get('id')
        key = (session, type(rid).__name__, rid) if rid is not None else None
        if method == 'tools/call' and key is not None:
            params = msg.get('params')
            if type(params) is not dict or type(params.get('name')) is not str:
                violations.append({'line': line, 'reason': 'MALFORMED_CALL'})
            elif key in pending:
                violations.append({'line': line, 'reason': 'DUPLICATE_OUTSTANDING_CALL'})
                pending.pop(key, None)
            else:
                pending[key] = (line, params['name'], params.get('arguments'))
        elif method is None and key is not None and key in pending:
            start, name, args = pending.pop(key)
            calls.append((session, start, line, name, args, msg.get('result')))
    for start, _, _ in pending.values():
        violations.append({'line': start, 'reason': 'UNMATCHED_CALL'})
    matched = checked = passed = 0
    findings = []
    unverified = list(violations)
    per_rule: dict[str, int] = {r['id']: 0 for r in rules}
    used_witnesses = set()
    for session, start, end, tool, args, result in calls:
        for rule in rules:
            if rule['tool'] != tool:
                continue
            if type(args) is not dict:
                # Cannot safely prove predicate matching or mismatch.
                unverified.append({'line': start, 'reason': 'ARGUMENTS_UNAVAILABLE'})
                continue
            if any(k not in args or type(args[k]) is not type(v) or args[k] != v
                   for k, v in rule['when'].items()):
                continue
            matched += 1
            per_rule[rule['id']] += 1
            key = (session, start, end)
            wit = witnesses.get(key)
            if wit is not None and wit['tool'] != tool:
                unverified.append({'line': end, 'reason': 'WITNESS_TOOL_MISMATCH'})
                continue
            if wit is not None:
                used_witnesses.add(key)
            status, why = _check(rule, result, wit)
            if status == 'UNVERIFIED':
                unverified.append({'line': end, 'reason': why,
                    'rule_hash': hashlib.sha256(rule['id'].encode()).hexdigest()[:12]})
                continue
            checked += 1
            if status == 'PASS':
                passed += 1
            else:
                findings.append({'rule_id': ('RME610' if rule['kind'].startswith('state-') else 'RME620'),
                    'line': end, 'request_line': start,
                    'rule_hash': hashlib.sha256(rule['id'].encode()).hexdigest()[:12],
                    'tool_hash': hashlib.sha256(tool.encode()).hexdigest()[:16],
                    'reason': why,
                    'verdict': 'OBSERVED_IN_UNATTESTED_CAPTURE_AND_DECLARED_CONTRACT'})
    for rule in rules:
        if per_rule[rule['id']] == 0:
            unverified.append({'reason': 'CONTRACT_RULE_UNMATCHED',
                    'rule_hash': hashlib.sha256(rule['id'].encode()).hexdigest()[:12]})
    # Extra state records cannot be silently adopted as evidence for another call.
    for key in witnesses:
        if key not in used_witnesses:
            unverified.append({'line': key[1], 'reason': 'UNUSED_EXTERNAL_STATE_WITNESS'})
    return {'schema':'risu-mcp-observation-report-v1',
        'trace_sha256':trace_hash,
        'contract_sha256':hashlib.sha256(json.dumps(contract,sort_keys=True,
             separators=(',',':'),ensure_ascii=False).encode()).hexdigest(),
        'evidence_origin':'UNATTESTED_USER_SUPPLIED_TRACE_AND_STATE_WITNESSES',
        'summary':{'declared':len(rules),'matched':matched,'checked':checked,
                   'passed':passed,'observed_mismatches':len(findings),
                   'unverified':len(unverified)},
        'findings':findings,'unverified':unverified,
        'scope':'Exact opt-in contract. Unambiguous JSON object and independent state hashes only. No inference of contract authority, native server identity, witness authenticity, global correctness or error from prose.',
        'safety':'Offline read-only local analysis; no source import, network, server execution or private values emitted.'}


def cli(argv: list[str] | None = None) -> int:
    p=argparse.ArgumentParser(prog='risu-probe check-mcp-observations')
    p.add_argument('trace',type=Path)
    p.add_argument('--contract',required=True,type=Path)
    p.add_argument('--witness',type=Path,help='Optional independently captured state before/after hashes')
    p.add_argument('--format',choices=('text','json'),default='text')
    p.add_argument('--out',type=Path)
    p.add_argument('--fail-on-observed',action='store_true')
    p.add_argument('--strict-incomplete',action='store_true')
    a=p.parse_args(argv)
    try:
        report=verify(a.trace, _load(a.contract,MAX_CONTRACT),
                      _load(a.witness,MAX_WITNESS) if a.witness else None)
        summary=report['summary']
        value=json.dumps(report,indent=2,sort_keys=True,ensure_ascii=False)+'\n' if a.format=='json' else (
            f"RISU MCP observations | matched={summary['matched']} checked={summary['checked']} "+
            f"mismatches={summary['observed_mismatches']} unverified={summary['unverified']}\n")
        if a.out:
            target=a.out.expanduser().absolute()
            with target.open('x',encoding='utf-8') as f:
                f.write(value)
        else:
            print(value,end='')
        if a.strict_incomplete and summary['unverified']:
            return 2
        return 1 if a.fail_on_observed and summary['observed_mismatches'] else 0
    except (ObservationError,TraceError,UnicodeError,ValueError,TypeError,OSError,RecursionError) as e:
        print('RME600 INVALID_OR_UNSUPPORTED_OBSERVATION_EVIDENCE: '+
              type(e).__name__,file=sys.stderr)
        return 2


if __name__=='__main__':
    raise SystemExit(cli())
