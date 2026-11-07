"""Evidence-calibrated HTTP -> MCP preservation classifier (v0.9.3 experimental).

Conservative: claims exact recovery only after a full, duplicate-free, finite
JSON parse and strict deep value/type comparison. Does not treat 'not found in
structuredContent' as proof that original information was destroyed.
No raw source/MCP values, snippets, or credentials in the output.
"""
from __future__ import annotations

import json
import math
import re
from typing import Any

from risu_diagnostics import _mime, _strict_same, _truncation

MAX_TEXT_CHARS = 1_000_000
MAX_TEXT_PARTS = 32
MAX_JSON_NODES = 20_000
MAX_DEPTH = 64
ENVELOPE_KEYS = frozenset(('data', 'body', 'payload', 'result', 'response', 'error'))
_FENCE = re.compile(r'\A```(?:json|JSON)?\s*\n(.*?)\n```\s*\Z', re.DOTALL)
_PREFIX = re.compile(r'\A(?:JSON|Response JSON|API response|Response|Result):\s*\n(.*)\Z', re.DOTALL)
_STATUS_KEYS = ('observed_http_status', 'httpStatus', 'http_status', 'statusCode', 'status_code')


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict:
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError('ambiguous duplicate JSON key')
        out[key] = value
    return out


def _reject_nonfinite(value: str):
    raise ValueError('non-JSON nonfinite constant')


def _bounded_shape(value: Any) -> bool:
    stack = [(value, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > MAX_DEPTH:
            return False
        if isinstance(current, dict):
            if not all(type(k) is str for k in current):
                return False
            stack.extend((v, depth+1) for v in current.values())
        elif isinstance(current, list):
            stack.extend((v, depth+1) for v in current)
        elif type(current) is float:
            if not math.isfinite(current):
                return False
        elif current is not None and type(current) not in (str, bool, int):
            return False
    return True


def _parse_json(text: str):
    """Returns parsed JSON, including null, or raises ValueError.

    No repeated-key ambiguity, Python-accepted NaN, or unbounded JSON trees.
    """
    if len(text) > MAX_TEXT_CHARS:
        raise ValueError('JSON text limit exceeded')
    try:
        obj = json.loads(text, object_pairs_hook=_no_duplicate_keys,
                         parse_constant=_reject_nonfinite)
    except (RecursionError, UnicodeError) as exc:
        raise ValueError('JSON parse exceeded limits') from exc
    if not _bounded_shape(obj):
        raise ValueError('JSON tree limits exceeded')
    return obj


def _json_text_candidates(text: str):
    yield 'ENTIRE_JSON_TEXT', text
    fenced = _FENCE.fullmatch(text.strip())
    if fenced:
        yield 'FENCED_JSON_TEXT', fenced.group(1)
    prefixed = _PREFIX.fullmatch(text.strip())
    if prefixed:
        yield 'LABELLED_JSON_TEXT', prefixed.group(1)


def _exact_envelope_paths(parsed: Any, body: Any) -> list[str]:
    """Only predeclared wrappers; never arbitrary nested logs or explanatory text.

    Avoid falsely certifying a tiny scalar contained accidentally in an object.
    Nested recovery is certified only for compound JSON bodies.
    """
    if not isinstance(body, (dict, list)) or not isinstance(parsed, dict):
        return []
    paths = []
    for key in ENVELOPE_KEYS:
        if key in parsed and _strict_same(parsed[key], body):
            paths.append('/' + key)
        inner = parsed.get(key)
        if isinstance(inner, dict):
            for nextkey in ENVELOPE_KEYS:
                if nextkey in inner and _strict_same(inner[nextkey], body):
                    paths.append('/' + key + '/' + nextkey)
    return sorted(set(paths))


def _texts(mcp: dict) -> list[str]:
    content = mcp.get('content')
    if not isinstance(content, list):
        return []
    return [item['text'] for item in content[:MAX_TEXT_PARTS]
            if isinstance(item, dict) and item.get('type') == 'text'
            and isinstance(item.get('text'), str) and len(item['text']) <= MAX_TEXT_CHARS]


def _structured_carrier(body: Any, mcp: dict, mime: str) -> str | None:
    result = mcp.get('structuredContent')
    if 'structuredContent' in mcp and _strict_same(result, body):
        return 'STRUCTURED_CONTENT_EXACT'
    if len(_exact_envelope_paths(result, body)) == 1:
        return 'STRUCTURED_ENVELOPE_EXACT'
    chunks = mcp.get('content')
    if isinstance(chunks, list):
        for chunk in chunks[:MAX_TEXT_PARTS]:
            if not isinstance(chunk, dict) or chunk.get('type') != 'resource':
                continue
            resource = chunk.get('resource')
            if (not isinstance(resource, dict) or
                    _mime(resource.get('mimeType')) not in
                    ('application/json', 'application/problem+json', mime)):
                continue
            data = resource.get('text')
            if not isinstance(data, str):
                continue
            try:
                val = _parse_json(data)
            except (ValueError, TypeError):
                continue
            if _strict_same(val, body):
                return 'TYPED_RESOURCE_EXACT'
            if len(_exact_envelope_paths(val, body)) == 1:
                return 'TYPED_RESOURCE_ENVELOPE_EXACT'
    metadata = mcp.get('_meta')
    if '_meta' in mcp and (_strict_same(metadata, body) or
                           len(_exact_envelope_paths(metadata, body)) == 1):
        return 'METADATA_ONLY_EXACT'
    return None


def _text_carrier(body: Any, mcp: dict):
    """Return (channel, wrapper_key, decoded_root) with deterministic bounds."""
    for text in _texts(mcp):
        for kind, segment in _json_text_candidates(text):
            try:
                root = _parse_json(segment)
            except (ValueError, TypeError):
                continue
            if _strict_same(root, body):
                return kind + '_EXACT', None, root
            paths = _exact_envelope_paths(root, body)
            if len(paths) == 1:
                return kind + '_ENVELOPE_EXACT', paths[0], root
            # Ambiguous multiple matching envelopes are deliberately uncertified.
    return None, None, None


def _status_evidence(root: dict | None, mcp: dict, status: int):
    # Typed metadata is distinct from status encoded in parsable text.
    metadata = mcp.get('_meta')
    if isinstance(metadata, dict):
        values = [metadata[k] for k in _STATUS_KEYS
                  if k in metadata and type(metadata[k]) is int]
        if values:
            return 'MACHINE_STATUS_MATCH' if all(v == status for v in values) else 'MACHINE_STATUS_CONFLICT'
    if isinstance(root, dict):
        values = [root[k] for k in _STATUS_KEYS
                  if k in root and type(root[k]) is int]
        if values:
            return 'TEXT_STATUS_RECOVERABLE' if all(v == status for v in values) else 'TEXT_STATUS_CONFLICT'
    return 'NO_EXPLICIT_STATUS'


def assess(source: dict, mcp: dict, *, consumer_scoped=False) -> dict:
    """Independent evidence axes; the legacy compare verdict remains unchanged.

    body_recovery is the availability of a *complete exact object* in a known
    carrier, not a claim that an LLM will necessarily interpret it correctly.
    """
    if not isinstance(source, dict) or not isinstance(mcp, dict):
        return {'schema':'risu-evidence-v1','body_recovery':'NOT_ASSESSED', 'reason':'MALFORMED_INPUT'}
    status, mime, body = source.get('status'), _mime(source.get('content_type')), source.get('body')
    if type(status) is not int or not 100 <= status <= 599:
        return {'schema':'risu-evidence-v1','body_recovery':'NOT_ASSESSED','reason':'INVALID_HTTP_STATUS'}
    result_type = mcp.get('resultType')
    if result_type == 'input_required':
        return {'schema':'risu-evidence-v1','body_recovery':'DEFERRED','reason':'INPUT_REQUIRED'}
    if result_type not in (None, 'complete'):
        return {'schema':'risu-evidence-v1','body_recovery':'NOT_ASSESSED','reason':'UNSUPPORTED_RESULT_TYPE'}
    flag = ('ERROR_FLAG_LOST' if status >= 400 and mcp.get('isError') is not True
            else 'SPURIOUS_ERROR_FLAG' if status < 400 and mcp.get('isError') is True
            else 'ERROR_FLAG_MATCH')
    if mime != 'application/json' and not mime.endswith('+json'):
        return {'schema':'risu-evidence-v1','body_recovery':'NOT_ASSESSED',
                'reason':'NON_JSON_MEDIA','error_flag':flag}
    if consumer_scoped:
        return {'schema':'risu-evidence-v1','body_recovery':'NOT_ASSESSED',
                'reason':'CONSUMER_SCOPED_CHECK','error_flag':flag}
    if not _bounded_shape(body):
        return {'schema':'risu-evidence-v1','body_recovery':'NOT_ASSESSED',
                'reason':'SOURCE_LIMIT_EXCEEDED','error_flag':flag}
    structured = _structured_carrier(body, mcp, mime)
    text_channel, envelope, decoded_root = _text_carrier(body, mcp)
    structured_recoverable = structured is not None
    text_recoverable = text_channel is not None
    clipped = None
    if not structured_recoverable and not text_recoverable and status >= 400:
        clipped = _truncation(source, mcp)
    if structured_recoverable:
        recovery = 'EXACT_MACHINE'
    elif text_recoverable:
        recovery = 'EXACT_JSON_TEXT'
    elif clipped:
        recovery = 'PROVEN_TRUNCATED_PREVIEW'
    elif _texts(mcp):
        recovery = 'UNVERIFIED_TEXT'
    else:
        recovery = 'NO_EXACT_CARRIER_OBSERVED'
    result = {
        'schema':'risu-evidence-v1',
        'body_recovery':recovery,
        'machine_carrier':structured or 'NONE_CERTIFIED',
        'text_carrier':text_channel or 'NONE_CERTIFIED',
        'error_flag':flag,
        'http_status':_status_evidence(decoded_root,mcp,status),
        'body_loss_claim':('OBSERVED_TRUNCATED_PREVIEW' if clipped else
                           'NO_EXACT_INFORMATION_LOSS_PROVEN'),
        'scope':'FULL_JSON_BODY',
        'confidence':('EXACT_TYPE_AND_VALUE' if structured_recoverable or text_recoverable else
                      'ALIGNED_PREFIX_AND_EXPLICIT_MARKER' if clipped else 'INSUFFICIENT_FOR_LOSS_CLAIM'),
    }
    if envelope is not None:
        # Whitelisted keys, never user-provided arbitrary paths.
        result['envelope_path'] = envelope
    if clipped is not None:
        result['truncation'] = {k:clipped[k] for k in
                                ('source_chars','prefix_chars','omitted_min_chars')}
    result['recommended_action'] = (
        'RESTORE_FULL_BODY' if clipped else
        'EMIT_STRUCTURED_CONTENT' if text_recoverable and not structured_recoverable else
        'REVIEW_UNKNOWN_TEXT_CARRIER' if not structured_recoverable and not text_recoverable else
        'REVIEW_ERROR_FLAG' if flag != 'ERROR_FLAG_MATCH' else
        'NONE')
    return result
