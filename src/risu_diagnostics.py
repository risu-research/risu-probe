"""Evidence-grounded, vendor-neutral HTTP -> MCP data-loss diagnostics.

No inferred loss from length alone; truncation needs demonstrable source prefix
alignment AND an explicit clipping marker in the observed MCP text.
This module never includes source-body values or MCP text in its findings.
"""
from __future__ import annotations

import json
from typing import Any

MARKERS = ('… (truncated)', '... (truncated)', ' [truncated]')
MAX_TEXT = 2_000_000
MAX_SOURCE_CHARS = 250_000


def _mime(value: Any) -> str:
    return str(value or '').split(';', 1)[0].strip().lower()


def _texts(mcp: dict) -> list[str]:
    parts = mcp.get('content') or []
    if not isinstance(parts, list):
        return []
    return [p.get('text') for p in parts[:100]
            if isinstance(p, dict) and p.get('type') == 'text'
            and isinstance(p.get('text'), str) and len(p['text']) <= MAX_TEXT]


def _json_candidates(body: Any, source: dict) -> list[str]:
    """Evidence alternatives for independent serializers; never speculate about values."""
    found = []
    raw = source.get('body_text')
    if isinstance(raw, str) and len(raw) <= MAX_SOURCE_CHARS:
        try:
            if _strict_same(json.loads(raw), body):
                found.append(raw)
        except (TypeError,ValueError,RecursionError):
            pass
    for ensure_ascii in (False, True):
        for separators in (None, (',', ':')):
            try:
                value = json.dumps(body, ensure_ascii=ensure_ascii, separators=separators)
            except (TypeError, ValueError, OverflowError, RecursionError):
                continue
            if len(value) > MAX_SOURCE_CHARS:
                continue
            if value not in found:
                found.append(value)
    return found


def _strict_same(a: Any, b: Any, depth: int = 0) -> bool:
    # Avoid Python's 'True == 1' equivalence when asserting JSON type preservation.
    if type(a) is not type(b) or depth > 64:
        return False
    if isinstance(a, dict):
        return (a.keys() == b.keys() and len(a) <= 20000
                and all(_strict_same(v,b[k],depth+1) for k,v in a.items()))
    if isinstance(a, list):
        return (len(a) == len(b) and len(a) <= 20000
                and all(_strict_same(x,y,depth+1) for x,y in zip(a,b)))
    return a == b


def _machine_exact(body: Any, mcp: dict, mime: str) -> bool:
    if 'structuredContent' in mcp and _strict_same(mcp['structuredContent'], body):
        return True
    for item in mcp.get('content') or []:
        if not isinstance(item, dict) or item.get('type') != 'resource':
            continue
        res = item.get('resource') or {}
        if not isinstance(res, dict):
            continue
        if _mime(res.get('mimeType')) not in (mime, 'application/problem+json', 'application/json'):
            continue
        try:
            val = json.loads(res.get('text', ''))
        except (TypeError, ValueError):
            continue
        if _strict_same(val,body):
            return True
    return False


def _truncation(source: dict, mcp: dict) -> dict | None:
    """Find a *proven* clipped source serialization, not a keyword coincidence.

    An explicit marker alone is insufficient. Require >=64 exact characters of
    upstream JSON immediately preceding the marker. The target must omit a tail
    of the source after the prefix. No vendor-specific 1000-character constant.
    """
    candidates = _json_candidates(source['body'], source)
    texts = _texts(mcp)
    if any(original in text for original in candidates for text in texts):
        # A clipped preview is possible, but the complete JSON is still
        # available elsewhere in the same result as text.
        return None
    for text in texts:
        for marker in MARKERS:
            start = 0
            marker_hits = 0
            while marker_hits < 24:
                end = text.find(marker, start)
                if end < 0:
                    break
                start = end + len(marker)
                marker_hits += 1
                for original in candidates:
                    if original in text:
                        # The full JSON is visible; a marker may simply be
                        # part of the original payload, or an unrelated note.
                        continue
                    if len(original) < 80:
                        continue
                    # Find an upstream prefix in any text surrounding the marker.
                    fragment = original[:64]
                    pos = text.find(fragment)
                    while pos >= 0 and pos < end:
                        size = end-pos
                        if (size >= 64 and size < len(original)
                                and text[pos:end] == original[:size]
                                and not original[size:].startswith(marker)):
                            details = {
                                'code': 'TRUNCATED_UPSTREAM_ERROR',
                                'severity': 'error',
                                'confidence': 'observed_prefix_and_marker',
                                'source_chars': len(original),
                                'prefix_chars': size,
                                'omitted_min_chars': len(original)-size,
                                'marker': marker,
                                'unit': 'Python unicode characters',
                            }
                            return details
                        pos = text.find(fragment, pos+1)
    return None


def _missing_positions(body: Any, mcp: dict) -> dict | None:
    """Conservatively count exact quoted/pointer strings absent from text.

    Limited to a declared list of dict entries containing a unique JSON Pointer
    string under 'pointer'. Never prints pointer contents (could be sensitive).
    """
    if not isinstance(body, dict) or not isinstance(body.get('errors'), list):
        return None
    items = body['errors']
    if not (1 <= len(items) <= 500):
        return None
    ptrs = [x.get('pointer') for x in items if isinstance(x, dict)]
    if len(ptrs) != len(items) or any(not isinstance(x, str) or len(x)>500 for x in ptrs):
        return None
    if len(set(ptrs)) != len(ptrs) or not all(x.startswith(('#/', '/')) for x in ptrs):
        return None
    texts = '\n'.join(_texts(mcp))
    if len(texts) > 200_000:
        return None
    present = sum(p in texts for p in ptrs)
    return {'source_pointer_count': len(ptrs), 'visible_complete_pointer_count': present,
            'missing_complete_pointer_count': len(ptrs)-present,
            'scope': 'exact pointer substrings in diagnostic text; partial entries excluded'}


def detect(source: dict, mcp: dict, *, verdict: str | None = None) -> list[dict]:
    """Return *diagnostic codes* independent of a library name.

    Preserve source data privacy: output metadata and counts only.
    """
    try:
        status = source['status']
        mime = _mime(source['content_type'])
        body = source['body']
        if type(status) is not int or not 100 <= status <= 599 or not isinstance(mcp, dict):
            return []
    except (KeyError, TypeError, ValueError):
        return []
    if mcp.get('resultType') not in (None, 'complete'):
        return []
    if status < 400:
        return []
    if not (mime == 'application/json' or mime.endswith('+json')):
        return []
    complete = _machine_exact(body, mcp, mime)
    details = _truncation(source, mcp)
    findings = []
    if details is not None and not complete:
        positions = _missing_positions(body, mcp)
        if positions is not None:
            details['collection'] = positions
        findings.append(details)
    if mcp.get('isError') is not True:
        findings.append({'code':'ERROR_FLAG_LOST','severity':'error',
                         'confidence':'observed_http_failure_vs_mcp_flag',
                         'note':'Upstream HTTP was unsuccessful but MCP tool result did not set isError=true.'})
    if not complete:
        findings.append({
            'code': 'UNSTRUCTURED_UPSTREAM_ERROR',
            'severity': 'warning',
            'confidence': 'observed_machine_carriers',
            'note': 'Exact original JSON object not found in structuredContent or an eligible typed embedded resource; textual JSON is not a typed carrier.',
        })
    return findings
