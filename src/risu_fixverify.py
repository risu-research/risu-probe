"""RISU Fix Verification v0.9.6: non-destructive, fail-closed consumer bridge.

A patch must not rewrite already-valid structuredContent. It must not
silently coerce inconsistent status flags. For textual carriers, the
existing strictly validated v0.9.5 promoter remains the only promotion path.
No network, no model calls, no edits to vendor source.
"""
from __future__ import annotations
import copy
import hashlib
import json
from typing import Any
from risu_repair import promote_text_json, RepairRejected
from risu_diagnostics import _strict_same
from risu_evidence import _bounded_shape

_STATUS_KEYS=('observed_http_status','httpStatus','http_status','statusCode','status_code')

def _typed_existing(mcp:dict) -> dict:
    structured=mcp.get('structuredContent')
    if not isinstance(structured,(dict,list)) or not _bounded_shape(structured):
        raise RepairRejected('INVALID_EXISTING_STRUCTURED_CONTENT')
    metadata=mcp.get('_meta')
    if metadata is not None and not isinstance(metadata,dict):
        raise RepairRejected('UNSAFE_METADATA_SHAPE')
    statuses=[metadata[key] for key in _STATUS_KEYS if key in metadata] if metadata else []
    if statuses:
        if any(type(v) is not int or v<100 or v>599 for v in statuses):
            raise RepairRejected('INVALID_EXPLICIT_STATUS_METADATA')
        if len(set(statuses))>1:
            raise RepairRejected('CONFLICTING_STATUS_METADATA')
        flag=mcp.get('isError')
        if type(flag) is bool and flag!=(statuses[0]>=400):
            raise RepairRejected('EXISTING_STATUS_ERROR_FLAG_CONFLICT')
    # Exact-preservation is intentional, including text and vendor metadata.
    return copy.deepcopy(mcp)

def prepare_consumer_result(mcp:dict) ->dict:
    """Return an isolated, typed consumer view, never edit caller's result.

    This does not establish external HTTP provenance; only previously captured
    MCP output is available. Existing structuredContent takes precedence.
    """
    if not isinstance(mcp,dict):
        raise RepairRejected('MCP_RESULT_NOT_OBJECT')
    if 'structuredContent' in mcp:
        return _typed_existing(mcp)
    return promote_text_json(mcp)

def verify_preserved(before:dict,after:dict)->bool:
    """Explicit condition for no regression on an already typed response."""
    return _strict_same(before,after)

def digest_without_values(value:Any)->str:
    data=json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,
                    allow_nan=False).encode('utf-8')
    return hashlib.sha256(data).hexdigest()
