"""RISU Probe v0.9.5: conservative consumer-side MCP JSON bridge.

This is an opt-in adapter proposal for known response envelopes, NOT an
automatic patch to any external upstream or certification of an MCP server.
Never reads source/API oracle values to decide which response to promote.
"""
from __future__ import annotations
import copy
from risu_evidence import _parse_json, MAX_TEXT_CHARS

class RepairRejected(ValueError):
    pass

def promote_text_json(mcp: dict) -> dict:
    """Promote first *complete* text JSON envelope into structuredContent.

    Only handles MCPGen-like {"status_code":int,"data":object|array}.
    It preserves all existing fields, requires consistent isError/status,
    rejects duplicated/ambiguous keys, unknown status, conflicting metadata,
    and NEVER silently replaces an existing structuredContent field.
    """
    if not isinstance(mcp,dict):raise RepairRejected('MCP_RESULT_NOT_OBJECT')
    if 'structuredContent' in mcp:
        raise RepairRejected('EXISTING_STRUCTURED_CONTENT_NOT_OVERWRITTEN')
    chunks=mcp.get('content')
    if not isinstance(chunks,list) or not 1<=len(chunks)<=32:
        raise RepairRejected('NO_BOUNDED_TEXT_CONTENT')
    first=None
    for chunk in chunks:
        if isinstance(chunk,dict) and chunk.get('type')=='text':
            first=chunk.get('text')
            break
    if not isinstance(first,str) or len(first)>MAX_TEXT_CHARS:
        raise RepairRejected('FIRST_TEXT_MISSING_OR_OVERSIZED')
    try:root=_parse_json(first)
    except (ValueError,TypeError):
        raise RepairRejected('FIRST_TEXT_NOT_UNAMBIGUOUS_JSON') from None
    if not isinstance(root,dict) or type(root.get('status_code')) is not int:
        raise RepairRejected('NO_EXPLICIT_NUMERIC_HTTP_STATUS')
    status=root['status_code']
    if not 100<=status<=599:raise RepairRejected('INVALID_HTTP_STATUS')
    data=root.get('data')
    if not isinstance(data,(dict,list)):
        raise RepairRejected('NO_TYPED_JSON_DATA')
    expected_error=status>=400
    if type(mcp.get('isError')) is not bool or mcp['isError']!=expected_error:
        raise RepairRejected('ERROR_FLAG_CONFLICT')
    metadata=mcp.get('_meta')
    if metadata is not None and not isinstance(metadata,dict):
        raise RepairRejected('UNSAFE_METADATA_SHAPE')
    if metadata:
        names=('observed_http_status','httpStatus','http_status','statusCode','status_code')
        if any(k in metadata and (type(metadata[k]) is not int or metadata[k]!=status)
               for k in names):
            raise RepairRejected('STATUS_METADATA_CONFLICT')
    out=copy.deepcopy(mcp)
    out['structuredContent']=copy.deepcopy(data)
    out['_meta']={**(metadata or {}),'observed_http_status':status}
    return out

def read_structured(mcp:dict) -> dict|list|None:
    """A strict, declared consumer; never looks at text or _meta for body."""
    value=mcp.get('structuredContent')
    return value if isinstance(value,(dict,list)) else None
