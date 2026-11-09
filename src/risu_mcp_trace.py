"""Offline, bounded semantic checks for recorded MCP JSON-RPC messages.

No user project import, subprocess, remote schema loading, network, or execution.
Verdicts mean *observed in an unauthenticated capture*, never live certification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
import sys
from typing import Any
from risu_display_fidelity import DisplayContractError, validate as validate_display_contract, load as load_display_contract, check as check_display, rule_hash as display_rule_hash

MAX_TRACE_BYTES = 4_194_304
MAX_LINE_BYTES = 524_288
MAX_MESSAGES = 4096
MAX_SCHEMA_NODES = 512
MAX_VALUE_NODES = 2048
MAX_CATALOG_NODES = 65536  # only for tools/list, bounded by existing 512-KiB line cap
MAX_CATALOG_PAGES = 100
MAX_CATALOG_TOOLS = 1024
MAX_CATALOG_CURSOR_LENGTH = 256
ALLOWED_PROTOCOLS = ('2025-03-26', '2025-06-18', '2025-11-25', '2026-07-28', 'unknown')
LEGACY_PROTOCOLS = frozenset(('2025-03-26', '2025-06-18', '2025-11-25'))
DRAFT7_DIALECTS = frozenset(('http://json-schema.org/draft-07/schema#',
                             'http://json-schema.org/draft-07/schema',
                             'https://json-schema.org/draft-07/schema',
                             'https://json-schema.org/draft-07/schema#'))
DRAFT202012_DIALECTS = frozenset(('https://json-schema.org/draft/2020-12/schema',
                                  'https://json-schema.org/draft/2020-12/schema#'))


class TraceError(ValueError):
    """Unsupported, malformed, missing or unsafe local capture input."""


def _unique(pairs: list[tuple[str, Any]]) -> dict:
    obj: dict[str, Any] = {}
    for k, v in pairs:
        if k in obj:
            raise TraceError('Duplicate JSON key in recorded message')
        obj[k] = v
    return obj


def _walk_limited(obj: Any, limit: int, max_array: int = 256) -> None:
    n = 0
    stack = [(obj, 0)]
    while stack:
        value, depth = stack.pop()
        n += 1
        if n > limit or depth > 32:
            raise TraceError('JSON message or schema exceeds safe complexity budget')
        if type(value) is dict:
            if len(value) > 1024:
                raise TraceError('JSON object too wide')
            stack.extend((v, depth + 1) for v in value.values())
        elif type(value) is list:
            if len(value) > max_array:
                raise TraceError('JSON array too wide for bounded validation')
            stack.extend((v, depth + 1) for v in value)


def _label(value: Any) -> str:
    """Do not echo arbitrary trace content in reports or logs."""
    if isinstance(value, str):
        # Treat user-supplied tool names as potentially sensitive. Preserve stable
        # correlation without emitting arbitrary names into public CI reports.
        return 'tool_sha256:' + hashlib.sha256(value.encode('utf-8')).hexdigest()[:16]
    return 'tool_identifier_redacted'


def _read_trace(path: Path) -> tuple[list[tuple[int, str, dict]], str]:
    path = path.expanduser().absolute()
    if path.is_symlink() or not path.is_file():
        raise TraceError('Trace must be an existing regular file, not a symlink')
    if path.stat().st_size > MAX_TRACE_BYTES:
        raise TraceError('Trace exceeds the 4 MiB local capture budget')
    raw = path.read_bytes()
    if not raw or len(raw) > MAX_TRACE_BYTES:
        raise TraceError('Trace must be nonempty and at most 4 MiB')
    trace_hash = hashlib.sha256(raw).hexdigest()
    records: list[tuple[int, str, dict]] = []
    for line, blob in enumerate(raw.splitlines(), 1):
        if not blob.strip():
            continue
        if len(blob) > MAX_LINE_BYTES or len(records) >= MAX_MESSAGES:
            raise TraceError('Trace line or message count exceeds safe budget')
        try:
            data = json.loads(blob.decode('utf-8'), object_pairs_hook=_unique,
                              parse_constant=lambda _: (_ for _ in ()).throw(TraceError('Nonfinite JSON number')))
        except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
            raise TraceError(f'Invalid UTF-8/JSON at line {line}') from exc
        if type(data) is not dict:
            raise TraceError(f'JSON-RPC message must be an object (line {line})')
        # A large legitimate tools/list is not a giant tool result. Index its
        # bounded declarations and defer schema inspection to invoked tools.
        # Any other message retains the smaller, original value budget.
        candidate = data.get('message', data)
        catalog = (type(candidate) is dict and type(candidate.get('result')) is dict
                   and type(candidate['result'].get('tools')) is list)
        _walk_limited(data, MAX_CATALOG_NODES if catalog else MAX_VALUE_NODES,
                      max_array=1024 if catalog else 256)
        session = data.get('session', 'default')
        if not isinstance(session, str) or not (1 <= len(session) <= 64):
            raise TraceError(f'Invalid session identifier on line {line}')
        # Optional client/server metadata is ignored; never trusted as attestation.
        msg = data.get('message', data)
        if type(msg) is not dict or msg.get('jsonrpc') != '2.0':
            raise TraceError(f'Expected a JSON-RPC 2.0 object (line {line})')
        if 'id' in msg and (type(msg['id']) not in (int, str) or len(str(msg['id'])) > 128):
            raise TraceError(f'Invalid JSON-RPC correlation ID (line {line})')
        records.append((line, session, msg))
    if not records:
        raise TraceError('Trace has no JSON-RPC records')
    return records, trace_hash


def _schema_capability(schema: Any) -> tuple[bool, str]:
    if type(schema) is not dict:
        return False, 'outputSchema is not a JSON Schema object'
    try:
        _walk_limited(schema, MAX_SCHEMA_NODES)
    except TraceError:
        return False, 'Schema exceeds bounded validation budget'
    dangerous = {'$dynamicRef', '$recursiveRef', '$id', '$anchor', '$dynamicAnchor',
                 'pattern', 'patternProperties', 'contentSchema'}
    root_dialect = schema.get('$schema', 'https://json-schema.org/draft/2020-12/schema')
    if root_dialect not in DRAFT7_DIALECTS | DRAFT202012_DIALECTS:
        return False, 'Unsupported root JSON Schema dialect'
    root_family = 'draft7' if root_dialect in DRAFT7_DIALECTS else '2020-12'
    stack = [schema]
    while stack:
        item = stack.pop()
        if type(item) is dict:
            if any(k in item for k in dangerous):
                return False, 'Schema contains unsupported remote/dynamic/regex keyword'
            dialect = item.get('$schema')
            if dialect is not None:
                if dialect not in DRAFT7_DIALECTS | DRAFT202012_DIALECTS:
                    return False, 'Unsupported JSON Schema dialect'
                family = 'draft7' if dialect in DRAFT7_DIALECTS else '2020-12'
                if family != root_family:
                    return False, 'Mixed JSON Schema dialects are not fully validated'
            ref = item.get('$ref')
            if ref is not None and (not isinstance(ref, str) or not ref.startswith(('#/$defs/', '#/definitions/')) or len(ref)>256):
                return False, 'Remote or non-local JSON pointer reference refused'
            # Formats are annotations by default, so cannot claim format-level checking.
            if 'format' in item:
                return False, 'Format assertion not enabled in bounded validator'
            stack.extend(item.values())
        elif type(item) is list:
            stack.extend(item)
    return True, ''


def _validate_schema(schema: dict, value: Any) -> tuple[str, dict | None]:
    try:
        from jsonschema import Draft202012Validator, Draft7Validator
        from jsonschema.exceptions import SchemaError
    except ImportError:
        return 'UNVERIFIED', {'reason':'jsonschema package is not installed'}
    validator_cls = Draft7Validator if schema.get('$schema') in DRAFT7_DIALECTS else Draft202012Validator
    try:
        validator_cls.check_schema(schema)
    except (SchemaError, RecursionError, ValueError):
        return 'DECLARATION_INVALID', {'reason':'Invalid Draft 2020-12 schema'}
    try:
        validator = validator_cls(schema)
        # Iterating only first error limits processing, while bounded schema/instance
        # nodes and disallowed costly regex/dynamic refs prevent common hazards.
        issue = next(validator.iter_errors(value), None)
        if issue is None:
            return 'PASS', None
        # Instance/property names may be secrets; emit only structural path
        # segments and the validator keyword. Do not echo raw values or keys.
        redacted_path='/'+'/'.join(str(p) if type(p) is int else '[key]' for p in issue.absolute_path)
        return 'MISMATCH', {'keyword':str(issue.validator or 'unknown')[:80],
                            'instance_path':redacted_path[:180],
                            'schema_path':'/[redacted]'}
    except (RecursionError, LookupError, ValueError, TypeError, KeyError) as exc:
        return 'UNVERIFIED', {'reason':'Schema validation could not safely complete ('+type(exc).__name__+')'}


def _reported_tool_error(result: dict) -> str:
    """Classify only recognizable *server-reported* failure text, never prove root cause."""
    content = result.get('content')
    if type(content) is not list or len(content) > 16:
        return 'EXECUTION_ERROR'
    messages = [item['text'] for item in content if type(item) is dict
                and item.get('type') == 'text' and type(item.get('text')) is str]
    text = ' '.join(messages).lower()
    if any(token in text for token in (
        'output validation error', 'output validation failed',
        'failed to validate tool output', 'tool output failed validation')):
        return 'REPORTED_OUTPUT_VALIDATION_REJECTION'
    if any(token in text for token in (
        'input validation error', 'input validation failed',
        'invalid tool arguments')):
        return 'REPORTED_INPUT_VALIDATION_REJECTION'
    return 'EXECUTION_ERROR'


def _check_behavior_contract(contract: dict | None) -> list[dict]:
    """User opt-in exact text contracts; tool names and values never echoed."""
    if contract is None:
        return []
    if type(contract) is not dict or set(contract) != {'schema', 'rules'}:
        raise TraceError('Behavior contract must contain only schema and rules')
    if contract['schema'] != 'risu-mcp-behavior-contract-v1':
        raise TraceError('Unsupported explicit behavior contract schema')
    rules = contract['rules']
    if type(rules) is not list or len(rules) > 64:
        raise TraceError('Behavior contract has too many rules')
    seen: set[str] = set()
    for rule in rules:
        if type(rule) is not dict or set(rule) != {'id','tool','when','text_equals'}:
            raise TraceError('Behavior rule has invalid fields')
        ident, tool, when, expected = (rule[k] for k in ('id','tool','when','text_equals'))
        if (type(ident) is not str or re.fullmatch(r'[A-Za-z0-9_-]{1,40}',ident) is None
                or ident in seen):
            raise TraceError('Behavior rule ID invalid or duplicate')
        seen.add(ident)
        if type(tool) is not str or not (1 <= len(tool) <= 128):
            raise TraceError('Behavior rule tool name invalid')
        if type(when) is not dict or not (1 <= len(when) <= 16):
            raise TraceError('Behavior rule requires bounded, nonempty argument preconditions')
        for key, value in when.items():
            if (type(key) is not str or len(key)>128
                    or type(value) not in (str,int,float,bool,type(None))
                    or (type(value) is str and len(value)>256)):
                raise TraceError('Behavior rule precondition must use short scalar fields')
        if type(expected) is not str or len(expected)>512:
            raise TraceError('Behavior rule must define bounded exact expected text')
    return rules


def _load_behavior_contract(path: Path) -> dict:
    path=path.expanduser().absolute()
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 32768:
        raise TraceError('Behavior contract must be a small regular file, not a symlink')
    try:
        data=json.loads(path.read_text(encoding='utf-8'),object_pairs_hook=_unique)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise TraceError('Invalid JSON behavior contract') from exc
    _check_behavior_contract(data)
    return data


def verify_trace(path: Path, protocol_version: str = 'unknown',
                 behavior_contract: dict | None = None,
                 display_contract: dict | None = None) -> dict:
    if protocol_version not in ALLOWED_PROTOCOLS:
        raise TraceError('Unsupported declared MCP protocol version')
    rules = _check_behavior_contract(behavior_contract)
    try:
        display_rules=validate_display_contract(display_contract) if display_contract is not None else []
    except DisplayContractError as exc:
        raise TraceError(str(exc)) from exc
    records, digest = _read_trace(path)
    # Keyed by session; a replay may multiplex requests and reuse IDs *sequentially*.
    sessions: dict[str, dict] = {}
    findings: list[dict] = []
    unverified: list[dict] = []
    checked = 0
    matched = 0
    successful_calls = 0
    call_requests = 0
    catalog_snapshots_indexed = 0
    catalog_pages_recorded = 0
    catalog_partial_chains = 0
    behavior_matched = 0
    behavior_checked = 0
    display_matched = 0
    display_checked = 0
    display_passed = 0
    def gap(code: str, reason: str, line: int, tool: str | None=None) -> None:
        if len(unverified)<256:
            row={'code':code,'reason':reason,'line':line}
            if tool is not None: row['tool']=_label(tool)
            unverified.append(row)
    def finding(code: str, reason: str, line: int, tool: str) -> None:
        if len(findings)<256:
            findings.append({'rule_id':code,'verdict':'OBSERVED_IN_UNATTESTED_CAPTURE',
                             'message':reason,'tool':_label(tool),'line':line})
    for line, session, msg in records:
        st=sessions.setdefault(session, {'pending':{},'tools':{},'ready':False,
            'invalid_ids':set(),'protocol':protocol_version,
            'protocol_source':'CALLER_DECLARED' if protocol_version!='unknown' else 'NOT_OBSERVED',
            'initialize_ids':set(),'negotiated_protocol':None,'validated_tools':set(),
            'catalog_chain':None})
        req_id = msg.get('id')
        method = msg.get('method')
        if method == 'notifications/tools/list_changed':
            st['ready']=False;st['tools']={};st['validated_tools']=set();st['catalog_chain']=None
            gap('CATALOG_INVALIDATED','Tool catalog changed; another complete tools/list needed',line)
            continue
        if method is not None:
            if method not in ('tools/list','tools/call'):
                # Initialize request/response is captured as actual protocol evidence.
                # Unlike a CLI --protocol-version flag, the response can establish
                # the negotiated protocol, conditional on the unauthenticated trace.
                if method=='initialize' and req_id is not None:
                    st['initialize_ids'].add(req_id)
                # Other JSON-RPC requests have responses with their own IDs.
                # Explicitly ignore those responses rather than count them as gaps.
                if req_id is not None:
                    if req_id in st['pending']:
                        st['pending'].pop(req_id,None)
                        st['invalid_ids'].add(req_id)
                        gap('AMBIGUOUS_REQUEST_ID','Unrelated request shares an outstanding tool request ID',line)
                    st.setdefault('other_ids',set()).add(req_id)
                continue
            if req_id is None:
                gap('REQUEST_WITHOUT_ID','Cannot correlate a tool request without an ID',line)
                continue
            if req_id in st.get('other_ids',set()) or req_id in st['pending']:
                st['invalid_ids'].add(req_id)
                st['pending'].pop(req_id,None)
                gap('AMBIGUOUS_REQUEST_ID','Multiple outstanding requests share an ID',line)
                continue
            if req_id in st['invalid_ids']:
                gap('AMBIGUOUS_REQUEST_ID','ID was previously reused concurrently',line)
                continue
            if method == 'tools/list':
                params=msg.get('params',{})
                if type(params) is not dict:
                    gap('MALFORMED_CATALOG_REQUEST','tools/list params must be an object',line)
                    st['ready']=False;st['catalog_chain']=None;st['tools']={}
                    continue
                cursor=params.get('cursor')
                if cursor is not None and (type(cursor) is not str or not (1<=len(cursor)<=MAX_CATALOG_CURSOR_LENGTH)):
                    gap('INVALID_CATALOG_CURSOR','tools/list cursor must be a bounded nonempty string',line)
                    st['ready']=False;st['catalog_chain']=None;st['tools']={}
                    continue
                st['pending'][req_id] = ('list', None, line, cursor)
            else:
                call_requests += 1
                params=msg.get('params')
                if type(params) is not dict or not isinstance(params.get('name'),str):
                    gap('MALFORMED_CALL_REQUEST','tools/call has no string tool name',line)
                    continue
                st['pending'][req_id] = ('call', params['name'], line, params.get('arguments'))
            continue
        if req_id is None or ('result' not in msg and 'error' not in msg):
            continue
        if req_id in st.get('other_ids',set()) and req_id not in st['pending']:
            st['other_ids'].discard(req_id)
            if req_id in st['initialize_ids']:
                st['initialize_ids'].discard(req_id)
                result=msg.get('result')
                negotiated=result.get('protocolVersion') if type(result) is dict else None
                st['negotiated_protocol']=negotiated if negotiated in ALLOWED_PROTOCOLS and negotiated!='unknown' else None
                if negotiated not in ALLOWED_PROTOCOLS or negotiated=='unknown':
                    st['protocol']='unknown'
                    st['protocol_source']='INIT_UNSUPPORTED'
                    gap('UNSUPPORTED_NEGOTIATED_PROTOCOL','Initialization response has unsupported/unknown protocol',line)
                elif protocol_version!='unknown' and protocol_version!=negotiated:
                    st['protocol']='unknown'
                    st['protocol_source']='DECLARED_NEGOTIATED_CONFLICT'
                    gap('PROTOCOL_VERSION_CONFLICT','Declared protocol disagrees with captured initialize response',line)
                else:
                    st['protocol']=negotiated
                    st['protocol_source']='CAPTURED_INITIALIZE_RESULT'
            continue
        if req_id in st['invalid_ids']:
            st['invalid_ids'].discard(req_id)
            continue
        previous=st['pending'].pop(req_id,None)
        if previous is None:
            gap('UNMATCHED_RESPONSE','Response has no matching captured request',line)
            continue
        kind, name, _req_line, call_args=previous
        if 'error' in msg or 'result' not in msg:
            gap('PROTOCOL_ERROR','JSON-RPC error response; tool execution semantics not assessed',line,name)
            if kind=='list':st['ready']=False;st['tools']={};st['catalog_chain']=None
            continue
        result=msg['result']
        if type(result) is not dict:
            gap('INVALID_RESULT_ENVELOPE','Tool response is not a JSON object',line,name)
            continue
        if kind=='list':
            # Only a cursor-complete, bounded catalog can authorize tool checks.
            tools=result.get('tools')
            next_cursor=result.get('nextCursor')
            if (type(tools) is not list or len(tools)>MAX_CATALOG_TOOLS
                    or (next_cursor is not None and
                        (type(next_cursor) is not str or
                         len(next_cursor)>MAX_CATALOG_CURSOR_LENGTH))):
                st['ready']=False;st['tools']={};st['catalog_chain']=None
                gap('INVALID_TOOLS_LIST','Malformed tools page or cursor beyond safe limits',line)
                continue
            if next_cursor=='': next_cursor=None
            chain=st['catalog_chain']
            if chain is None:
                if call_args is not None:
                    st['ready']=False;st['tools']={}
                    gap('ORPHAN_CATALOG_CURSOR','Continuation without an initial recorded tools/list page',line)
                    continue
                chain={'tools':{},'expected':None,'seen':set(),'pages':0,'start_line':line}
                st['ready']=False;st['tools']={};st['validated_tools']=set()
            elif call_args != chain['expected']:
                st['ready']=False;st['tools']={};st['catalog_chain']=None
                gap('CATALOG_CURSOR_MISMATCH','Continuation request did not use the prior opaque cursor',line)
                continue
            temp=chain['tools']
            valid=True
            for entry in tools:
                if (type(entry) is not dict or type(entry.get('name')) is not str
                        or not (1<=len(entry['name'])<=128)
                        or entry['name'] in temp):
                    valid=False;break
                temp[entry['name']]=entry
            chain['pages']+=1
            catalog_pages_recorded+=1
            if not valid:
                st['ready']=False;st['tools']={};st['catalog_chain']=None
                gap('INVALID_CATALOG','Duplicate or malformed tool declaration across catalog pages',line)
                continue
            if len(temp)>MAX_CATALOG_TOOLS or chain['pages']>MAX_CATALOG_PAGES:
                st['ready']=False;st['tools']={};st['catalog_chain']=None
                gap('CATALOG_COMPLEXITY_LIMIT','Multi-page catalog exceeds tool/page budget',line)
                continue
            if next_cursor is not None:
                if next_cursor in chain['seen']:
                    st['ready']=False;st['tools']={};st['catalog_chain']=None
                    gap('CATALOG_CURSOR_CYCLE','A recorded tools/list cursor was repeated; no complete catalog',line)
                    continue
                chain['seen'].add(next_cursor)
                chain['expected']=next_cursor
                st['catalog_chain']=chain
                continue
            st['tools']=dict(temp);st['ready']=True;st['validated_tools']=set()
            st['catalog_chain']=None
            catalog_snapshots_indexed += 1
            continue
        matched += 1
        if not st['ready']:
            gap('NO_COMPLETE_CATALOG','A complete tools/list response must precede this call',line,name)
            continue
        tool=st['tools'].get(name)
        if tool is None:
            gap('UNKNOWN_DECLARATION','Tool not in last complete catalog',line,name)
            continue
        if result.get('resultType','complete') != 'complete':
            gap('NONFINAL_TOOL_RESULT','Non-complete tool result not evaluated',line,name)
            continue
        is_error=result.get('isError',False)
        if type(is_error) is not bool:
            gap('INVALID_ERROR_FLAG','isError must be a boolean or absent',line,name)
            continue
        # Explicit source->presentation mappings work on real tool errors too.
        # Do this before isError short-circuits the success output schema checker.
        for rule in display_rules:
            if rule['tool'] != name or rule['on_error'] is not is_error:
                continue
            display_matched += 1
            verdict, reason = check_display(result,rule)
            if verdict == 'UNVERIFIED':
                gap(reason,'Explicit display mapping could not be assessed safely',line,name)
            else:
                display_checked += 1
                if verdict == 'PASS':
                    display_passed += 1
                else:
                    code='RMC507' if rule['mode']=='markdown-rendered' else 'RMC508'
                    finding(code,
                        'Explicit structured-to-display mapping does not preserve the declared scalar; rule_sha256:'+
                        display_rule_hash(rule['id']),line,name)
        if is_error:
            classification = _reported_tool_error(result)
            if classification == 'REPORTED_OUTPUT_VALIDATION_REJECTION':
                gap(classification, 'Server text reports output validation rejection; independent output mismatch not established', line, name)
            elif classification == 'REPORTED_INPUT_VALIDATION_REJECTION':
                gap(classification, 'Server text reports invalid input; no output contract violation inferred', line, name)
            else:
                gap('EXECUTION_ERROR','Tool reported isError=true; success output contract not asserted',line,name)
            continue
        successful_calls += 1
        # Opt-in behavior assertions operate on observed arguments + *one* text
        # response; no inference from tool names, no live execution, no raw values in report.
        for rule in rules:
            if rule['tool'] != name or type(call_args) is not dict:
                continue
            if not all(k in call_args and type(call_args[k]) is type(v)
                       and call_args[k] == v for k,v in rule['when'].items()):
                continue
            behavior_matched += 1
            content = result.get('content')
            if (type(content) is not list or len(content) != 1
                    or type(content[0]) is not dict or content[0].get('type') != 'text'
                    or type(content[0].get('text')) is not str):
                gap('BEHAVIOR_OUTPUT_UNAVAILABLE',
                    'Explicit text assertion cannot be checked against this result envelope',line,name)
                continue
            behavior_checked += 1
            if content[0]['text'] != rule['text_equals']:
                finding('RMC506',
                        'Recorded text violates opt-in user-declared behavioral expectation; rule_sha256:'+
                        hashlib.sha256(rule['id'].encode()).hexdigest()[:12],
                        line,name)
        if 'outputSchema' not in tool:
            gap('NO_OUTPUT_SCHEMA','The tool declared no outputSchema; no output type contract checked',line,name)
            continue
        schema=tool['outputSchema']
        valid,reason=_schema_capability(schema)
        if not valid:
            if reason=='outputSchema is not a JSON Schema object':
                finding('RMC503','Declared outputSchema is not a JSON Schema object',line,name)
            else:gap('UNSUPPORTED_SCHEMA',reason,line,name)
            continue
        if st['protocol'] in LEGACY_PROTOCOLS and schema.get('type')!='object':
            finding('RMC504','Legacy outputSchema must declare an object root',line,name)
            continue
        if 'structuredContent' not in result:
            # See MCP tools output schema MUST provide conforming structured output;
            # only apply to successful, *complete* calls.
            finding('RMC501','Successful tool call omitted structuredContent despite declared outputSchema',line,name)
            continue
        value=result['structuredContent']
        try:_walk_limited(value, MAX_VALUE_NODES)
        except TraceError:
            gap('OUTPUT_LIMIT','Structured output exceeds bounded validation limits',line,name)
            continue
        outcome, detail=_validate_schema(schema,value)
        if outcome=='PASS':checked+=1;st['validated_tools'].add(name)
        elif outcome=='MISMATCH':
            checked+=1;st['validated_tools'].add(name)
            path_info=' at '+(detail or {}).get('instance_path','/')
            finding('RMC502','structuredContent violates the declared outputSchema'+path_info,line,name)
        elif outcome=='DECLARATION_INVALID':
            finding('RMC503','Declared outputSchema is invalid Draft 2020-12 schema',line,name)
        else:
            gap('UNVERIFIED_SCHEMA_VALIDATION',(detail or {}).get('reason','Unable to validate schema'),line,name)
    for session, st in sessions.items():
        if st['catalog_chain'] is not None:
            catalog_partial_chains += 1
            gap('INCOMPLETE_CATALOG_PAGINATION',
                'Captured tools/list has nextCursor but not a fully matched terminal page',
                st['catalog_chain']['start_line'])
        for kind, name, request_line, _args in st['pending'].values():
            gap('MISSING_RESPONSE','Request lacks a corresponding captured response',request_line,name)
    # Do not conflate catalog metadata indexed with actual successful schema checks.
    latest_declarations = sum(len(st['tools']) for st in sessions.values() if st['ready'])
    latest_validated = sum(len(st['validated_tools']) for st in sessions.values() if st['ready'])
    status=('OBSERVED_MISMATCHES_IN_CAPTURE' if findings else
            'INCOMPLETE_MEANING_CHECK' if unverified else
            'CHECKED_NO_MISMATCHES' if checked else 'NOT_CHECKED')
    return {'schema':'risu-mcp-jsonrpc-trace-audit-v1','tool':'RISU Probe',
            'capture_status':'PARSED_BOUNDED_JSONRPC','capture_sha256':digest,
            'origin_integrity':'UNATTESTED_LOCAL_CAPTURE',
            'protocol_version':protocol_version,
            'session_protocols':[{'session_sha256':hashlib.sha256(name.encode()).hexdigest()[:16],
                                  'negotiated_protocol':st['negotiated_protocol'],
                                  'effective_protocol':st['protocol'],
                                  'evidence':st['protocol_source']}
                                 for name,st in sorted(sessions.items())],
            'semantic_verification':status,
            'source_analysis':'NOT_PERFORMED',
            'summary':{'messages_parsed':len(records),'sessions':len(sessions),
                       'tool_call_requests':call_requests,'tool_call_responses_matched':matched,
                       'successful_tool_calls_with_catalog':successful_calls,
                       'structured_values_schema_checked':checked,
                       'catalog_snapshots_indexed':catalog_snapshots_indexed,
                       'catalog_pages_recorded':catalog_pages_recorded,
                       'incomplete_catalog_chains':catalog_partial_chains,
                       'latest_catalog_declarations_indexed':latest_declarations,
                       'latest_catalog_declarations_schema_validated':latest_validated,
                       'latest_catalog_declarations_not_validated':max(0,latest_declarations-latest_validated),
                       'explicit_display_rules_declared':len(display_rules),
                       'explicit_display_rules_matched':display_matched,
                       'explicit_display_rules_checked':display_checked,
                       'explicit_display_rules_passed':display_passed,
                       'explicit_behavior_rules_declared':len(rules),
                       'explicit_behavior_assertions_matched':behavior_matched,
                       'explicit_behavior_assertions_checked':behavior_checked,
                       'findings':len(findings),
                       'unverified_count':len(unverified)},
            'findings':findings,'unverified':unverified,
            'coverage_note':'A parsed JSON-RPC trace is not a certified MCP session. Large catalogs are bounded and indexed only after all cursor-linked pages, not fully schema-validated; only actually invoked successful complete calls with supported outputSchema are checked.',
            'provenance_note':'This file is supplied by the user. JSON-RPC contents may be fabricated, truncated or altered; findings are observations in this capture only, not independently attested runtime incidents.',
            'safety':'No project imports, schema network fetches, subprocesses or server connections. No raw structuredContent values appear in the report.'}


def _text(report: dict) -> str:
    s=report['summary']
    lines=['RISU Probe MCP JSON-RPC trace | '+report['semantic_verification'],
           'Source analysis: NOT PERFORMED | Capture: '+report['capture_status'],
           'Origin: '+report['origin_integrity'],
           f"Matched calls: {s['tool_call_responses_matched']} | Schema checked: {s['structured_values_schema_checked']} | Findings: {s['findings']} | Unverified: {s['unverified_count']}"]
    lines += [v['rule_id']+' '+v['message']+' ('+v['tool']+')' for v in report['findings']]
    lines += ['The report concerns saved, unauthenticated capture contents; no live MCP execution was performed.']
    return '\n'.join(lines)+'\n'


def _sarif(report: dict) -> dict:
    return {'version':'2.1.0','$schema':'https://json.schemastore.org/sarif-2.1.0.json',
            'runs':[{'tool':{'driver':{'name':'RISU Probe','version':'0.9.25','rules':[
               {'id':code,'shortDescription':{'text':desc}} for code,desc in (
                ('RMC501','Missing successful structured output'),
                ('RMC502','Structured output violates declared schema'),
                ('RMC503','Invalid declared output schema'),
                ('RMC504','Legacy output schema lacks object root'),
                ('RMC506','Violation of explicit caller-supplied text behavior contract'),
                ('RMC507','Declared structured value disagrees with rendered CommonMark text'),
                ('RMC508','Declared structured value disagrees with copied raw/code-span text'))]}},
             'results':[{'ruleId':f['rule_id'],'level':'error','message':{'text':f['message']},
                         'properties':{'origin_integrity':report['origin_integrity'],'tool':f['tool'],'trace_line':f['line']}} for f in report['findings']],
             'properties':{'semantic_verification':report['semantic_verification'],
                           'source_analysis':'NOT_PERFORMED','summary':report['summary'],
                           'unverified':report['unverified']}}]}


def cli(argv: list[str] | None=None) -> int:
    p=argparse.ArgumentParser(prog='risu-probe verify-mcp-trace',
        description='Read saved, untrusted JSON-RPC JSONL. No code or MCP server execution.')
    p.add_argument('trace',type=Path,help='Local JSONL containing captured JSON-RPC requests and responses')
    p.add_argument('--protocol-version',choices=ALLOWED_PROTOCOLS,default='unknown',
                   help='Declared captured protocol version (not independently attested)')
    p.add_argument('--format',choices=('json','text','sarif'),default='text')
    p.add_argument('--display-contract',type=Path,
                   help='Opt-in structuredContent JSON-pointer to text-prefix display/copy assertions')
    p.add_argument('--behavior-contract',type=Path,
                   help='Optional safe JSON contract of explicit argument-conditioned text assertions')
    p.add_argument('--out',type=Path,help='Write a new report without overwrite')
    p.add_argument('--fail-on-observed',action='store_true',
                   help='Opt-in CI failure (1) for recorded discrepancies, not proof of live incidence')
    p.add_argument('--strict-incomplete',action='store_true',
                   help='Fail (2) if any tool assessment is incomplete')
    a=p.parse_args(argv)
    try:
        report=verify_trace(a.trace,a.protocol_version,
                            _load_behavior_contract(a.behavior_contract) if a.behavior_contract else None,
                            load_display_contract(a.display_contract) if a.display_contract else None)
        output=_text(report) if a.format=='text' else json.dumps(report if a.format=='json' else _sarif(report),indent=2,sort_keys=True,ensure_ascii=False)+'\n'
        if a.out:
            path=a.out.expanduser()
            if path.exists() or path.is_symlink():
                raise TraceError('Output path already exists; refusing overwrite')
            path.parent.mkdir(parents=True,exist_ok=True)
            with path.open('x',encoding='utf-8') as f:f.write(output)
        else:print(output,end='')
        if a.strict_incomplete and report['summary']['unverified_count']:
            return 2
        if a.fail_on_observed and report['summary']['findings']:
            return 1
        return 0
    except (TraceError, DisplayContractError, OSError, UnicodeError, ValueError, TypeError, RecursionError) as e:
        print('RMC500 INVALID_OR_UNSUPPORTED_MCP_TRACE: '+str(e)[:240]+
              '\nNext: supply a local UTF-8 JSONL trace of matched JSON-RPC tools/list and tools/call messages; no secrets or production data.',file=sys.stderr)
        return 2


if __name__=='__main__':
    raise SystemExit(cli())
