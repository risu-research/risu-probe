#!/usr/bin/env python3
"""RISU Probe: find machine-readable data lost across HTTP API -> MCP boundary.

Experimental consumer utility, not MCP conformance certification. Python 3.11+ stdlib.
Live calls run only against an explicit loopback HTTP base by default.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
import queue
import subprocess
from risu_process import spawn_stdio, stop_stdio, write_with_timeout
import sys
import threading
import time
from pathlib import Path
from risu_report import emit as emit_report
from risu_diagnostics import detect as detect_diagnostics
from risu_evidence import assess as assess_evidence
from risu_decision import apply as apply_decisions, any_blocking, decide
from risu_plan import plan_cli
from risu_project import resolve_config, load_cases, resolve_argv, ConfigError
from risu_contract import resolve as resolve_pointer, validate_paths, segments, ContractError
from risu_baseline import load_baseline, mark_baseline, BaselineError, cli as baseline_cli
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse, parse_qsl
from urllib.request import Request, build_opener, HTTPRedirectHandler

VERSION = '0.9.20-experimental'
PROBLEM = 'application/problem+json'
MODERN = '2026-07-28'
LEGACY = '2025-11-25'
MAX_BYTES = 1_048_576


class ProbeError(Exception):
    pass


def media(value):
    return str(value or '').split(';', 1)[0].strip().lower()


def path_of(path):
    if not path:
        return '/'
    def guard(part):
        part=str(part)
        # JSON object keys are user-controlled data and sometimes include PII.
        # Names that resemble sensitive values are hashed in exported paths.
        if len(part)>48 or any(c in part for c in ('@','\n','\r','\x00')):
            part='[key:'+hashlib.sha256(part.encode('utf-8')).hexdigest()[:12]+']'
        return part.replace('~','~0').replace('/','~1')
    return '/' + '/'.join(guard(p) for p in path)


def _diff(source, target, path=()):
    """Bounded iterative loss checker; prevents deep recursive crashes.

    Source keys must survive with exact values. New target fields do not by
    themselves establish semantic invention; those need a dedicated rule.
    """
    issues=[]
    stack=[(source,target,path,0)]
    visited=0
    while stack:
        left,right,position,depth=stack.pop()
        visited += 1
        if visited > 20000 or depth > 64:
            raise ProbeError('comparison node/depth limit exceeded (20000 nodes / 64 levels)')
        if isinstance(left,dict):
            if not isinstance(right,dict):
                issues.append(path_of(position)+' (type changed)')
                continue
            for key,val in reversed(list(left.items())):
                if key not in right:
                    issues.append(path_of(position+(key,))+' (missing)')
                else:
                    stack.append((val,right[key],position+(key,),depth+1))
        elif isinstance(left,list):
            if not isinstance(right,list):
                issues.append(path_of(position)+' (array replaced)')
                continue
            if len(left)!=len(right):
                issues.append(path_of(position)+f' (array length {len(left)} -> {len(right)})')
            for i in reversed(range(min(len(left),len(right)))):
                stack.append((left[i],right[i],position+(i,),depth+1))
        elif type(left) is not type(right) or left != right:
            issues.append(path_of(position)+' (value changed)')
    return issues


def _walk(value):
    stack=[(value,0)]
    seen=0
    while stack:
        current,depth=stack.pop()
        seen += 1
        if seen>20000 or depth>64:
            raise ProbeError('JSON observation traversal exceeded safety limits')
        yield current
        if isinstance(current,dict):
            stack.extend((v,depth+1) for v in reversed(list(current.values())))
        elif isinstance(current,list):
            stack.extend((v,depth+1) for v in reversed(current))

def _problem_objects(mcp):
    candidates=[]
    for container in (mcp.get('structuredContent'), mcp.get('_meta')):
        if container is not None:
            candidates.extend(node for node in _walk(container) if isinstance(node, dict))
    for chunk in mcp.get('content') or []:
        if not isinstance(chunk, dict) or chunk.get('type') != 'resource':
            continue
        resource=chunk.get('resource') or {}
        if not isinstance(resource, dict) or media(resource.get('mimeType')) != PROBLEM:
            continue
        try:
            val=json.loads(resource.get('text', ''))
        except (TypeError, ValueError):
            continue
        if isinstance(val, dict):
            candidates.append(val)
    return candidates


def _json_error_objects(mcp,mime):
    # Only explicitly machine-readable carriers can satisfy a JSON error contract.
    candidates=[]
    if 'structuredContent' in mcp:
        candidates.append(mcp['structuredContent'])
    # Only dict subtrees can carry a semantic nested object error.
    if isinstance(mcp.get('structuredContent'),(dict,list)):
        candidates.extend(node for node in _walk(mcp['structuredContent']) if isinstance(node,dict))
    if isinstance(mcp.get('_meta'),(dict,list)):
        candidates.extend(node for node in _walk(mcp['_meta']) if isinstance(node,dict))
    for chunk in mcp.get('content') or []:
        if not isinstance(chunk,dict) or chunk.get('type')!='resource':
            continue
        resource=chunk.get('resource') or {}
        if not isinstance(resource,dict) or media(resource.get('mimeType'))!=mime:
            continue
        try:
            candidates.append(json.loads(resource.get('text','')))
        except (TypeError,ValueError):
            continue
    return candidates


def _success_objects(mcp):
    candidates=[]
    if 'structuredContent' in mcp:
        # Compare the top-level declared JSON value. Matching an arbitrary nested
        # scalar could incorrectly mark a transformed result as preserved.
        candidates.append(mcp['structuredContent'])
    for chunk in mcp.get('content') or []:
        if not isinstance(chunk, dict) or chunk.get('type') != 'resource':
            continue
        resource=chunk.get('resource') or {}
        if not isinstance(resource, dict) or media(resource.get('mimeType')) != 'application/json':
            continue
        try:
            candidates.append(json.loads(resource.get('text', '')))
        except (TypeError, ValueError):
            continue
    return candidates


def _observed_status(mcp):
    names={'observed_http_status', 'httpStatus', 'http_status', 'statusCode', 'status_code'}
    for item in _walk(mcp.get('_meta') or {}):
        if not isinstance(item, dict):
            continue
        for k, v in item.items():
            if k in names and type(v) is int and 100 <= v <= 599:
                return v
    return None


def _new_claims(mcp, source):
    # Minimal, bounded claims: flag only explicitly invented boolean retry guarantees
    # outside the original source payload; never infer intent from HTTP status/prose.
    truthy={'retryable', 'safeToRetry', 'safe_to_retry', 'idempotent_retry'}
    source_values=set()
    for node in _walk(source.get('body')):
        if not isinstance(node, dict):
            continue
        for k, v in node.items():
            if k in truthy and v is True:
                source_values.add(k)
    claims=set()
    for root in (mcp.get('structuredContent') or {}, mcp.get('_meta') or {}):
        for node in _walk(root):
            if not isinstance(node, dict):
                continue
            for k, v in node.items():
                if k in truthy and v is True and k not in source_values:
                    claims.add(k)
    return sorted(claims)


def _has_untyped_error_promoted(mcp):
    for chunk in mcp.get('content') or []:
        if isinstance(chunk,dict) and chunk.get('type') == 'resource' and media((chunk.get('resource') or {}).get('mimeType')) == PROBLEM:
            return True
    return False


def compare(source, mcp, case_id='case', *, required_paths=None, target_root=None, error_profile='problem-only'):
    """Bounded, runtime-observation comparison. Does not prove generic equivalence."""
    try:
        status=source['status']
        mime=media(source['content_type'])
        body=source['body']
        if type(status) is not int or not 100 <= status <= 599 or not isinstance(mcp, dict):
            raise ValueError('status or MCP result invalid')
    except (KeyError, TypeError, ValueError) as e:
        raise ProbeError('bad source or MCP response: ' + str(e)) from e
    # Modern MCP may return an intermediate MRTR request. No tool result exists yet.
    # Never blame a translation for data loss at an unfinished tool invocation.
    if mcp.get('resultType') == 'input_required':
        return {'evidence_v1':assess_evidence(source,mcp),
                'id':case_id, 'verdict':'INPUT_REQUIRED', 'source_http_status':status,
                'media_type':mime, 'losses':[], 'inventions':[],
                'note':'MCP result requires another client round-trip; no final result was compared'}
    if mcp.get('resultType') not in (None,'complete'):
        return {'evidence_v1':assess_evidence(source,mcp),
                'id':case_id, 'verdict':'ERROR', 'source_http_status':status,
                'media_type':mime, 'losses':['unsupported MCP resultType'], 'inventions':[]}
    # Consumer contracts are an opt-in narrower assertion. This intentionally
    # says which fields matter instead of declaring general equivalence.
    if required_paths is not None:
        try:
            validate_paths(required_paths)
        except ContractError as exc:
            raise ProbeError(str(exc)) from exc
    if target_root is not None:
        try:
            segments(target_root)
        except ContractError as exc:
            raise ProbeError('invalid target_root: ' + str(exc)) from exc
    if error_profile not in ('problem-only', 'json-errors'):
        raise ProbeError('error_profile must be problem-only or json-errors')
    json_error = (error_profile == 'json-errors' and status >= 400
                  and (mime == 'application/json' or mime.endswith('+json')))
    errors=[]
    invented=[]
    if not (mime == PROBLEM or json_error or (200 <= status < 300 and mime == 'application/json')):
        if _has_untyped_error_promoted(mcp):
            invented.append('non-Problem response was relabeled application/problem+json')
        if status >= 400 and mcp.get('isError') is not True:
            errors.append('upstream failed but MCP result is not isError=true')
        if 200 <= status < 300 and mcp.get('isError') is True:
            errors.append('upstream succeeded but MCP result declares an error')
        verdict='LOSS_AND_INVENTED' if errors and invented else ('LOSS' if errors else ('INVENTED' if invented else 'NOT_APPLICABLE'))
        return {'id':case_id, 'verdict':verdict, 'source_http_status':status, 'media_type':mime,
                'losses':errors, 'inventions':invented, 'note':'error-flag only; non-Problem payload outside this profile',
                'evidence_v1':assess_evidence(source,mcp,consumer_scoped=(required_paths is not None or target_root is not None))}

    if mime == PROBLEM or json_error:
        if mime == PROBLEM and not isinstance(body, dict):
            raise ProbeError('Problem Details body must be an object')
        if mime == PROBLEM:
            candidates=_problem_objects(mcp)
            label='problem body'
        else:
            candidates=_json_error_objects(mcp,mime)
            label='JSON error body'
    else:
        candidates=_success_objects(mcp)
        label='successful JSON'
    if target_root is not None:
        located=[]
        for candidate in candidates:
            found, nested=resolve_pointer(candidate,target_root)
            if found:
                located.append(nested)
        candidates=located
    if required_paths is not None:
        for pointer in required_paths:
            found, _ = resolve_pointer(body,pointer)
            if not found:
                raise ProbeError(f'consumer contract references source field absent at {pointer}')
        differences=[]
        for candidate in candidates:
            issues=[]
            for pointer in required_paths:
                _, src=resolve_pointer(body,pointer)
                found, tgt=resolve_pointer(candidate,pointer)
                if not found:
                    issues.append(pointer + ' (required consumer field missing)')
                else:
                    issues.extend(_diff(src,tgt,tuple(segments(pointer))))
            differences.append(issues)
    else:
        differences=[_diff(body, candidate) for candidate in candidates]
    if not candidates:
        errors.append(f'{label} missing from structuredContent, _meta, or typed embedded resource; text alone is diagnostic')
    else:
        best=min(differences, key=lambda d: (len(d), sum(len(s) for s in d)))
        errors.extend(best[:30])
        if len(best) > 30:
            errors.append(f'... {len(best)-30} additional paths')
    obs_status=_observed_status(mcp)
    if obs_status != status and (mime == PROBLEM or json_error):
        errors.append('observed upstream HTTP status unavailable' if obs_status is None
                      else f'observed upstream HTTP status changed: {status} -> {obs_status}')
    if status >= 400 and mcp.get('isError') is not True:
        errors.append('upstream failed but MCP result is not isError=true')
    if 200 <= status < 300 and mcp.get('isError') is True:
        errors.append('upstream succeeded but MCP result declares an error')
    invented=_new_claims(mcp,source)
    verdict='INVENTED' if invented else ('LOSS' if errors else 'PRESERVED')
    if invented and errors:
        verdict='LOSS_AND_INVENTED'
    entry={'id':case_id,'verdict':verdict,'source_http_status':status,'media_type':mime,
           'losses':errors,'inventions':invented,
           'note':'Runtime sample only; equivalent observation depends on source stability'}
    if required_paths is not None:
        entry['scope']='consumer'
        entry['checked_paths']=list(required_paths)
        entry['note']='Consumer-scoped check ONLY; unchecked fields may be lost. Runtime sample only.'
    if target_root is not None:
        entry['target_root']=target_root
    if status >= 400 and (mime == PROBLEM or json_error) and verdict in ('LOSS','LOSS_AND_INVENTED'):
        entry['diagnostics'] = detect_diagnostics(source,mcp,verdict=verdict)
    entry['evidence_v1'] = assess_evidence(source,mcp,consumer_scoped=(required_paths is not None or target_root is not None))
    return entry


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ProbeError('upstream redirects refused')


def get_http(base_url, path, *, allow_remote=False):
    parsed=urlparse(base_url)
    if parsed.scheme not in ('http','https') or parsed.username or parsed.password or not parsed.netloc:
        raise ProbeError('invalid upstream base URL')
    if not allow_remote and parsed.hostname not in ('localhost','127.0.0.1','::1'):
        raise ProbeError('remote upstream disabled; --allow-remote must be explicit')
    if not isinstance(path,str) or not path.startswith('/') or path.startswith('//') or len(path)>4096:
        raise ProbeError('source path must be a safe absolute path')
    path_only,sep,query=path.partition('?')
    if '..' in path_only.split('/') or '#' in path or '?' in query:
        raise ProbeError('unsafe path/query')
    if sep:
        try:
            pairs=parse_qsl(query,keep_blank_values=True,strict_parsing=True,max_num_fields=64)
        except ValueError as e:
            raise ProbeError('invalid query parameters') from e
        if not pairs or any(any(ord(c)<32 for c in k+v) for k,v in pairs):
            raise ProbeError('invalid or unsafe query parameters')
    if parsed.query or parsed.fragment:
        raise ProbeError('query/fragment in base URL not supported')
    req=Request(base_url.rstrip('/')+path, method='GET',headers={'Accept':'application/json, application/problem+json'})
    try:
        resp=build_opener(NoRedirect()).open(req,timeout=5)
    except HTTPError as e:
        resp=e
    except URLError as e:
        raise ProbeError('upstream unavailable: '+str(e.reason)) from e
    with resp:
        raw=resp.read(MAX_BYTES+1)
        if len(raw) > MAX_BYTES:
            raise ProbeError('upstream response exceeds 1 MiB')
        try:
            payload=json.loads(raw.decode('utf-8'))
        except (UnicodeError, ValueError):
            payload=None
        return {'status':resp.status,'content_type':resp.headers.get('Content-Type',''), 'body':payload}


class MCPClient:
    """Small stdio test client, explicit argv, no shell, bounded waits."""
    def __init__(self, argv, *, protocol='modern', env=None):
        if not isinstance(argv,list) or not argv or not all(isinstance(s,str) and s for s in argv):
            raise ProbeError('server command must be a JSON array of nonempty strings')
        self.argv=argv
        self.env=env
        self.protocol=protocol
        self.messages=queue.Queue()
        self.proc=None
        self.counter=0

    def _spawn(self):
        self.messages=queue.Queue()
        self.proc=spawn_stdio(self.argv,env=self.env)
        def reader(out, incoming):
            for line in out:
                try:
                    incoming.put(json.loads(line))
                except ValueError:
                    incoming.put({'_invalid_line':line[:200]})
            incoming.put(None)
        threading.Thread(target=reader,args=(self.proc.stdout,self.messages),daemon=True).start()

    def _initialize_legacy(self):
        self.protocol='legacy'
        self.request('initialize',{'protocolVersion':LEGACY,'capabilities':{},
                                   'clientInfo':{'name':'risu-probe','version':VERSION}}, with_meta=False)
        self.notify('notifications/initialized',{})

    def __enter__(self):
        self._spawn()
        try:
            if self.protocol == 'legacy':
                self._initialize_legacy()
            elif self.protocol == 'modern':
                response=self.request('server/discover',{})
                if MODERN not in response.get('supportedVersions',[]):
                    raise ProbeError('modern MCP server/discover did not advertise protocol version')
            elif self.protocol == 'auto':
                self.protocol='modern'
                try:
                    # Avoid a false legacy downgrade under a briefly busy host.
                    response=self.request('server/discover',{},timeout=5.0)
                    if MODERN not in response.get('supportedVersions',[]):
                        raise ProbeError('modern revision not advertised')
                except ProbeError:
                    # A handshake-era server may reject modern discovery.
                    # Restart: do not reuse old queues or protocol state.
                    self.__exit__(None,None,None)
                    self._spawn()
                    self._initialize_legacy()
            else:
                raise ProbeError('protocol must be auto, modern, or legacy')
            return self
        except BaseException:
            self.__exit__(None,None,None)
            raise

    def __exit__(self,*_):
        if self.proc:
            proc, self.proc = self.proc, None
            stop_stdio(proc)

    def _send(self, data, *, timeout=8.0):
        line=json.dumps(data,separators=(',',':'),ensure_ascii=False)+'\n'
        try:
            write_with_timeout(self.proc, line, timeout)
        except TimeoutError as e:
            raise ProbeError('MCP subprocess stdin write timed out') from e
        except ValueError as e:
            raise ProbeError(str(e)) from e
        except (OSError, BrokenPipeError) as e:
            raise ProbeError('MCP process ended before request') from e

    def notify(self,method,params):
        self._send({'jsonrpc':'2.0','method':method,'params':params})

    def request(self,method,params,*,with_meta=True, timeout=8.0):
        self.counter +=1
        rid=self.counter
        params=copy.deepcopy(params)
        if self.protocol=='modern' and with_meta:
            params['_meta']={'io.modelcontextprotocol/protocolVersion':MODERN,
                             'io.modelcontextprotocol/clientCapabilities':{},
                             'io.modelcontextprotocol/clientInfo':{'name':'risu-probe','version':VERSION}}
        deadline=time.monotonic()+timeout
        self._send({'jsonrpc':'2.0','id':rid,'method':method,'params':params},
                   timeout=max(0.01,deadline-time.monotonic()))
        while True:
            remaining=deadline-time.monotonic()
            if remaining <= 0:
                raise ProbeError(f'MCP request {method} timed out')
            try:
                resp=self.messages.get(timeout=remaining)
            except queue.Empty as e:
                raise ProbeError(f'MCP request {method} timed out') from e
            if resp is None:
                raise ProbeError('MCP server closed stdout')
            if not isinstance(resp,dict):
                raise ProbeError('MCP server returned a non-object JSON response')
            if '_invalid_line' in resp:
                raise ProbeError('MCP stdout includes non-JSON output: '+resp['_invalid_line'])
            if resp.get('id')!=rid:  # notification from server
                continue
            if 'error' in resp:
                raise ProbeError(f'MCP {method} returned JSON-RPC error: {resp["error"]}')
            if not isinstance(resp.get('result'),dict):
                raise ProbeError('MCP response missing result object')
            return resp['result']

    def list_tools_catalog(self):
        """Full paginated tools/list metadata for reviewed auto-mapping.

        Unlike list_tools(), this retains schemas and annotations. No tool call
        is sent by catalog discovery, but launching servers still needs consent.
        """
        catalog={}
        cursors=set()
        cursor=None
        for _ in range(100):
            params={'cursor':cursor} if cursor is not None else {}
            response=self.request('tools/list',params)
            tools=response.get('tools')
            if not isinstance(tools,list):
                raise ProbeError('MCP tools/list returned no tools array')
            for tool in tools:
                if not isinstance(tool,dict) or not isinstance(tool.get('name'),str) or not tool['name']:
                    raise ProbeError('invalid MCP tool in tools/list response')
                name=tool['name']
                if name in catalog:
                    raise ProbeError('duplicate tool name across MCP catalog pages')
                catalog[name]=tool
                if len(catalog)>10000:
                    raise ProbeError('tool catalog exceeded 10000-name guard')
            cursor=response.get('nextCursor')
            if cursor is None:
                return catalog
            if not isinstance(cursor,str) or not cursor or cursor in cursors:
                raise ProbeError('invalid or repeating tools/list pagination cursor')
            cursors.add(cursor)
        raise ProbeError('MCP tools/list exceeded 100-page guard')

    def list_tools(self):
        return set(self.list_tools_catalog())

    def call(self,name,args):
        return self.request('tools/call',{'name':name,'arguments':args})


def run_cases(cases, *, upstream=None, server_cmd=None, protocol='auto', allow_remote=False, recheck_source=False, verify_catalog=True, error_profile='problem-only', policy='calibrated'):
    items=[]
    client=None
    catalog=None
    catalog_error=None
    try:
        if server_cmd is not None:
            client=MCPClient(server_cmd,protocol=protocol)
            client.__enter__()
            protocol=client.protocol
            if verify_catalog:
                try:
                    catalog = client.list_tools()
                except ProbeError as e:
                    catalog_error = str(e)
        for case in cases:
            ident=case.get('id','unnamed')
            try:
                if catalog_error is not None and 'mcp_result' not in case:
                    items.append({'id':ident,'verdict':'INVALID_CATALOG','losses':[catalog_error],
                                  'inventions':[], 'note':'MCP tools/list preflight could not complete'})
                    continue
                if (catalog is not None and 'mcp_result' not in case
                        and case.get('tool') not in catalog):
                    items.append({'id':ident,'verdict':'MISSING_TOOL',
                                  'losses':[f"MCP tools/list has no tool named {case.get('tool')!r}"],
                                  'inventions':[], 'note':'target tool missing; no tool/call sent'})
                    continue

                if 'source' in case and 'response' in case['source']:
                    source=case['source']['response']
                elif upstream and 'source' in case:
                    if case['source'].get('method','GET').upper()!='GET':
                        raise ProbeError('only GET source probes are supported')
                    source=get_http(upstream,case['source']['path'],allow_remote=allow_remote)
                else:
                    raise ProbeError('source.response or --upstream and source.path required')
                if 'mcp_result' in case:
                    result=case['mcp_result']
                elif client:
                    result=client.call(case['tool'],case.get('arguments',{}))
                else:
                    raise ProbeError('mcp_result or --server-json required')
                if recheck_source and upstream and 'source' in case and 'response' not in case['source']:
                    second=get_http(upstream,case['source']['path'],allow_remote=allow_remote)
                    if second!=source:
                        items.append({'id':ident,'verdict':'UNSTABLE_SOURCE','losses':[],
                                      'inventions':[], 'note':'Original API changed between observations; cannot reliably attribute differences to MCP'})
                        continue
                items.append(compare(source,result,ident,required_paths=case.get('required_paths'),
                                     target_root=case.get('target_root'), error_profile=case.get('error_profile',error_profile)))
            except (ProbeError, KeyError, ValueError) as e:
                items.append({'id':ident,'verdict':'ERROR','losses':[str(e)],'inventions':[]})
    finally:
        if client:
            client.__exit__(None,None,None)
    summary={v:sum(r['verdict']==v for r in items) for v in
             ('PRESERVED','LOSS','INVENTED','LOSS_AND_INVENTED','NOT_APPLICABLE','UNSTABLE_SOURCE','ERROR','MISSING_TOOL','INVALID_CATALOG','INPUT_REQUIRED')}
    codes={}
    for item in items:
        for finding in item.get('diagnostics',[]):
            code=finding.get('code')
            if isinstance(code,str): codes[code]=codes.get(code,0)+1
    return apply_decisions({'tool':'RISU Probe','version':VERSION,'protocol':protocol,
            'summary':summary,'diagnostic_summary':codes,'results':items},policy)


def remedy_for(item):
    evidence=item.get('evidence_v1') or {}
    if evidence.get('error_flag') in ('ERROR_FLAG_LOST','SPURIOUS_ERROR_FLAG'):
        return 'Correct the MCP isError flag independently of body transport.'
    if evidence.get('body_recovery')=='EXACT_JSON_TEXT':
        return 'Original JSON was verified in text. Structured-only consumers still need structuredContent; avoid claiming actual body deletion.'
    if evidence.get('machine_carrier')=='METADATA_ONLY_EXACT':
        return 'Body exists only in _meta; confirm consumer access and contract before calling this preserved.'
    losses='\n'.join(item.get('losses',[]))
    if any(d.get('code')=='TRUNCATED_UPSTREAM_ERROR' for d in item.get('diagnostics', [])):
        return 'A source JSON prefix and clipping marker prove a truncated error preview. Prefer an opt-in, bounded typed carrier for authorized fields; do not expose secrets by default.'
    if 'problem body missing' in losses:
        return 'Preserve the original RFC 9457 object in structuredContent or a typed application/problem+json embedded resource.'
    if 'successful JSON missing' in losses:
        return 'Keep the original JSON available under structuredContent; a human-readable text copy alone is insufficient for this check.'
    if 'observed upstream HTTP status' in losses:
        return 'Record the observed HTTP status in machine-readable result _meta, separately from any body.status.'
    if item.get('inventions'):
        return 'Remove retry/idempotency guarantees that are not supported by source data; inspect how target metadata is generated.'
    if 'not isError=true' in losses:
        return 'Return isError=true for upstream tool execution failures.'
    if losses:
        return 'Compare the listed JSON Pointer paths and preserve the source data types, values, and array structure.'
    return None


def render_text(report):
    lines=[]
    for item in report['results']:
        verdict=item['verdict']
        decision=item.get('decision_v1') or decide(item)
        lines.append(f"{decision['outcome']:8} {item['id']} [legacy:{verdict} reason:{decision['reason']}]" +
                     (f' [baseline:{item["baseline"]}]' if item.get('baseline') in ('known','new') else '') +
                     (' [consumer-scope]' if item.get('scope')=='consumer' else ''))
        for loss in item['losses']:
            lines.append(f'  strict-carrier finding: {loss}')
        for invention in item['inventions']:
            lines.append(f'  invented: {invention}')
        for d in item.get('diagnostics', []):
            detail = f"  diagnosis: {d['code']}"
            if d['code']=='TRUNCATED_UPSTREAM_ERROR':
                detail += f" (source {d['source_chars']} chars, retained prefix {d['prefix_chars']} chars)"
                c=d.get('collection')
                if c: detail+=f" (complete JSON pointers {c['visible_complete_pointer_count']}/{c['source_pointer_count']})"
            lines.append(detail)
        remedy=remedy_for(item)
        if remedy:
            lines.append(f'  fix: {remedy}')
    s=report['summary']
    lines.extend(['',f'Checked {len(report["results"])} cases: '+', '.join(f'{v} {n}' for v,n in s.items() if n),
                  'Runtime samples only; no claim of general MCP conformance or production safety.'])
    return '\n'.join(lines)



def check_project(argv):
    """One-command, project-scoped workflow. Offline runs need no opt-in.

    Live MCP server subprocesses require --allow-exec; the case file contains
    explicit requests, and live HTTP remains loopback-only unless --allow-remote.
    """
    p = argparse.ArgumentParser(description='Check a project using risu-probe.json')
    p.add_argument('project', nargs='?', default='.', help='project directory or config file')
    p.add_argument('--allow-exec', action='store_true', help='run configured MCP subprocess (review it first)')
    p.add_argument('--allow-remote', action='store_true')
    p.add_argument('--format', choices=('text', 'json', 'sarif', 'markdown'), default='text')
    p.add_argument('--out', type=Path, help='write report in --format representation')
    p.add_argument('--min-covered', type=int, default=1, help='minimum analyzed cases (default 1)')
    p.add_argument('--policy',choices=('calibrated','strict-carrier'),default='calibrated')
    p.add_argument('--fail-on-review',action='store_true',help='opt into blocking uncertain or deferred cases')
    p.add_argument('--error-profile', choices=('problem-only','json-errors'), help='override project error profile')
    p.add_argument('--baseline', type=Path, help='existing known-findings file; expires automatically')
    p.add_argument('--fail-new-only', action='store_true', help='fail on new findings and probe errors; requires --baseline')
    args=p.parse_args(argv)
    try:
        if args.fail_new_only and not args.baseline:
            raise ProbeError('--fail-new-only requires --baseline')
        conf_path, config=resolve_config(args.project)
        cases, origin=load_cases(conf_path, config)
        cmd=resolve_argv(conf_path, config)
        if cmd and not args.allow_exec:
            raise ProbeError('live server command requires --allow-exec; review risu-probe.json first')
        upstream=config.get('upstream')
        protocol=config.get('protocol', 'auto')
        if protocol not in ('auto', 'modern', 'legacy'):
            raise ProbeError('protocol must be auto, modern or legacy')
        report=run_cases(cases, upstream=upstream, server_cmd=cmd,
                         protocol=protocol, allow_remote=args.allow_remote,
                         recheck_source=bool(config.get('recheck_source', True)),
                         verify_catalog=True, error_profile=(args.error_profile or config.get('error_profile','problem-only')),
                         policy=args.policy)
        if args.baseline:
            mark_baseline(report,load_baseline(args.baseline))
        covered=sum(report['summary'].get(v,0) for v in ('PRESERVED','LOSS','INVENTED','LOSS_AND_INVENTED'))
        shortfall=covered < args.min_covered
        if args.format == 'text':
            output=render_text(report)+'\n'
            if shortfall:
                output += f'INSUFFICIENT_COVERAGE {covered} analyzed; minimum {args.min_covered}\n'
        else:
            output=emit_report(report, args.format, case_file=origin.name)
        if args.out:
            args.out.parent.mkdir(parents=True,exist_ok=True)
            args.out.write_text(output,encoding='utf-8')
        else:
            print(output,end='')
        if args.fail_new_only:
            return int(shortfall or any_blocking(report,fail_review=args.fail_on_review,new_only=True))
        return int(shortfall or any_blocking(report,fail_review=args.fail_on_review))
    except (OSError, ValueError, ProbeError, ConfigError, BaselineError) as e:
        print('RISU Probe: ' + str(e), file=sys.stderr)
        return 2

def quick_compare(argv):
    """No configuration required: compare two saved response JSON files."""
    p=argparse.ArgumentParser(description='Compare one HTTP response envelope with one MCP tool result')
    p.add_argument('http_response',type=Path,help='JSON {status,content_type,body}')
    p.add_argument('mcp_result',type=Path,help='MCP CallToolResult JSON or JSON-RPC result envelope')
    p.add_argument('--format',choices=('text','json'),default='text')
    p.add_argument('--error-profile',choices=('problem-only','json-errors'),default='problem-only')
    p.add_argument('--policy',choices=('calibrated','strict-carrier'),default='calibrated')
    args=p.parse_args(argv)
    try:
        source=json.loads(args.http_response.read_text())
        payload=json.loads(args.mcp_result.read_text())
        result=payload.get('result',payload)
        if not isinstance(result,dict):
            raise ProbeError('MCP result must be a JSON object')
        entry=compare(source,result,'one-call',error_profile=args.error_profile)
        s={v:int(entry['verdict']==v) for v in
           ('PRESERVED','LOSS','INVENTED','LOSS_AND_INVENTED','NOT_APPLICABLE','UNSTABLE_SOURCE','ERROR','MISSING_TOOL','INVALID_CATALOG','INPUT_REQUIRED')}
        report=apply_decisions({'tool':'RISU Probe','version':VERSION,'summary':s,'results':[entry]},args.policy)
        print(json.dumps(report,indent=2) if args.format=='json' else render_text(report))
        return int(any_blocking(report))
    except (OSError,ValueError,ProbeError) as e:
        print('RISU Probe: '+str(e),file=sys.stderr)
        return 2


def main(argv=None):
    argv=list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0]=='first-check':
        from risu_onboarding import first_check
        return first_check(argv[1:] if argv else [])
    if argv[0] in ('--version', '-V'):
        print('risu-probe '+VERSION)
        return 0
    if argv[0] in ('--help', '-h'):
        print('RISU Probe '+VERSION+'\n\nStart safely:  risu-probe first-check [directory]'
              +'\nOffline scan:   risu-probe scan .'
              +'\nLive fixture:   risu-probe verify --fixture PROJECT --allow-exec'
              +'\nOther commands: check, plan, plan-auto, collect, analyze, witness, reproduce, compare, baseline'
              +'\n\nFirst check only reads source. Live commands require explicit execution approval.')
        return 0
    if argv and argv[0]=='verify':
        from risu_verify import main as verify_main
        return verify_main(argv[1:])
    if argv and argv[0]=='scan':
        from risu_static import main as static_scan_main
        return static_scan_main(argv[1:])
    if argv and argv[0]=='compare':
        return quick_compare(argv[1:])
    if argv and argv[0]=='check':
        return check_project(argv[1:])
    if argv and argv[0]=='plan':
        return plan_cli(argv[1:])
    if argv and argv[0]=='plan-auto':
        from risu_auto_plan import main as auto_plan_main
        return auto_plan_main(argv[1:])
    if argv and argv[0]=='baseline':
        return baseline_cli(argv[1:])
    if argv and argv[0]=='collect':
        from risu_collect import main as collect_main
        return collect_main(argv[1:])
    if argv and argv[0]=='analyze':
        from risu_analyze import main as analyze_main
        return analyze_main(argv[1:])
    if argv and argv[0]=='witness':
        from risu_witness import main as witness_main
        return witness_main(argv[1:])
    if argv and argv[0]=='reproduce':
        from risu_reproduce import main as reproduce_main
        return reproduce_main(argv[1:])
    p=argparse.ArgumentParser(description='RISU Probe: what disappeared between your API and AI tool?')
    p.add_argument('cases',type=Path,help='JSON file containing {"cases": [...]}')
    p.add_argument('--upstream',help='HTTP source URL root (GET only, loopback by default)')
    p.add_argument('--server-json',help='JSON array of subprocess argv; no shell expansion')
    p.add_argument('--protocol',choices=['auto','modern','legacy'],default='auto')
    p.add_argument('--allow-remote',action='store_true')
    p.add_argument('--recheck-source',action='store_true',help='re-read GET source to detect changing baselines')
    p.add_argument('--format',choices=['text','json','sarif','markdown'],default='text')
    p.add_argument('--out',type=Path,help='write the report as JSON, retaining no full response bodies')
    p.add_argument('--fail-on-loss',action='store_true',help='nonzero exit on calibrated FAIL')
    p.add_argument('--fail-on-review',action='store_true')
    p.add_argument('--policy',choices=('calibrated','strict-carrier'),default='calibrated')
    p.add_argument('--error-profile',choices=('problem-only','json-errors'),default='problem-only')
    args=p.parse_args(argv)
    try:
        obj=json.loads(args.cases.read_text(encoding='utf-8'))
        cases=obj.get('cases')
        if not isinstance(cases,list) or not cases:
            raise ProbeError('cases file must contain nonempty cases array')
        argv_cmd=json.loads(args.server_json) if args.server_json else None
        report=run_cases(cases,upstream=args.upstream,server_cmd=argv_cmd,
                         protocol=args.protocol,allow_remote=args.allow_remote,recheck_source=args.recheck_source,error_profile=args.error_profile,
                         policy=args.policy)
        payload=(render_text(report)+'\n') if args.format=='text' else emit_report(report,args.format,case_file=args.cases.name)
        if args.out:
            args.out.write_text(payload,encoding='utf-8')
        else:
            print(payload,end='')
        if args.fail_on_loss and any_blocking(report,fail_review=args.fail_on_review):
            return 1
        return 0
    except (OSError, ValueError, ProbeError) as e:
        print('RISU Probe: '+str(e),file=sys.stderr)
        return 2

if __name__=='__main__':
    sys.exit(main())
