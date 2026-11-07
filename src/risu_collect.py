"""Explicit-GET, local-first automatic capture for HTTP -> MCP comparisons.

Runs no tool without a reviewed case; never guesses unknown IDs or invokes HTTP
methods besides GET. Evidence files contain **raw payloads** and must be private.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

from risu_project import resolve_config, load_cases, resolve_argv, ConfigError

MAX_CASES = 200
MAX_OUTPUT = 8_000_000


def digest(value):
    raw=json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False)
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()


def _atomic_private_write(path: Path, payload: dict):
    data=(json.dumps(payload,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode('utf-8')
    if len(data)>MAX_OUTPUT:
        raise ValueError('capture exceeds 8 MB evidence cap; no output written')
    path.parent.mkdir(parents=True,exist_ok=True)
    fd, tmp=tempfile.mkstemp(prefix='.risu-evidence-',dir=path.parent)
    try:
        try:os.fchmod(fd,0o600)
        except (AttributeError,OSError):pass  # Windows: best-effort file ACL only
        with os.fdopen(fd,'wb') as f:
            f.write(data)
            f.flush();os.fsync(f.fileno())
        os.replace(tmp,path)
        try: os.chmod(path,0o600)
        except OSError: pass
    finally:
        if os.path.exists(tmp):os.unlink(tmp)


def capture(cases, upstream, server_cmd, *, protocol='auto',allow_remote=False,
            recheck_source=True, error_profile='json-errors', label='live-target',server_env=None):
    from risu_probe import MCPClient, get_http, ProbeError, VERSION
    from risu_analyze import analyze
    if not isinstance(cases,list) or not 1<=len(cases)<=MAX_CASES:
        raise ProbeError('1-200 explicitly reviewed cases required')
    if not isinstance(label,str) or not label or len(label)>100:
        raise ProbeError('invalid capture target label')
    if not server_cmd:
        raise ProbeError('server_cmd required; no silent MCP execution')
    if not upstream:
        raise ProbeError('upstream required')
    # Fail closed before launching arbitrary MCP subprocesses.
    ids=set()
    for c in cases:
        if not isinstance(c,dict) or not isinstance(c.get('id'),str) or not c['id'] or c['id'] in ids:
            raise ProbeError('cases need unique nonempty string IDs')
        ids.add(c['id'])
        if 'mcp_result' in c or ('source' in c and 'response' in c['source']):
            raise ProbeError('collect requires live source and MCP calls; offline cases prohibited')
        s=c.get('source') or {}
        if not isinstance(s,dict) or s.get('method','GET').upper() != 'GET' or not isinstance(s.get('path'),str):
            raise ProbeError('collect accepts explicit GET source.path only')
        if not isinstance(c.get('tool'),str) or not c['tool'] or not isinstance(c.get('arguments',{}),dict):
            raise ProbeError('collect needs tool name and object arguments')
    # Confirm loopback/remote restriction and valid syntax, with a source read
    # only after inspection. The same strict function serves normal check.
    rows=[]; failures=[];negotiated=protocol
    with MCPClient(server_cmd,protocol=protocol,env=server_env) as client:
        negotiated=client.protocol
        catalog=client.list_tools_catalog()
        tools=set(catalog)
        for c in cases:
            ident=c['id'];tool=c['tool'];src_spec=c['source']
            if tool not in tools:
                failures.append({'id':ident,'code':'MISSING_TOOL','message':'MCP tools/list did not expose requested tool'})
                continue
            # An automatically proposed name is a *conditional* match. Recheck
            # the exact advertised tool contract before making any HTTP call.
            provenance=c.get('_auto_match')
            if provenance is not None:
                from risu_auto_plan import schema_digest
                if not isinstance(provenance,dict) or not isinstance(provenance.get('tool_schema_sha256'),str):
                    failures.append({'id':ident,'code':'INVALID_AUTO_MATCH','message':'invalid planning provenance'})
                    continue
                try:
                    current=schema_digest(catalog[tool])
                except (TypeError,ValueError,KeyError):
                    current=None
                if current!=provenance['tool_schema_sha256']:
                    failures.append({'id':ident,'code':'MCP_SCHEMA_CHANGED',
                                     'message':'MCP tool schema/annotations changed since planning; re-plan before calling'})
                    continue
            try:
                before=get_http(upstream,src_spec['path'],allow_remote=allow_remote)
                raw=client.call(tool,c.get('arguments',{}))
                after=get_http(upstream,src_spec['path'],allow_remote=allow_remote) if recheck_source else before
                if before!=after:
                    failures.append({'id':ident,'code':'UNSTABLE_SOURCE','message':'GET response differed before/after MCP call'})
                    continue
                if not isinstance(raw,dict):
                    failures.append({'id':ident,'code':'INVALID_MCP_RESULT','message':'MCP result was not object'})
                    continue
                if raw.get('resultType') not in (None, 'complete'):
                    failures.append({'id':ident,'code':'INCOMPLETE_MCP_RESULT','message':'MCP tool result not complete; no semantic verdict'})
                    continue
                rows.append({'check':{'id':ident,'tool':tool,'source_method':'GET','source_path':src_spec['path'],
                                      'arguments_sha256':digest(c.get('arguments',{}))},
                             'source_sample':before,'mcp_sample':raw,
                             'source_sha256':digest(before),'mcp_sha256':digest(raw)})
            except (ProbeError,ValueError,KeyError,TypeError,OverflowError) as e:
                failures.append({'id':ident,'code':'CAPTURE_ERROR','message':str(e)[:250]})
    matrix={'status':'EXECUTED' if not failures else 'PARTIAL_FAILURE',
            'collection_type':'live_http_and_mcp', 'tool':'RISU Probe', 'version':VERSION,
            'protocol':negotiated,'recheck_source':recheck_source,
            'raw_data_warning':'Contains raw HTTP/MCP payloads. Review before sharing or committing.',
            'targets':[{'target':label,'checks':rows}], 'failures':failures,
            'attempted_cases':len(cases),'captured_cases':len(rows)}
    if rows:
        report=analyze({'targets':matrix['targets']},profile=error_profile)
        matrix['diagnostic_summary']=report['diagnostic_summary']
        matrix['verdict_summary']=report['summary']
    else:
        matrix['diagnostic_summary']={};matrix['verdict_summary']={}
    return matrix


def main(argv=None):
    p=argparse.ArgumentParser(description='Collect original HTTP GET and real MCP tool results automatically into a private matrix')
    p.add_argument('project',help='project folder or risu-probe.json')
    p.add_argument('--out',type=Path,required=True,help='raw evidence JSON; file permissions 0600 on Unix')
    p.add_argument('--allow-exec',action='store_true',help='required to run MCP command from project configuration')
    p.add_argument('--allow-remote',action='store_true',help='explicitly permit remote HTTP (review target and secrets)')
    p.add_argument('--error-profile',choices=('problem-only','json-errors'),default='json-errors')
    p.add_argument('--label',default='live-target')
    p.add_argument('--no-recheck-source',action='store_true',help='disable before/after source comparison (weaker evidence)')
    a=p.parse_args(argv)
    try:
        if not a.allow_exec:raise ValueError('collect runs MCP subprocesses: pass --allow-exec after reviewing project config')
        path,config=resolve_config(a.project)
        cases,_=load_cases(path,config)
        argv=resolve_argv(path,config)
        result=capture(cases,config.get('upstream'),argv,protocol=config.get('protocol','auto'),
                       allow_remote=a.allow_remote,recheck_source=not a.no_recheck_source,
                       error_profile=a.error_profile,label=a.label)
        _atomic_private_write(a.out,result)
        print(f"RISU collected {result['captured_cases']}/{result['attempted_cases']} cases; "
              f"diagnostics {result['diagnostic_summary']}; output {a.out}")
        if result['failures']:
            print('FAIL_CLOSED: '+str(result['failures']),file=sys.stderr)
            return 2
        return 0
    except (ValueError,TypeError,OSError,ConfigError) as e:
        print('RISU collect: '+str(e),file=sys.stderr)
        return 2
    except Exception as e:
        # Avoid printing tool server exceptions with potentially sensitive values.
        print('RISU collect failed: '+type(e).__name__+': '+str(e)[:200],file=sys.stderr)
        return 2

if __name__=='__main__':raise SystemExit(main())
