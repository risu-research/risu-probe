"""RISU Probe v0.8: conservative static-signal -> controlled fixture -> real MCP bridge.

First adapter deliberately supports only an inspected CNOE generated Python
server layout and one explicit GET with one primitive path parameter. Unknown
source layout, authentication, ambiguity and missing error responses fail closed.
Generated target code is launched ONLY with --allow-exec and an isolated fixture
base URL. Do not treat static correlation as proof of Python line execution.
"""
from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
import os
import re
import sys
import threading
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from risu_auto_plan import auto_plan
from risu_collect import capture, _atomic_private_write
from risu_static import scan, ScanError

MAX_SPEC_BYTES = 524_288
MAX_CASES = 5
RUN_MARKER = 'risu-fixture'
WRITE_WORDS = re.compile(r'(?:delete|update|create|reset|submit|purchase|transfer|cancel|approve|write|mutate)',re.I)

class FixtureError(Exception):
    pass


def _source(path:Path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_SPEC_BYTES:
        raise FixtureError('unsupported, symlinked or oversized source file: '+str(path.name))
    return path.read_text(encoding='utf-8')


def _tree(path:Path):
    return ast.parse(_source(path),filename=str(path))


def _registered_tools(tree):
    """AST matches exact CNOE mcp.tool()(module.function) registrations."""
    found={}
    for node in ast.walk(tree):
        if not isinstance(node,ast.Call) or len(node.args)!=1 or node.keywords:
            continue
        inner=node.func
        if not (isinstance(inner,ast.Call) and isinstance(inner.func,ast.Attribute)
                and isinstance(inner.func.value,ast.Name)
                and inner.func.value.id=='mcp' and inner.func.attr=='tool'):
            continue
        actual=node.args[0]
        if not (isinstance(actual,ast.Attribute) and isinstance(actual.value,ast.Name)):
            continue
        name=actual.attr
        if name in found:raise FixtureError('duplicate MCP tool registration: '+name)
        found[name]=actual.value.id
    return found


def _getenv_names(tree):
    out={}
    for stmt in tree.body:
        if not isinstance(stmt,ast.Assign) or len(stmt.targets)!=1 or not isinstance(stmt.targets[0],ast.Name):
            continue
        val=stmt.value
        if not (isinstance(val,ast.Call) and isinstance(val.func,ast.Attribute)
                and isinstance(val.func.value,ast.Name) and val.func.value.id=='os'
                and val.func.attr=='getenv' and val.args
                and isinstance(val.args[0],ast.Constant) and isinstance(val.args[0].value,str)):
            continue
        out[stmt.targets[0].id]=val.args[0].value
    return out


def _function_on_line(tree,line):
    found=[]
    for node in ast.walk(tree):
        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)) and node.lineno<=line<=getattr(node,'end_lineno',node.lineno):
            found.append(node)
    return min(found,key=lambda n:getattr(n,'end_lineno',n.lineno)-n.lineno).name if found else None


def _selected_spec(root:Path,specified:Path|None, operation:str|None):
    if specified is not None:
        file=specified.resolve()
        if specified.is_symlink() or root not in file.parents:
            raise FixtureError('--openapi must be a non-symlinked file inside the project')
        files=[file]
    else:
        files=sorted(p for p in root.glob('*.json') if p.name.lower() in ('openapi.json','swagger.json','api.json'))
    if len(files)!=1:raise FixtureError('exactly one root-level OpenAPI JSON is required (or --openapi)')
    obj=json.loads(_source(files[0]))
    if not isinstance(obj,dict) or not str(obj.get('openapi','')).startswith('3.') or not isinstance(obj.get('paths'),dict):
        raise FixtureError('OpenAPI 3.x JSON with paths required')
    matches=[]
    for route,paths in obj['paths'].items():
        if isinstance(paths,dict) and isinstance(paths.get('get'),dict):
            op=paths['get'];opid=op.get('operationId')
            if opid==operation or (operation is None and isinstance(opid,str)):
                matches.append((route,paths,op))
    if not matches:raise FixtureError('no matching GET operation')
    return files[0],obj,matches


def _safe_get(path, entry, op, spec):
    if not isinstance(path,str) or not path.startswith('/') or path.startswith('//') or '\\' in path or '..' in path.split('/'):
        raise FixtureError('unsafe path')
    name=op.get('operationId')
    if not isinstance(name,str) or not re.fullmatch('[A-Za-z_][A-Za-z0-9_]*',name):
        raise FixtureError('unsafe or missing operationId')
    if WRITE_WORDS.search(name+' '+path):raise FixtureError('operation name/path suggests writes')
    if op.get('requestBody') is not None or op.get('callbacks') or op.get('deprecated') or op.get('x-risu-probe-skip'):
        raise FixtureError('GET has side-effect or unsupported metadata')
    if 'security' in op and not isinstance(op['security'],list):
        raise FixtureError('invalid operation security declaration')
    if 'security' in spec and not isinstance(spec['security'],list):
        raise FixtureError('invalid global security declaration')
    if ('security' in op and op['security']) or (('security' not in op) and spec.get('security')):
        raise FixtureError('authenticated GET not auto-fixtured')
    if len(entry.get('parameters',[])) or not isinstance(op.get('parameters',[]),list):
        raise FixtureError('only direct operation parameters supported')
    params=op.get('parameters',[])
    if len(params)!=1:raise FixtureError('v0.8 fixture requires exactly one path parameter')
    p=params[0]
    if not isinstance(p,dict) or p.get('in')!='path' or p.get('required') is not True or not isinstance(p.get('name'),str):
        raise FixtureError('only one required path parameter supported')
    if path.count('{'+p['name']+'}')!=1 or len(re.findall(r'\{[^}]+\}',path))!=1:
        raise FixtureError('path placeholder does not match parameter')
    if p.get('style','simple')!='simple' or 'content' in p:
        raise FixtureError('unsupported parameter serialization')
    sch=p.get('schema')
    if not isinstance(sch,dict) or sch.get('type')!='string' or any(k in sch for k in ('$ref','enum','const','format','pattern','minLength','maxLength','oneOf','anyOf','allOf')):
        raise FixtureError('path schema has constraints; no safe synthetic value inferred')
    return p


def _responses(op):
    raw=op.get('responses')
    if not isinstance(raw,dict):raise FixtureError('OpenAPI responses object required')
    candidate=[]
    for key,desc in raw.items():
        if not (isinstance(key,str) and len(key)==3 and key.isdigit()):continue
        n=int(key)
        if n not in (200,400,409,422):continue
        if not isinstance(desc,dict) or '$ref' in desc:continue
        content=desc.get('content') or {}
        if not isinstance(content,dict):continue
        mimes=(('application/json',) if n==200 else ('application/problem+json','application/json'))
        mime=next((m for m in mimes if m in content),None)
        if not mime:continue
        schema=content[mime].get('schema') if isinstance(content[mime],dict) else None
        if (not isinstance(schema,dict) or schema.get('type')!='object'
                or schema.get('additionalProperties') is False or '$ref' in schema
                or schema.get('required') or any(k in schema for k in ('oneOf','anyOf','allOf'))):
            continue
        candidate.append((n,mime))
    if (200,'application/json') not in candidate or not any(n>=400 for n,_ in candidate):
        raise FixtureError('requires explicit unconstrained 200 JSON and at least one 4xx JSON/Problem schema')
    candidate=sorted(candidate,key=lambda x:(x[0]!=200,x[0]))[:MAX_CASES]
    return candidate


def _fixture_payload(status,mime,marker,token):
    if status==200:return {'id':token,'state':'ready','risu_fixture_marker':marker}
    if mime=='application/problem+json':
        return {'type':f'https://example.invalid/risu-probe/{status}',
                'title':'Synthetic upstream problem','status':status,
                'detail':'RISU generated fixture; not a real production request',
                'risu_fixture_marker':marker,
                'errors':[{'pointer':'#/items/0/quantity','detail':'invalid synthetic value'}]}
    return {'error':'synthetic invalid request','details':{'risu_fixture_marker':marker,'field':'id'},'status':status}


def _adapter(root:Path,findings,operation=None):
    pkgdirs=sorted(p for p in root.iterdir() if p.is_dir() and p.name.startswith('mcp_') and not p.is_symlink())
    choices=[]
    for pkg in pkgdirs:
        server=pkg/'server.py'; client=pkg/'api'/'client.py'
        if not (server.is_file() and client.is_file()) or any(p.is_symlink() for p in (server,client,pkg/'api',pkg/'tools')):
            continue
        try:
            srv_ast=_tree(server); cli_ast=_tree(client)
        except (OSError,SyntaxError,ValueError,FixtureError):continue
        regs=_registered_tools(srv_ast)
        envs=_getenv_names(cli_ast)
        url_env=envs.get('API_URL')
        if not url_env or not re.fullmatch(r'[A-Z][A-Z0-9_]*_API_URL',url_env):continue
        token_env=envs.get('API_TOKEN')
        if token_env and not re.fullmatch(r'[A-Z][A-Z0-9_]*_TOKEN',token_env):continue
        # Confirm the helper references the variable injected by the adapter.
        helper=[f for f in ast.walk(cli_ast) if isinstance(f,(ast.FunctionDef,ast.AsyncFunctionDef)) and f.name=='make_api_request']
        if len(helper)!=1 or not any(isinstance(n,ast.Name) and n.id=='API_URL' for n in ast.walk(helper[0])):
            continue
        for item in findings:
            if item['rule_id']!='RPY101':continue
            hit=root/item['path']
            if hit.is_symlink() or hit.parent!=(pkg/'tools') or not hit.is_file():continue
            fn=_function_on_line(_tree(hit),item['line'])
            if fn is None or regs.get(fn)!=hit.stem or (operation is not None and operation!=fn):continue
            choices.append({'tool':fn,'module':hit.stem,'tool_source':hit,'server':server,
                            'client':client,'pkg':pkg,'api_url_env':url_env,'token_env':token_env,
                            'static_finding':item})
    if not choices:raise FixtureError('no verified CNOE-style RPY101 source/tool/client registration found')
    if len(choices)>1:raise FixtureError('multiple supported findings; specify --operation and verify one at a time')
    return choices[0]


def prepare(root:Path,*,openapi=None,operation=None):
    if root.is_symlink() or not root.is_dir():raise FixtureError('project must be an actual directory, not a symlink')
    root=root.resolve()
    static=scan(root)
    if static['incomplete']:
        raise FixtureError('static scan incomplete; cannot safely link candidates')
    adapter=_adapter(root,static['findings'],operation)
    spec_file,spec,ops=_selected_spec(root,openapi,adapter['tool'])
    matches=[x for x in ops if x[2].get('operationId')==adapter['tool']]
    if len(matches)!=1:raise FixtureError('matched tool requires exactly one operationId')
    path,entry,op=matches[0]
    param=_safe_get(path,entry,op,spec)
    statuses=_responses(op)
    digest=hashlib.sha256((adapter['tool']+'|'+path).encode('utf-8')).hexdigest()[:8]
    # Examples are generated ONLY for our loopback substitute, never for production.
    spec=copy.deepcopy(spec)
    cases={}
    example_entries={}
    for status,mime in statuses:
        label=f'risu_{status}'
        ident=f'{RUN_MARKER}-{status}-{digest}'
        source_path=path.replace('{'+param['name']+'}',ident)
        marker='RISU_'+digest.upper()+'_'+str(status)
        cases[source_path]={'status':status,'content_type':mime,'body':_fixture_payload(status,mime,marker,ident)}
        example_entries[label]={'value':ident}
    # Narrow the schema to one inspected GET; empty global authentication override.
    spec['paths']={path:{'get':copy.deepcopy(op)}}
    spec['security']=[]
    spec['paths'][path]['get']['security']=[]
    spec['paths'][path]['get']['parameters'][0]['example']=next(iter(example_entries.values()))['value']
    spec['paths'][path]['get']['parameters'][0]['examples']=example_entries
    return {'root':root,'scan':static,'adapter':adapter,'spec':spec,'spec_file':spec_file,
            'source_cases':cases,'statuses':[s for s,m in statuses], 'operation':adapter['tool']}


def _restricted_env(adapter,base,root):
    # Do not inherit API credentials, arbitrary injected app settings or env files.
    whitelist=('PATH','SYSTEMROOT','WINDIR','HOME','TEMP','TMP','TMPDIR','VIRTUAL_ENV',
               'PYTHONHOME','LANG','LC_ALL','SSL_CERT_FILE','SSL_CERT_DIR',
               'USERPROFILE','LOCALAPPDATA','APPDATA','PROGRAMDATA',
               'HOMEDRIVE','HOMEPATH','SYSTEMDRIVE','COMSPEC','PATHEXT')
    env={k:os.environ[k] for k in whitelist if k in os.environ}
    env.update({'PYTHONPATH':str(root),'PYTHON_DOTENV_DISABLED':'1',
                'PYTHONUNBUFFERED':'1','MCP_MODE':'stdio',
                adapter['api_url_env']:base})
    if adapter['token_env']:
        env[adapter['token_env']]='RISU_SYNTHETIC_TOKEN_NO_PRIVILEGES'
    return env


def _server(cases,counters,unexpected):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            path=urlsplit(self.path)
            if path.query or path.fragment or path.path not in cases:
                unexpected.append(self.path); self.send_error(404);return
            row=cases[path.path]; counters[path.path]+=1
            payload=json.dumps(row['body'],ensure_ascii=False,separators=(',',':')).encode('utf-8')
            self.send_response(row['status'])
            self.send_header('Content-Type',row['content_type'])
            self.send_header('Content-Length',str(len(payload)))
            self.send_header('Cache-Control','no-store')
            self.end_headers();self.wfile.write(payload)
        def do_POST(self):
            unexpected.append('POST '+self.path);self.send_error(405)
        do_PUT=do_POST;do_PATCH=do_POST;do_DELETE=do_POST
        def log_message(self,*args):pass
    return ThreadingHTTPServer(('127.0.0.1',0),Handler)


def verify_fixture(project:Path,*,openapi=None,operation=None,python=None,allow_exec=False):
    prep=prepare(project,openapi=openapi,operation=operation)
    adapter=prep['adapter'];finding=adapter['static_finding']
    preview={'status':'UNVERIFIED','execution':'NONE' if not allow_exec else 'SUBPROCESS_WITH_LOOPBACK_FIXTURE',
             'adapter':'cnoe-generated-python-v1','operation':prep['operation'],
             'static_finding':{'rule_id':finding['rule_id'],'path':finding['path'],'line':finding['line'],
                               'classification':'SUSPECTED_LOSS'},
             'fixture_cases':[{'path':p,'status':v['status'],'media_type':v['content_type']}
                              for p,v in prep['source_cases'].items()],
             'note':'Static source mapping is not Python line-execution coverage.'}
    if not allow_exec:return preview
    if python is not None:
        exe=Path(python).expanduser()
        if not exe.is_file():raise FixtureError('--python must point to an existing interpreter; arbitrary commands not supported')
        interpreter=str(exe.absolute())
    else:interpreter=sys.executable
    counters=Counter();unexpected=[]
    http=_server(prep['source_cases'],counters,unexpected)
    worker=threading.Thread(target=http.serve_forever,daemon=True);worker.start()
    base='http://127.0.0.1:'+str(http.server_port)
    cmd=[interpreter,'-u',str(adapter['server'])]
    env=_restricted_env(adapter,base,prep['root'])
    try:
        from risu_probe import MCPClient, VERSION
        with MCPClient(cmd,protocol='legacy',env=env) as client:
            catalog=list(client.list_tools_catalog().values())
        if counters or unexpected:raise FixtureError('MCP startup/catalog made unexpected source API calls')
        plan=auto_plan(prep['spec'],catalog,upstream=base,server_cmd=cmd,protocol='legacy')
        expected=set(prep['source_cases'])
        planned={row['source']['path'] for row in plan['cases']}
        if planned!=expected or any(c['tool']!=adapter['tool'] for c in plan['cases']):
            raise FixtureError('tool catalog or auto planner could not map all expected fixture calls')
        if counters or unexpected:raise FixtureError('planning unexpectedly called fixture')
        matrix=capture(plan['cases'],base,cmd,protocol='legacy',recheck_source=True,
                       error_profile='json-errors',label='v09-cnoe-fixture',server_env=env)
        if matrix['failures'] or matrix['captured_cases']!=len(expected):
            raise FixtureError('live capture incomplete; cannot corroborate static signal')
        if unexpected or any(counters[p]!=3 for p in expected):
            raise FixtureError('unexpected fixture traffic: expected exactly 3 GETs per case')
        from risu_analyze import analyze
        from risu_evidence import assess as calibrated_assess
        counterfactual_rejections=0
        for row in matrix['targets'][0]['checks']:
            mutated=copy.deepcopy(row['source_sample'])
            body=mutated.get('body')
            if not isinstance(body,dict):
                raise FixtureError('fixture body must be an object for counterfactual')
            carrier=body if 'risu_fixture_marker' in body else body.get('details',{})
            if not isinstance(carrier,dict) or 'risu_fixture_marker' not in carrier:
                raise FixtureError('fixture body lacks synthetic marker for counterfactual')
            carrier['risu_fixture_marker']='RISU_COUNTERFACTUAL_NOT_PRESENT'
            proof=calibrated_assess(mutated,row['mcp_sample'])
            if proof['body_recovery'] in ('EXACT_MACHINE','EXACT_JSON_TEXT'):
                raise FixtureError('counterfactual source was falsely certified as exact')
            counterfactual_rejections+=1
        analysis=analyze({'targets':matrix['targets']},profile='json-errors')
        source_by_id={r['check']['id']:r['source_sample']['status'] for r in matrix['targets'][0]['checks']}
        evaluations=[]
        for row in analysis['results']:
            evaluations.append({'id':row['id'],'http_status':source_by_id[row['id']],
                                'verdict':row['verdict'],'diagnostic_codes':[x['code'] for x in row.get('diagnostics',[])],
                                'loss_count':len(row.get('losses',[])),
                                'evidence_v1':row.get('evidence_v1'),
                                'decision_v1':row.get('decision_v1')})
        # A broken positive control makes all other correlations unreliable.
        positive=[x for x in evaluations if x['http_status']==200]
        if len(positive)!=1 or positive[0]['verdict']!='PRESERVED':
            raise FixtureError('positive control failed; error-path observations are inconclusive')
        negatives=[x for x in evaluations if x['http_status']>=400]
        confirmed=[x for x in negatives if x['verdict'] in ('LOSS','LOSS_AND_INVENTED')]
        preview.update({'execution':'REAL_LOCALHOST_HTTP_AND_MCP','status':
                        'CORROBORATED_BEHAVIOR' if confirmed else 'NO_DYNAMIC_LOSS_OBSERVED',
                        'probe_version':VERSION,
                        'counts':{'planned':len(expected),'captured':matrix['captured_cases'],
                                  'fixture_gets':sum(counters.values()),'unexpected_requests':len(unexpected),
                                  'error_losses':len(confirmed),'counterfactual_rejections':counterfactual_rejections},
                        'evaluations':evaluations,
                        'positive_control':'PRESERVED',
                        'static_links':[{'rule_id':finding['rule_id'],'path':finding['path'],
                                         'line':finding['line'],'tool':adapter['tool'],
                                         'verdict':'BEHAVIORALLY_CORROBORATED' if confirmed else 'NOT_CORROBORATED_IN_TESTED_CASES',
                                         'note':'Registered tool invoked; exact Python source line was not traced.'}],
                        'other_static_findings':[{'rule_id':f['rule_id'],'path':f['path'],
                                                  'line':f['line'],'verdict':'UNVERIFIED'}
                                                 for f in prep['scan']['findings'] if f is not finding],
                        'matrix':matrix})
        return preview
    finally:
        http.shutdown();http.server_close()


def main(argv=None):
    p=argparse.ArgumentParser(description='Corroborate a supported v0.7 source hypothesis using only a loopback HTTP fixture and actual MCP calls')
    p.add_argument('--fixture',type=Path,required=True,help='CNOE-style generated Python project directory')
    p.add_argument('--openapi',type=Path,help='specific local OpenAPI JSON file under project')
    p.add_argument('--operation',help='select a unique registered GET operationId')
    p.add_argument('--python',help='path to interpreter with the target generated server dependencies')
    p.add_argument('--allow-exec',action='store_true',help='required to launch reviewed generated MCP server subprocess')
    p.add_argument('--out',type=Path,help='private JSON evidence output; defaults to stdout summary without raw captures')
    p.add_argument('--fail-on-loss',action='store_true',help='CI fail on calibrated actual failures')
    p.add_argument('--fail-on-review',action='store_true',help='optionally block review findings')
    a=p.parse_args(argv)
    try:
        report=verify_fixture(a.fixture,openapi=a.openapi,operation=a.operation,python=a.python,allow_exec=a.allow_exec)
        if a.out:_atomic_private_write(a.out,report)
        view={k:v for k,v in report.items() if k!='matrix'}
        print(json.dumps(view,ensure_ascii=False,indent=2))
        if not a.allow_exec:return 0
        from risu_decision import any_blocking
        return int(a.fail_on_loss and any_blocking({'results':report.get('evaluations',[])},
                                                   fail_review=a.fail_on_review))
    except (FixtureError,ScanError,OSError,ValueError,SyntaxError,TypeError) as e:
        print('RISU verify fixture: '+str(e),file=sys.stderr)
        return 2
    except Exception as e:
        # Do not leak sensitive target exception data into normal CLI logs.
        print('RISU verify fixture failed: '+type(e).__name__,file=sys.stderr)
        return 2

if __name__=='__main__':raise SystemExit(main())
