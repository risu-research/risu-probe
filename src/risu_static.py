"""RISU Probe v0.7 — offline, evidence-scoped Python/OpenAPI static scanner.

Never imports or executes target code. Source-derived hypotheses are SUSPECTED,
not proven behavioral losses. stdlib scanner; PyYAML, if installed, adds YAML
OpenAPI parsing. This is not a security or MCP-conformance analyzer.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

RULES = {
    'RPY101': ('UPSTREAM_ERROR_DETAILS_DROPPED', 'warning',
               'A generated tool narrows an upstream error with details to its error summary.',
               'Review the generator/tool return mapping; test whether the original response fields survive using risu-probe collect.'),
    'RPY102': ('UPSTREAM_ERROR_RETURNED_AS_VALUE', 'note',
               'A tool-like function returns a normal error dict on an upstream failure path.',
               'Inspect the actual MCP isError value with risu-probe collect; this code alone cannot establish it.'),
    'RPY201': ('ERROR_TEXT_BOUNDED', 'note',
               'An error-handling path slices an HTTP response text field to a fixed character limit.',
               'Check whether a longer upstream response loses needed diagnostics; bounded messages may be intentional.'),
    'RPY202': ('HTTP_ERROR_REDUCED_TO_EXCEPTION_TEXT', 'note',
               'An HTTP error handler converts an exception into a returned error summary.',
               'Verify whether structured upstream fields are preserved in a machine-readable MCP result.'),
    'RPY203': ('EXPLICIT_ERROR_BODY_TRUNCATION_POLICY', 'note',
               'An error-body helper appends a truncation marker to a bounded prefix.',
               'Review documented message-size policy and use dynamic fixture tests to determine whether required fields disappear.'),
}
SKIP_DIRS = {'.git','.hg','.svn','.venv','venv','env','node_modules','__pycache__',
             'dist','build','.mypy_cache','.ruff_cache','.pytest_cache','.tox',
             '.next','coverage','.idea','.vscode'}
MAX_FILES = 3000
MAX_BYTES = 512 * 1024  # Unchanged maximum for Python source
MAX_SPEC_BYTES = 16 * 1024 * 1024  # One public OpenAPI description
MAX_TOTAL_BYTES = 35 * 1024 * 1024  # Across accepted files
MAX_SNIFF_BYTES = 16 * 1024
MAX_DEPTH = 24
MAX_FINDINGS = 500
OPENAPI_NAMES = re.compile(r'(?:openapi|swagger|api[-_]?spec|^spec\.(?:json|ya?ml)$|^api\.(?:json|ya?ml)$)', re.I)

class ScanError(Exception):
    pass


def _literal_str(node):
    return node.value if isinstance(node,ast.Constant) and isinstance(node.value,str) else None


def _call_name(node):
    if isinstance(node,ast.Name):return node.id
    if isinstance(node,ast.Attribute):return node.attr
    return None


def _literal_dict_keys(node):
    if not isinstance(node,ast.Dict):return set()
    return {_literal_str(k) for k in node.keys if _literal_str(k) is not None}


def _details_return(node):
    """Explicit tuple (False, {'error':..., 'details':...}) in same function body."""
    if not isinstance(node,ast.Return):return False
    x=node.value
    if not isinstance(x,ast.Tuple) or len(x.elts)!=2:return False
    false, body=x.elts
    return isinstance(false,ast.Constant) and false.value is False and {'error','details'} <= _literal_dict_keys(body)


def _api_call_bindings(fn, nodes=None):
    """Track exact (success,response) = [await] make_api_request(...) source shape."""
    names=set()
    for n in (ast.walk(fn) if nodes is None else nodes):
        if not isinstance(n,(ast.Assign,ast.AnnAssign)):continue
        targets=n.targets if isinstance(n,ast.Assign) else [n.target]
        value=n.value
        if isinstance(value,ast.Await):value=value.value
        if not isinstance(value,ast.Call) or _call_name(value.func)!='make_api_request':continue
        for t in targets:
            if isinstance(t,(ast.Tuple,ast.List)) and len(t.elts)==2 and all(isinstance(k,ast.Name) for k in t.elts):
                names.add((t.elts[0].id,t.elts[1].id))
    return names


def _failure_test(node, flag):
    if isinstance(node,ast.UnaryOp) and isinstance(node.op,ast.Not) and isinstance(node.operand,ast.Name):
        return node.operand.id==flag
    if isinstance(node,ast.Compare) and len(node.ops)==1 and isinstance(node.left,ast.Name) and node.left.id==flag:
        return isinstance(node.ops[0],ast.Is) and len(node.comparators)==1 and isinstance(node.comparators[0],ast.Constant) and node.comparators[0].value is False
    return False


def _error_only_return(node, response):
    if not isinstance(node,ast.Return) or not isinstance(node.value,ast.Dict) or len(node.value.keys)!=1 or _literal_dict_keys(node.value)!={'error'}:return False
    values=node.value.values
    if len(values)!=1:return False
    for n in ast.walk(values[0]):
        if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='get' and isinstance(n.func.value,ast.Name) and n.func.value.id==response and n.args and _literal_str(n.args[0])=='error':
            return True
    return False


def _path_for(path,root):
    try:return path.relative_to(root).as_posix()
    except ValueError:return path.name


def _finding(rule,path,root,line,reason):
    title,level,description,fix=RULES[rule]
    return {'rule_id':rule,'code':title,'verdict':'SUSPECTED_LOSS',
            'confidence':'structural_candidate','severity':level,
            'path':_path_for(path,root),'line':line,'message':description,
            'evidence':reason,'next_step':fix}


def _func_nodes(tree):
    return [n for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))]


def _python_rules(parsed,root):
    findings=[]
    functions_by_path={path:_func_nodes(tree) for path,tree in parsed}
    helper_paths={path for path,tree in parsed for fn in functions_by_path[path]
                  if fn.name=='make_api_request' and any(_details_return(n) for n in ast.walk(fn))}
    for path,tree in parsed:
        # Do not infer a producer/consumer relationship merely because an
        # unrelated file in the tree has a function with the same name.
        imported_clients={str(n.module).replace('.', '/')+'.py'
                          for n in ast.walk(tree) if isinstance(n,ast.ImportFrom)
                          and str(n.module or '').endswith('api.client')
                          and any(a.name=='make_api_request' and a.asname is None for a in n.names)}
        has_details_helper=any(h.as_posix().endswith('/'+m) for m in imported_clients
                               for h in helper_paths)

        for fn in functions_by_path[path]:
            # One ordered AST walk reused by bindings, branches, slices and handlers.
            fn_nodes=list(ast.walk(fn))
            bindings=_api_call_bindings(fn, fn_nodes)
            for n in fn_nodes:
                if not isinstance(n,ast.If):continue
                for success,response in bindings:
                    if not _failure_test(n.test,success):continue
                    for statement in n.body:
                        for ret in ast.walk(statement):
                            if not _error_only_return(ret,response):continue
                            rule='RPY101' if has_details_helper else 'RPY102'
                            reason=('A make_api_request() (success, response) pair enters '
                                    'a failure branch returning only response.get("error"). '
                                    + ('The project also defines a make_api_request() path returning an explicit details field.'
                                       if has_details_helper else 'No matching details-producing helper was verified in scanned Python files.'))
                            findings.append(_finding(rule,path,root,ret.lineno,reason))
            # Detect deliberate bounded error previews, e.g. FastMCP 4.1.6.
            # This is a policy signal, NOT evidence of an unknown bug.
            if 'error' in fn.name.lower() and 'body' in fn.name.lower():
                for ret in fn_nodes:
                    if not isinstance(ret,ast.Return) or not isinstance(ret.value,ast.BinOp) or not isinstance(ret.value.op,ast.Add):continue
                    left,right=ret.value.left,ret.value.right
                    if not (isinstance(left,ast.Subscript) and isinstance(left.slice,ast.Slice) and left.slice.upper is not None):continue
                    upper=left.slice.upper
                    limited=(isinstance(upper,ast.Name) and any(x in upper.id.upper() for x in ('LIMIT','MAX'))) or (isinstance(upper,ast.Constant) and type(upper.value) is int and upper.value>0)
                    marked=(isinstance(right,ast.Name) and 'TRUNC' in right.id.upper()) or (isinstance(right,ast.Constant) and isinstance(right.value,str) and 'truncat' in right.value.lower())
                    if limited and marked:
                        findings.append(_finding('RPY203',path,root,ret.lineno,
                            'A bounded error-body slice is concatenated with an explicit truncation marker; policy behavior may be intentional.'))
            # Slices are captured only in an explicitly error-oriented branch or handler.
            has_error_context=None
            for n in fn_nodes:
                if not isinstance(n,ast.Subscript) or not isinstance(n.slice,ast.Slice):continue
                upper=n.slice.upper
                if not isinstance(upper,ast.Constant) or type(upper.value) is not int or not 0 < upper.value <= 65536:continue
                v=n.value
                if not (isinstance(v,ast.Attribute) and v.attr=='text' and isinstance(v.value,ast.Name)
                        and v.value.id in ('response','resp','r','exc_response')):continue
                # Require the enclosing function to have explicit error/exception control-flow.
                if has_error_context is None:
                    has_error_context=(fn.name.lower().find('error')>=0 or fn.name=='make_api_request' or
                         any(isinstance(x,(ast.ExceptHandler,ast.Raise)) for x in fn_nodes))
                if not has_error_context:continue
                findings.append(_finding('RPY201',path,root,n.lineno,
                                         f'An HTTP response text expression is sliced at a constant upper bound of {upper.value} characters. No upstream data loss was executed or measured.'))
            for n in fn_nodes:
                if not isinstance(n,ast.ExceptHandler) or not n.name:continue
                err=(_call_name(n.type) or '')
                if err not in ('HTTPStatusError','HTTPError'):continue
                for stmt in n.body:
                    for ret in ast.walk(stmt):
                        if not isinstance(ret,ast.Return) or _literal_dict_keys(ret.value)!={'error'}:continue
                        if any(isinstance(c,ast.Name) and c.id==n.name for c in ast.walk(ret.value)):
                            findings.append(_finding('RPY202',path,root,ret.lineno,
                                'An HTTP error exception is referenced inside a returned one-key error object; no original structured body appears in this return.'))
    unique={}
    for x in findings:unique[(x['path'],x['line'],x['rule_id'])]=x
    return sorted(unique.values(),key=lambda x:(x['path'],x['line'],x['rule_id']))


def _schema_gets(obj):
    if not isinstance(obj,dict) or not isinstance(obj.get('paths'),dict):return None
    if not ('openapi' in obj or 'swagger' in obj):return None
    all_get=0; ready=0; need_examples=0; unsafe=0
    for route,group in obj['paths'].items():
        if not isinstance(route,str) or not isinstance(group,dict):continue
        operation=group.get('get')
        if not isinstance(operation,dict):continue
        all_get+=1
        opid=str(operation.get('operationId') or '')
        if not opid or any(x in (opid+' '+route).lower() for x in ('delete','update','create','reset','submit','purchase','transfer','cancel','approve')) or operation.get('security') or obj.get('security') or operation.get('requestBody'):
            unsafe+=1;continue
        parameters=(group.get('parameters') or [])+(operation.get('parameters') or [])
        missing=False
        for p in parameters:
            if not isinstance(p,dict) or '$ref' in p:
                missing=True;break
            if p.get('required') is True and p.get('in') in ('path','query'):
                sample=p.get('example', (p.get('schema') or {}).get('example'))
                es=p.get('examples')
                if sample is None and not (isinstance(es,dict) and any(isinstance(x,dict) and 'value' in x for x in es.values())):
                    missing=True;break
            if p.get('required') and p.get('in') in ('header','cookie'):
                missing=True;break
        if missing:need_examples+=1
        else:ready+=1
    return {'get_total':all_get,'get_with_explicit_examples_or_no_required_arguments':ready,
            'get_needing_examples_or_manual_review':need_examples,'get_excluded_by_conservative_metadata':unsafe}


def _has_openapi_header(path:Path):
    """True only for bounded JSON/YAML files with an apparent OpenAPI header.

    This identifies *candidates*, never proves a valid specification.
    Actual parser and _schema_gets determine whether the file is OpenAPI.
    """
    if path.suffix.lower() not in ('.json','.yaml','.yml'):
        return False
    try:
        if path.stat().st_size>MAX_SPEC_BYTES:
            # Too large to admit automatically, but include recognized names
            # so it is recorded as incomplete rather than silently omitted.
            return bool(OPENAPI_NAMES.search(path.name))
        with path.open('rb') as f:
            prefix=f.read(MAX_SNIFF_BYTES)
        if path.suffix.lower()=='.json':
            return bool(re.search(rb'"(?:openapi|swagger)"\s*:',prefix))
        return bool(re.search(rb'(?m)^\s*(?:openapi|swagger)\s*:',prefix))
    except (OSError,ValueError):
        return False


def _find_files(target:Path):
    if target.is_symlink():raise ScanError('target symlink not accepted')
    if target.is_file():return [target],target.parent
    if not target.is_dir():raise ScanError('target must be an existing file or directory')
    files=[]
    root=target.resolve()
    for current,dirs,names in os.walk(root,topdown=True,followlinks=False):
        base=Path(current)
        depth=len(base.relative_to(root).parts)
        dirs[:]=sorted(d for d in dirs if d not in SKIP_DIRS and (not d.startswith('.') or d=='.schema') and not (base/d).is_symlink() and depth < MAX_DEPTH)
        for name in sorted(names):
            path=base/name
            if path.is_symlink() or not path.is_file():continue
            if name.endswith('.py') or (path.suffix.lower() in ('.json','.yaml','.yml') and (OPENAPI_NAMES.search(name) or _has_openapi_header(path))):
                files.append(path)
                if len(files)>MAX_FILES:
                    raise ScanError(f'scan limit exceeded ({MAX_FILES} eligible files); narrow the project directory')
    return files,root


def scan(path:Path):
    files,root=_find_files(path)
    parsed=[]; specs=[]; incomplete=[]; total=0; python_count=0; other_count=0
    for file in files:
        label=_path_for(file,root)
        try:
            sz=file.stat().st_size
            limit=MAX_BYTES if file.suffix.lower()=='.py' else MAX_SPEC_BYTES
            if sz>limit:
                incomplete.append({'path':label,'reason':f'file exceeds {limit} byte limit'});continue
            total+=sz
            if total>MAX_TOTAL_BYTES:
                incomplete.append({'path':label,'reason':f'cumulative file budget {MAX_TOTAL_BYTES} exceeded'});break
            txt=file.read_text(encoding='utf-8')
            if file.suffix=='.py':
                try:tree=ast.parse(txt,filename=label)
                except (SyntaxError,ValueError,RecursionError) as e:
                    incomplete.append({'path':label,'reason':'Python parse failed: '+str(e)[:120]});continue
                parsed.append((file,tree));python_count+=1
            else:
                try:
                    if file.suffix.lower()=='.json':obj=json.loads(txt)
                    else:
                        try:import yaml
                        except ImportError:
                            incomplete.append({'path':label,'reason':'YAML OpenAPI requires optional PyYAML; no code executed'});continue
                        obj=yaml.safe_load(txt)
                    result=_schema_gets(obj)
                    if result is not None:specs.append({'path':label,**result});other_count+=1
                except (ValueError,TypeError,RecursionError,MemoryError) as e:
                    incomplete.append({'path':label,'reason':'OpenAPI parse error: '+str(e)[:120]})
                except Exception as e:
                    # PyYAML parser errors are optional runtime plugin exceptions; never mark scanned.
                    incomplete.append({'path':label,'reason':'Unsupported or invalid OpenAPI: '+type(e).__name__})
        except (OSError,UnicodeError) as e:
            incomplete.append({'path':label,'reason':'File unavailable or non-UTF8: '+type(e).__name__})
    findings=_python_rules(parsed,root)
    if len(findings)>MAX_FINDINGS:
        incomplete.append({'path':'.','reason':f'finding count exceeds {MAX_FINDINGS} (report truncated)'})
        findings=findings[:MAX_FINDINGS]
    stats={'eligible_files':len(files),'python_parsed':python_count,'openapi_parsed':len(specs),
           'openapi_get_total':sum(s['get_total'] for s in specs),
           'openapi_get_ready_candidates':sum(s['get_with_explicit_examples_or_no_required_arguments'] for s in specs),
           'openapi_get_needing_review':sum(s['get_needing_examples_or_manual_review'] for s in specs),
           'findings':len(findings),'incomplete_files':len(incomplete)}
    status='UNVERIFIED' if not parsed and not specs else 'PARTIAL' if incomplete else 'SUSPECTED_LOSS' if findings else 'NO_STATIC_FINDINGS'
    return {'tool':'RISU Probe','version':'0.9.7-experimental','command':'scan',
            'result_scope':'OFFLINE_SOURCE_ONLY','status':status,'summary':stats,
            'findings':findings,'openapi':specs,'incomplete':incomplete,
            'disclaimer':'No target module import, API call or MCP call was performed. Findings are hypotheses, not proven data loss. NO_STATIC_FINDINGS is not a preservation guarantee.'}


def as_text(result):
    stats=result['summary']
    lines=[f"RISU static scan: {result['status']}  ({stats['python_parsed']} Python; {stats['openapi_parsed']} OpenAPI; {stats['findings']} hypotheses)"]
    for f in result['findings']:
        lines.append(f"  {f['path']}:{f['line']}: {f['rule_id']} {f['code']} [SUSPECTED]")
        lines.append('    '+f['evidence'])
        lines.append('    Next: '+f['next_step'])
    for s in result['openapi']:
        lines.append(f"  OpenAPI {s['path']}: {s['get_total']} GET, {s['get_with_explicit_examples_or_no_required_arguments']} candidate plans, {s['get_needing_examples_or_manual_review']} need example/review, {s['get_excluded_by_conservative_metadata']} excluded")
    for x in result['incomplete'][:30]:lines.append('  UNVERIFIED '+x['path']+': '+x['reason'])
    lines.append('Offline source-only hypotheses; no MCP or HTTP executed. No static findings ≠ preserved behavior.')
    return '\n'.join(lines)+'\n'


def as_sarif(result):
    rules=[{'id':key,'shortDescription':{'text':val[0]},'fullDescription':{'text':val[2]},
            'help':{'text':val[3]},'properties':{'category':'static-hypothesis','evidence_level':'source-pattern-only'}}
           for key,val in RULES.items()]
    observations=[]
    for f in result['findings']:
        observations.append({'ruleId':f['rule_id'],'level':f['severity'],
            'message':{'text':f['message']+' '+f['evidence']},
            'locations':[{'physicalLocation':{'artifactLocation':{'uri':f['path']},
                                              'region':{'startLine':f['line']}}}],
            'properties':{'verdict':f['verdict'],'confidence':f['confidence'],'next_step':f['next_step']}})
    return {'version':'2.1.0','$schema':'https://json.schemastore.org/sarif-2.1.0.json',
            'runs':[{'tool':{'driver':{'name':'RISU Probe Static','version':'0.9.7','rules':rules}},
                     'results':observations,
                     'properties':{'scanStatus':result['status'],'scanSummary':result['summary'],
                                   'unverified':result['incomplete']}}]}


def main(argv=None):
    p=argparse.ArgumentParser(description='Offline, no-process Python/OpenAPI risk hypotheses')
    p.add_argument('project',nargs='?',default='.',type=Path)
    p.add_argument('--format',choices=('text','json','sarif'),default='text')
    p.add_argument('--out',type=Path)
    p.add_argument('--fail-on-suspected',action='store_true',help='opt in to nonzero exit for candidate findings')
    p.add_argument('--strict-incomplete',action='store_true',help='nonzero exit if some eligible files were not parsed')
    args=p.parse_args(argv)
    try:
        result=scan(args.project)
        payload=(as_text(result) if args.format=='text' else json.dumps(as_sarif(result) if args.format=='sarif' else result,ensure_ascii=False,indent=2)+'\n')
        if args.out:
            args.out.parent.mkdir(parents=True,exist_ok=True)
            args.out.write_text(payload,encoding='utf-8')
        else:print(payload,end='')
        if result['status']=='UNVERIFIED' or (args.strict_incomplete and result['incomplete']):return 2
        if args.fail_on_suspected and result['findings']:return 1
        return 0
    except (OSError,ValueError,ScanError) as e:
        print('RISU Probe scan: '+str(e),file=sys.stderr)
        return 2

if __name__=='__main__':sys.exit(main())
