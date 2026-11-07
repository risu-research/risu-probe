"""Conservative, non-executing OpenAPI 3.x sample planner.

Only explicit GET examples/defaults with primitive path/query parameters are
included. Local parameter refs and operation-level overrides are supported.
Authentication, external refs, header/cookie requirements, non-form encodings,
and unresolved inputs fail closed into a visible skipped list.
"""
from __future__ import annotations
import json
import re
from pathlib import Path
from urllib.parse import quote, urlencode

class PlanError(Exception):
    pass


def _sample(parameter):
    schema = parameter.get('schema') or {}
    if not isinstance(schema, dict) or '$ref' in schema:
        return None
    # OpenAPI parameter.examples provides named Example Objects. We only read
    # *inline* values; $ref and external examples cannot be safely inferred.
    if 'example' in parameter:
        value=parameter['example']
    elif 'example' in schema:
        value=schema['example']
    elif isinstance(parameter.get('examples'),dict) and parameter['examples']:
        examples=parameter['examples']
        first=examples[sorted(examples)[0]]
        value=first.get('value') if isinstance(first,dict) and '$ref' not in first else None
    else:
        value=schema.get('default')
    return value if type(value) in (str,int,float,bool) else None


def _resolve_parameter(spec: dict, parameter: dict):
    """Resolve only local component parameter references, at most 8 hops."""
    refs=set()
    for _ in range(8):
        if not isinstance(parameter,dict):
            raise PlanError('parameter is not an object')
        ref=parameter.get('$ref')
        if ref is None:
            return parameter
        if not isinstance(ref,str) or not ref.startswith('#/components/parameters/'):
            raise PlanError('external or unsupported parameter $ref')
        if ref in refs:
            raise PlanError('cyclic parameter $ref')
        refs.add(ref)
        cur=spec
        for key in ref[2:].split('/'):
            if any('~' == key[i] and (i+1 == len(key) or key[i+1] not in '01') for i in range(len(key))):
                raise PlanError('invalid local $ref escape')
            unescaped=key.replace('~1','/').replace('~0','~')
            if not isinstance(cur,dict) or unescaped not in cur:
                raise PlanError('unresolved local parameter $ref')
            cur=cur[unescaped]
        parameter=cur
    raise PlanError('parameter $ref depth limit exceeded')


def _parameters(spec, entry, op):
    path_parameters=entry.get('parameters',[])
    op_parameters=op.get('parameters',[])
    if not isinstance(path_parameters,list) or not isinstance(op_parameters,list):
        raise PlanError('parameters must be arrays')
    merged={}
    for raw in path_parameters+op_parameters:
        p=_resolve_parameter(spec, raw)
        name, where=p.get('name'),p.get('in')
        if not isinstance(name,str) or not name or where not in ('path','query','header','cookie'):
            raise PlanError('unsupported parameter name or location')
        merged[(where,name)]=p  # operation-level parameter overrides path-level
    return list(merged.values())


def plan_spec(spec: dict, *, upstream: str | None = None, server_cmd: list[str] | None = None) -> dict:
    if (not isinstance(spec,dict) or not isinstance(spec.get('paths'),dict) or
            not str(spec.get('openapi','3.1')).startswith('3.')):
        raise PlanError('OpenAPI 3.x object must contain paths')
    cases=[]
    skipped=[]
    used_ids=set()
    for path, entry in sorted(spec['paths'].items()):
        if not isinstance(path,str) or not path.startswith('/') or path.startswith('//') or '..' in path.split('/'):
            skipped.append({'path':str(path),'reason':'unsafe path'})
            continue
        if not isinstance(entry,dict):
            continue
        for method,op in sorted(entry.items()):
            if method.lower()!='get' or not isinstance(op,dict):
                continue
            name=op.get('operationId')
            if not isinstance(name,str) or not name:
                skipped.append({'path':path,'method':'GET','reason':'operationId missing; tool mapping unknown'})
                continue
            reasons=[]
            if name in used_ids:
                reasons.append(f'operationId {name} duplicates another generated tool')
            # Explicit security:[] on operation overrides global security.
            security=op['security'] if 'security' in op else spec.get('security',[])
            if security:
                reasons.append('operation requires authentication; no credentials inferred')
            params={}
            query=[]
            try:
                parameters=_parameters(spec,entry,op)
            except PlanError as e:
                parameters=[]
                reasons.append(str(e))
            for param in parameters:
                where=param['in']; key=param['name']
                if where=='path':
                    if param.get('style','simple')!='simple':
                        reasons.append(f'path {key} uses unsupported serialization')
                        continue
                    value=_sample(param)
                    if value is None:
                        reasons.append(f'path parameter {key} missing example/default')
                    else:
                        params[f'path_{key}']=value
                elif where=='query':
                    if param.get('style','form')!='form':
                        reasons.append(f'query {key} uses unsupported serialization')
                        continue
                    value=_sample(param)
                    if value is None:
                        if param.get('required'):
                            reasons.append(f'required query parameter {key} missing example/default')
                    else:
                        params[f'query_{key}']=value
                        query.append((key,str(value).lower() if type(value) is bool else str(value)))
                elif param.get('required'):
                    reasons.append(f'required {where} parameter {key} needs manual fixture')
            for key in re.findall(r'\{([^}]+)\}',path):
                if f'path_{key}' not in params:
                    reasons.append(f'path placeholder {key} not filled')
            if reasons:
                skipped.append({'path':path,'method':'GET','tool':name,'reason':'; '.join(dict.fromkeys(reasons))})
                continue
            target=path
            for key,val in params.items():
                if key.startswith('path_'):
                    target=target.replace('{'+key[len('path_'):]+'}',quote(str(val).lower() if type(val) is bool else str(val),safe=''))
            if '{' in target or '}' in target:
                skipped.append({'path':path,'method':'GET','tool':name,'reason':'unresolved path placeholder'})
                continue
            if query:
                target += '?' + urlencode(query)
            cases.append({'id':name,'tool':name,'arguments':params,
                          'source':{'method':'GET','path':target}})
            used_ids.add(name)
    config={'version':1,'protocol':'auto','recheck_source':True,'cases':cases,
            '_plan':{'included':len(cases),'skipped':skipped,
                     'note':'Generated examples only. Review all requests, tool names and authorization before execution.'}}
    if upstream is not None:
        config['upstream']=upstream
    if server_cmd is not None:
        config['server_cmd']=server_cmd
    return config


def plan_cli(argv:list[str]) -> int:
    import argparse, sys
    p=argparse.ArgumentParser(description='Create read-only Probe cases from explicit OpenAPI examples')
    p.add_argument('openapi',type=Path)
    p.add_argument('--out',type=Path,default=Path('risu-probe.json'))
    p.add_argument('--upstream',help='HTTP source root; no requests are sent by plan')
    p.add_argument('--server-json',help='JSON argv array; no subprocess launched by plan')
    p.add_argument('--force',action='store_true',help='overwrite an existing output file')
    p.add_argument('--show-skips',action='store_true',help='print reasons why operations could not be safely planned')
    args=p.parse_args(argv)
    try:
        spec=json.loads(args.openapi.read_text(encoding='utf-8'))
        cmd=json.loads(args.server_json) if args.server_json else None
        if cmd is not None and (not isinstance(cmd,list) or not all(isinstance(v,str) and v for v in cmd)):
            raise PlanError('--server-json must encode an array of strings')
        planned=plan_spec(spec,upstream=args.upstream,server_cmd=cmd)
        if args.out.exists() and not args.force:
            raise PlanError(f'{args.out} exists; use --force to overwrite')
        args.out.write_text(json.dumps(planned,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
        print(f'RISU Probe: {len(planned["cases"])} GET checks planned; '
              f'{len(planned["_plan"]["skipped"])} skipped; wrote {args.out}')
        if args.show_skips:
            for row in planned['_plan']['skipped']:
                print(f'  skip {row["path"]} {row.get("tool", "")}: {row["reason"]}')
        return 0 if planned['cases'] else 1
    except (PlanError,OSError,ValueError,TypeError) as e:
        print('RISU Probe: '+str(e),file=sys.stderr)
        return 2
