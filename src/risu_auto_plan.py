"""RISU Probe v0.6 conservative OpenAPI GET -> MCP tool auto mapping.

Discovery is read-only at the *MCP tools protocol* level, but running a server
process can have side effects. Caller must grant explicit --allow-exec.
The planner never calls an MCP tool or sends an upstream HTTP request.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from pathlib import Path
from urllib.parse import quote, urlencode

from risu_plan import plan_spec, _parameters, _sample, PlanError


class AutoPlanError(Exception):
    pass


SENSITIVE = re.compile(r'(?:token|secret|password|passwd|api[_-]?key|auth|cookie|csrf|session|credential)', re.I)
WRITE_VERBS = re.compile(r'(?:^|[_\-])(delete|remove|modify|update|create|post|put|patch|write|submit|approve|cancel|pay|purchase|reset|transfer)(?:$|[_\-])', re.I)
NAME_CHARS = re.compile(r'^[A-Za-z0-9_.-]{1,128}$')


def canonical(value):
    if not isinstance(value, str):
        return ''
    value = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', value)
    value = re.sub(r'([A-Z])([A-Z][a-z])', r'\1_\2', value)
    return re.sub(r'[^a-z0-9]', '', value.lower())


def schema_digest(tool):
    raw=json.dumps({'name':tool['name'],'inputSchema':tool['inputSchema'],
                    'annotations':tool.get('annotations')},
                   sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()


def check_scalar(value, schema):
    """Narrow JSON Schema subset; unsupported assertions are never guessed."""
    if not isinstance(schema,dict):
        return False,'missing parameter schema'
    unsupported={'$ref','allOf','oneOf','anyOf','not','if','then','else','dependentSchemas','patternProperties',
                 'contains','prefixItems','items','properties','required','contentEncoding','contentMediaType'}
    if unsupported.intersection(schema):
        return False,'complex/indirect JSON Schema constraint'
    kind=schema.get('type')
    types={'string': lambda x:isinstance(x,str),
           'integer':lambda x:type(x) is int,
           'number':lambda x:type(x) in (int,float) and math.isfinite(x),
           'boolean':lambda x:type(x) is bool}
    if kind not in types or not types[kind](value):
        return False,'incompatible or unsupported scalar schema type'
    if 'enum' in schema and (not isinstance(schema['enum'],list) or value not in schema['enum']):
        return False,'example absent from enum'
    if 'const' in schema and value!=schema['const']:
        return False,'example differs from const'
    try:
        if kind=='string':
            if len(value)>512 or any(ord(x)<32 for x in value):return False,'oversized/control-character string'
            if 'minLength' in schema and len(value)<schema['minLength']:return False,'below minLength'
            if 'maxLength' in schema and len(value)>schema['maxLength']:return False,'above maxLength'
            if 'pattern' in schema:
                p=schema['pattern']
                # Only a narrow, anchored character-class grammar is accepted;
                # unrestricted regex matching of untrusted specs can hang.
                if not isinstance(p,str) or len(p)>100 or not re.fullmatch(
                        r'\^\[[A-Za-z0-9_\-]+\]\+\$',p):
                    return False,'regex needs manual review'
                if re.fullmatch(p,value) is None:return False,'pattern mismatch'
            if schema.get('format') not in (None,'uuid','date','date-time','hostname'):
                return False,'unsupported format'
        if kind in ('integer','number'):
            for prop,fn in [('minimum',lambda x,y:x>=y),('maximum',lambda x,y:x<=y),
                            ('exclusiveMinimum',lambda x,y:x>y),('exclusiveMaximum',lambda x,y:x<y)]:
                if prop in schema and not fn(value,schema[prop]):return False,'numeric bound '+prop
            if 'multipleOf' in schema:
                v=schema['multipleOf']
                if type(v) not in (int,float) or v<=0 or not math.isclose((value/v)%1,0,abs_tol=1e-9):
                    return False,'multipleOf mismatch'
    except (TypeError,ValueError,re.error,OverflowError):return False,'invalid schema constraint'
    return True,''


def _source_guards(spec, operation_id):
    """Validate examples against OpenAPI constraints before adapting tool args."""
    matches=[]
    for path,entry in spec.get('paths',{}).items():
        if not isinstance(entry,dict):continue
        op=entry.get('get')
        if isinstance(op,dict) and op.get('operationId')==operation_id:
            matches.append((path,entry,op))
    if len(matches)!=1:
        return 'missing or nonunique GET operationId in spec'
    path,entry,op=matches[0]
    if op.get('deprecated') is True:return 'deprecated operation; review manually'
    if op.get('x-risu-probe-skip') is True:return 'explicit x-risu-probe-skip'
    if WRITE_VERBS.search(operation_id) or WRITE_VERBS.search(path):
        return 'GET name/path suggests mutation; manual review needed'
    if op.get('requestBody') is not None:return 'GET with request body requires review'
    if op.get('callbacks') or op.get('webhooks'):return 'callback/webhook operation requires review'
    try:params=_parameters(spec,entry,op)
    except PlanError as e:return str(e)
    for p in params:
        name=p['name'];where=p['in']
        if SENSITIVE.search(name):return 'parameter name suggests credential/secret'
        if where not in ('path','query'):
            if p.get('required'):return 'required header/cookie not safe to infer'
            continue
        if p.get('style', 'simple' if where=='path' else 'form')!=('simple' if where=='path' else 'form'):
            return 'unsupported parameter serialization'
        if where=='query' and p.get('explode',True) is False:
            return 'unsupported non-default query explode'
        value=_sample(p)
        if value is None:
            if where=='path' or p.get('required'):return 'required example missing'
            continue
        schema=p.get('schema')
        good,reason=check_scalar(value,schema)
        if not good:return f'{where} {name}: {reason}'
        if where=='path' and not p.get('required',True):return 'path parameter is not explicitly required'
    return None


def _match_tools(name,tools):
    matches=[t for t in tools if t.get('name')==name]
    if len(matches)==1:return matches[0],'exact'
    if len(matches)>1:return None,'duplicate catalog name'
    key=canonical(name)
    normalized=[t for t in tools if canonical(t.get('name'))==key]
    if len(normalized)==1:return normalized[0],'unique normalized spelling'
    if normalized:return None,'ambiguous normalized tool names'
    return None,'no tool name matches operationId'


def _schema_adapt(source_args,schema):
    if not isinstance(schema,dict) or schema.get('type')!='object':return None,'tool inputSchema must be object'
    if any(k in schema for k in ('$ref','oneOf','anyOf','allOf','if','then','else','patternProperties','dependentSchemas')):
        return None,'complex tool inputSchema needs review'
    props=schema.get('properties',{})
    required=schema.get('required',[])
    if not isinstance(props,dict) or not isinstance(required,list) or any(not isinstance(k,str) for k in required):
        return None,'invalid tool input schema properties/required'
    if len(props)>500:return None,'oversized input schema'
    adapted={}
    used=set()
    for key,val in source_args.items():
        if key in props:
            chosen=key
        elif key.startswith('path_') or key.startswith('query_'):
            original=key.split('_',1)[1]
            # Only unambiguous exact stripped alias is permitted.
            if original in props and original not in used and list(source_args).count('path_'+original)+list(source_args).count('query_'+original)==1:
                chosen=original
            else:return None,'path/query argument could not map to MCP schema: '+key
        else:return None,'unknown source argument: '+key
        if chosen in used:return None,'two parameters map to same tool argument'
        ok,why=check_scalar(val,props[chosen])
        if not ok:return None,f'tool argument {chosen}: {why}'
        used.add(chosen);adapted[chosen]=val
    missing=set(required)-set(adapted)
    if missing:return None,'tool has unfilled required arguments: '+', '.join(sorted(missing))
    return adapted,None



def _example_variants(spec,op_id,base_case):
    """Use named *inline* examples for one parameter; never guess values.

    Multiple variable parameters with independent scenario collections are
    ambiguous, so they are not multiplied into invented combinations.
    Returns the base case plus at most seven extra explicit scenarios.
    """
    found=[]
    for path,entry in spec['paths'].items():
        if isinstance(entry,dict) and isinstance(entry.get('get'),dict) and entry['get'].get('operationId')==op_id:
            found.append((path,entry,entry['get']))
    if len(found)!=1:return [base_case],None
    path,entry,op=found[0]
    try:parameters=_parameters(spec,entry,op)
    except PlanError:return [base_case],None
    with_examples=[p for p in parameters if isinstance(p.get('examples'),dict) and p.get('examples')]
    if len(with_examples)>1:return [base_case],'multiple independent example collections; no cross-product'
    if not with_examples:return [base_case],None
    p=with_examples[0]
    where,key=p['in'],p['name']
    if where not in ('path','query'):
        return [base_case],None
    prop=f'{where}_{key}'
    result=[base_case]
    seen={str(base_case['arguments'].get(prop))}
    for label,raw in sorted(p['examples'].items()):
        if len(result)>=8:break
        if not isinstance(raw,dict) or '$ref' in raw or 'value' not in raw:
            continue
        value=raw['value']
        if type(value) not in (str,int,float,bool) or str(value) in seen:
            continue
        ok,reason=check_scalar(value,p.get('schema'))
        if not ok:continue
        args=dict(base_case['arguments']);args[prop]=value
        url=path
        query=[]
        for prm in parameters:
            part=f"{prm['in']}_{prm['name']}"
            if part not in args:continue
            v=args[part]
            converted=str(v).lower() if type(v) is bool else str(v)
            if prm['in']=='path':url=url.replace('{'+prm['name']+'}',quote(converted,safe=''))
            elif prm['in']=='query':query.append((prm['name'],converted))
        if '{' in url or '}' in url:continue
        if query:url+='?'+urlencode(query)
        row=dict(base_case)
        row['id']=op_id+'__'+re.sub('[^A-Za-z0-9_-]','_',label)[:40]
        row['arguments']=args
        row['source']={'method':'GET','path':url}
        row['_example_label']=label
        result.append(row);seen.add(str(value))
    return result,None

def auto_plan(spec,catalog,*,upstream=None,server_cmd=None,protocol='auto'):
    """Match actual MCP tools to OpenAPI examples without making API/tool calls."""
    if not isinstance(catalog,list):raise AutoPlanError('catalog must be list of tool objects')
    if len(catalog)>10000:raise AutoPlanError('oversized MCP catalog')
    for t in catalog:
        if not isinstance(t,dict) or not isinstance(t.get('name'),str) or not NAME_CHARS.fullmatch(t['name']):
            raise AutoPlanError('catalog contains invalid tool name')
        if not isinstance(t.get('inputSchema'),dict):
            raise AutoPlanError('catalog tool missing inputSchema')
    if len({t['name'] for t in catalog})!=len(catalog):raise AutoPlanError('duplicate catalog names')
    base=plan_spec(spec)
    skipped=list(base['_plan']['skipped'])
    checks=[]
    for old in base['cases']:
        operation_id=old['tool']
        reason=_source_guards(spec,operation_id)
        if reason:
            skipped.append({'path':old['source']['path'],'tool':operation_id,'reason':reason})
            continue
        tool,basis=_match_tools(operation_id,catalog)
        if tool is None:
            skipped.append({'path':old['source']['path'],'tool':operation_id,'reason':basis})
            continue
        annotations=tool.get('annotations') or {}
        if not isinstance(annotations,dict):annotations={}
        if annotations.get('readOnlyHint') is False or annotations.get('destructiveHint') is True:
            skipped.append({'path':old['source']['path'],'tool':operation_id,
                            'reason':'tool declares write/destructive behavior despite GET; skip'})
            continue
        variants,variant_warning=_example_variants(spec,operation_id,old)
        if variant_warning:
            skipped.append({'path':old['source']['path'],'tool':operation_id,
                            'reason':variant_warning})
        for variant in variants:
            arguments,err=_schema_adapt(variant['arguments'],tool['inputSchema'])
            if err:
                skipped.append({'path':variant['source']['path'],'tool':operation_id,'reason':err})
                continue
            row={'id':variant['id'],'tool':tool['name'],'arguments':arguments,
                 'source':variant['source'],
                 '_auto_match':{'operationId':operation_id,'match_basis':basis,
                                'tool_schema_sha256':schema_digest(tool),
                                'catalog_verification':'recheck before MCP call',
                                'review_required':True}}
            if '_example_label' in variant:
                row['_auto_match']['example_label']=variant['_example_label']
            checks.append(row)
    out={'version':1,'protocol':protocol,'recheck_source':True,'error_profile':'json-errors',
         'cases':checks,'_plan':{'included':len(checks),'skipped':skipped,'catalog_size':len(catalog),
             'execution_notice':'No calls made during planning. GET can have side effects; review every case. MCP annotations are untrusted hints.'}}
    if len({x['id'] for x in checks})!=len(checks):
        raise AutoPlanError('generated duplicate case IDs; refuse ambiguous scenario names')
    if len(checks)>200:
        raise AutoPlanError('more than 200 planned cases; narrow OpenAPI scope')
    if upstream:out['upstream']=upstream
    if server_cmd:out['server_cmd']=server_cmd
    return out


def main(argv=None):
    p=argparse.ArgumentParser(description='Discover actual MCP tools and conservatively map OpenAPI GET examples')
    p.add_argument('openapi',type=Path,help='local OpenAPI 3.x JSON file')
    p.add_argument('--server-json',help='MCP server argv encoded as JSON array')
    p.add_argument('--catalog',type=Path,help='saved tools/list JSON; runs no subprocess')
    p.add_argument('--upstream',help='explicit base HTTP URL for later collect (not fetched now)')
    p.add_argument('--protocol',choices=('auto','modern','legacy'),default='auto')
    p.add_argument('--out',type=Path,default=Path('risu-probe.json'))
    p.add_argument('--allow-exec',action='store_true',help='explicitly launch MCP server for tools/list only')
    p.add_argument('--force',action='store_true')
    p.add_argument('--show-skips',action='store_true')
    a=p.parse_args(argv)
    try:
        if bool(a.catalog)==bool(a.server_json):raise AutoPlanError('choose exactly one of --catalog or --server-json')
        if a.out.exists() and not a.force:raise AutoPlanError('output exists; use --force to overwrite')
        spec=json.loads(a.openapi.read_text(encoding='utf-8'))
        command=json.loads(a.server_json) if a.server_json else None
        runtime_command=None
        if command is not None and (not isinstance(command,list) or not command or
                                     not all(isinstance(x,str) and x for x in command)):
            raise AutoPlanError('--server-json must be an argv array of strings')
        if command is not None:
            if not a.allow_exec:raise AutoPlanError('--server-json requires --allow-exec for process launch')
            from risu_probe import MCPClient
            expanded=[x.replace('{python}',sys.executable).replace('{project}',str(a.openapi.parent.resolve())) for x in command]
            runtime_command=expanded
            with MCPClient(expanded,protocol=a.protocol) as client:
                catalog=list(client.list_tools_catalog().values())
                protocol=client.protocol
        else:
            obj=json.loads(a.catalog.read_text(encoding='utf-8'))
            catalog=obj['tools'] if isinstance(obj,dict) else obj
            protocol=a.protocol
        result=auto_plan(spec,catalog,upstream=a.upstream,server_cmd=runtime_command,protocol=protocol)
        from risu_collect import _atomic_private_write
        _atomic_private_write(a.out,result)
        print(f'RISU mapped {len(result["cases"])} GET operations / {len(catalog)} MCP tools; '
              f'{len(result["_plan"]["skipped"])} skipped; wrote {a.out}')
        if a.show_skips:
            for row in result['_plan']['skipped']:
                print('  skip '+str(row.get('tool',''))+': '+row['reason'])
        return 0 if result['cases'] else 1
    except (OSError,ValueError,TypeError,PlanError,AutoPlanError) as e:
        print('RISU plan-auto: '+str(e),file=sys.stderr)
        return 2

if __name__=='__main__':raise SystemExit(main())
