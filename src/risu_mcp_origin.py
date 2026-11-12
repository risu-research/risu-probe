"""B17 offline upstream-source corroboration of captured MCP tool contracts.

Git blob + full commit pin + conservative static AST + in-band same-session
tools/list. The tool does NOT execute source code, contact GitHub, authenticate
server process identity, infer authorization, or trust human-language hints.

A local Git checkout is user-supplied. The provenance claim is conditional on
the separately verified GitHub repo/revision: an independently audited CI
fetch of the remote tree is required to ground repository ownership.
"""
from __future__ import annotations
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

from risu_mcp_authority import correlate, verify as verify_catalog
from risu_mcp_observations import _load, validate_contract, MAX_CONTRACT, MAX_WITNESS
from risu_mcp_trace import _read_trace, TraceError

SCHEMA = 'risu-mcp-upstream-source-manifest-v1'
MAX_SOURCE_BYTES = 262144
MAX_SOURCES = 16
HEX40 = re.compile('[0-9a-f]{40}\\Z')
REPO = re.compile('[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\\Z')


class OriginError(ValueError):
    pass


def canon(obj):
    return json.dumps(obj,sort_keys=True,ensure_ascii=False,separators=(',',':'))


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def safe_path(path):
    if type(path) is not str or len(path)>220 or '\\' in path or path.startswith('/'):
        raise OriginError('INVALID_SOURCE_RELATIVE_PATH')
    pure=PurePosixPath(path)
    if len(pure.parts)>12 or not pure.parts or any(p in ('.','..') for p in pure.parts):
        raise OriginError('UNSAFE_SOURCE_PATH')
    return path


def validate_manifest(doc):
    if type(doc) is not dict or set(doc)!= {'schema','repository','revision','sources'}:
        raise OriginError('INVALID_SOURCE_MANIFEST_FIELDS')
    if doc['schema']!=SCHEMA or type(doc['repository']) is not str or not REPO.fullmatch(doc['repository']):
        raise OriginError('INVALID_REPOSITORY_DECLARATION')
    if type(doc['revision']) is not str or not HEX40.fullmatch(doc['revision']):
        raise OriginError('REVISION_MUST_BE_FULL_SHA1')
    if type(doc['sources']) is not list or not 1<=len(doc['sources'])<=MAX_SOURCES:
        raise OriginError('SOURCE_MANIFEST_SIZE')
    found=set()
    for entry in doc['sources']:
        if type(entry) is not dict or set(entry)!={'tool','path','git_blob_sha1'}:
            raise OriginError('INVALID_SOURCE_ENTRY')
        name=entry['tool']
        if type(name) is not str or not 1<=len(name)<=128:
            raise OriginError('INVALID_SOURCE_TOOL')
        path=safe_path(entry['path'])
        blob=entry['git_blob_sha1']
        if type(blob) is not str or not HEX40.fullmatch(blob):
            raise OriginError('INVALID_SOURCE_BLOB_PIN')
        if name in found:
            raise OriginError('AMBIGUOUS_SOURCE_TOOL_ENTRY')
        found.add(name)
    return doc


def git(root, *args, max_bytes=MAX_SOURCE_BYTES):
    env={
        'PATH':os.environ.get('PATH',''),
        'HOME':str(root),'GIT_CONFIG_NOSYSTEM':'1',
        'GIT_CONFIG_GLOBAL':'/dev/null',
        'GIT_TERMINAL_PROMPT':'0','GIT_OPTIONAL_LOCKS':'0',
    }
    try:
        proc=subprocess.run(['git','-C',str(root),'-c','core.hooksPath=/dev/null',*args],
            stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=env,
            timeout=12,check=False)
    except (OSError,subprocess.TimeoutExpired) as e:
        raise OriginError('GIT_OBJECT_INSPECTION_UNAVAILABLE') from e
    if proc.returncode!=0 or len(proc.stdout)>max_bytes:
        raise OriginError('GIT_PIN_OR_SOURCE_OBJECT_UNAVAILABLE')
    return proc.stdout


def pinned_sources(root,manifest):
    root=root.resolve(strict=True)
    commit=manifest['revision']
    current=git(root,'rev-parse','--verify','HEAD',max_bytes=200).decode().strip()
    if current!=commit:
        raise OriginError('CHECKOUT_HEAD_REVISION_DISAGREES_WITH_PIN')
    if git(root,'cat-file','-t',commit,max_bytes=100).strip()!=b'commit':
        raise OriginError('PINNED_REVISION_NOT_A_COMMIT')
    files={}
    for item in manifest['sources']:
        path=item['path']
        file=root.joinpath(*PurePosixPath(path).parts)
        if file.is_symlink() or not file.is_file() or file.stat().st_size>MAX_SOURCE_BYTES:
            raise OriginError('INVALID_OR_SYMLINKED_WORKTREE_SOURCE_FILE')
        raw=file.read_bytes()
        blob=git(root,'rev-parse',f'{commit}:{path}',max_bytes=100).decode().strip()
        if blob!=item['git_blob_sha1'] or git(root,'cat-file','-t',blob,max_bytes=100).strip()!=b'blob':
            raise OriginError('DECLARED_GIT_TREE_BLOB_MISMATCH')
        object_bytes=git(root,'cat-file','blob',blob)
        if object_bytes!=raw:
            raise OriginError('WORKTREE_BYTES_DIVERGE_FROM_PINNED_GIT_BLOB')
        # Git blob SHA-1 is a VCS locator; separate SHA-256 avoids
        # treating collision-prone SHA-1 as the only content checksum.
        envelope=b'blob '+str(len(raw)).encode()+b'\\x00'+raw
        if hashlib.sha1(envelope).hexdigest()!=blob:
            raise OriginError('GIT_BLOB_CONTENT_ID_MISMATCH')
        files[item['tool']]={'path':path,'git_blob_sha1':blob,
            'source_sha256':sha256(raw),'source_text':raw}
    return files


def static_tool_declaration(raw,tool):
    """Conservative literal-only Python Tool(name=..., outputSchema=...) AST."""
    try:
        syntax=ast.parse(raw.decode('utf-8'))
    except (UnicodeError,SyntaxError,ValueError) as e:
        return None,'UNSUPPORTED_SOURCE_SYNTAX'
    found=[]
    for node in ast.walk(syntax):
        if not isinstance(node,ast.Call):continue
        func=node.func
        if not (isinstance(func,ast.Attribute) and func.attr=='Tool' and
                isinstance(func.value,ast.Name) and func.value.id=='types'):
            continue
        keys={kw.arg:kw.value for kw in node.keywords if kw.arg is not None}
        if 'name' not in keys:continue
        try:name=ast.literal_eval(keys['name'])
        except (ValueError,TypeError,MemoryError,RecursionError):continue
        if name!=tool:continue
        found.append(keys)
    if len(found)!=1:
        return None,'SOURCE_TOOL_LITERAL_NOT_UNIQUE' if found else 'SOURCE_TOOL_LITERAL_NOT_PRESENT'
    keys=found[0]
    if 'outputSchema' not in keys:
        return None,'SOURCE_TOOL_HAS_NO_EXPLICIT_OUTPUT_SCHEMA'
    try:output=ast.literal_eval(keys['outputSchema'])
    except (ValueError,TypeError,MemoryError,RecursionError):
        return None,'DYNAMIC_SCHEMA_SOURCE_NOT_ATTESTABLE'
    if type(output) is not dict:
        return None,'SOURCE_OUTPUT_SCHEMA_NOT_OBJECT'
    return output,''


def verify(trace,contract,source_manifest,source_checkout,witness=None):
    validate_contract(contract)
    manifest=validate_manifest(source_manifest)
    evidence=pinned_sources(source_checkout,manifest)
    baseline=verify_catalog(trace,contract,witness)
    records,digest=_read_trace(trace)
    calls,anomalies=correlate(records)
    by_start={v['request_line']:v for v in calls}
    source_decls={}
    for tool,data in evidence.items():
        decl,why=static_tool_declaration(data['source_text'],tool)
        source_decls[tool]={'output':decl,'reason':why,'sha256':data['source_sha256'],
                            'blob':data['git_blob_sha1'],'path':data['path']}
    rule_lookup={hashlib.sha256(r['id'].encode()).hexdigest()[:12]:r for r in contract['rules']}
    checks=[]
    for check in baseline['checks']:
        call=by_start.get(check['request_line'])
        rule=rule_lookup.get(check['rule_hash'])
        if call is None or rule is None or call['name']!=rule['tool']:
            raise OriginError('B16_CHECK_NOT_CORRELATED_TO_SAME_RAW_CALL')
        source=source_decls.get(rule['tool'])
        descriptor=(call['snapshot'] or {}).get('tools',{}).get(rule['tool'])
        if source is None:
            reason='NO_PINNED_SOURCE_FOR_TOOL'
            level='UNVERIFIED_SOURCE'
        elif check['authority_grade']!='CATALOG_NORMATIVE':
            reason='NO_CONTEMPORANEOUS_NORMATIVE_CATALOG_OBLIGATION'
            level='NO_PROMOTION'
        elif source['output'] is None:
            reason=source['reason']
            level='UNVERIFIED_SOURCE'
        elif type(descriptor) is not dict or type(descriptor.get('outputSchema')) is not dict:
            reason='MISSING_BOUND_CATALOG_SCHEMA'
            level='UNVERIFIED_SOURCE'
        elif source['output']!=descriptor['outputSchema']:
            reason='PINNED_SOURCE_SCHEMA_DISAGREES_WITH_CATALOG'
            level='SOURCE_CATALOG_CONFLICT'
        else:
            reason='GIT_PINNED_LITERAL_OUTPUT_SCHEMA_MATCHES_SAME_SESSION_CATALOG'
            level='SOURCE_DECLARATION_CORROBORATED'
        disposition=('SOURCE_CORROBORATED_MISMATCH'
                    if level=='SOURCE_DECLARATION_CORROBORATED' and check['observed']=='MISMATCH'
                    else 'SOURCE_CORROBORATED_PASS'
                    if level=='SOURCE_DECLARATION_CORROBORATED' and check['observed']=='PASS'
                    else 'QUARANTINED_SOURCE_CONFLICT'
                    if level=='SOURCE_CATALOG_CONFLICT'
                    else 'NOT_PROMOTED')
        checks.append({
            'request_line':check['request_line'],
            'response_line':check['response_line'],
            'tool_hash':check['tool_hash'],'rule_hash':check['rule_hash'],
            'base_authority_grade':check['authority_grade'],
            'base_observation':check['observed'],
            'base_disposition':check['disposition'],
            'source_level':level,'source_reason':reason,
            'source_file_sha256':source['sha256'] if source else None,
            'source_blob_sha1':source['blob'] if source else None,
            'source_path':source['path'] if source else None,
            'catalog_sha256':check['catalog_sha256'],
            'disposition':disposition
        })
    counts={state:sum(c['disposition']==state for c in checks)
            for state in ('SOURCE_CORROBORATED_MISMATCH','SOURCE_CORROBORATED_PASS',
                          'QUARANTINED_SOURCE_CONFLICT','NOT_PROMOTED')}
    return {'schema':'risu-mcp-upstream-source-report-v1',
        'trace_sha256':digest,'manifest_sha256':sha256(canon(source_manifest).encode()),
        'claimed_repository':manifest['repository'],'claimed_full_commit':manifest['revision'],
        'sources_verified_against_local_git_objects':len(evidence),
        'source_files':[{'tool_hash':hashlib.sha256(k.encode()).hexdigest()[:16],
                         'path':v['path'],'git_blob_sha1':v['blob'],
                         'file_sha256':v['sha256'],'static_parse_reason':source_decls[k]['reason']}
                        for k,v in evidence.items()],
        'summary':{'matched_obligations':len(checks),**counts,
                   'uncorrelated_catalog_anomalies':len(anomalies)},
        'checks':checks,
        'trust_boundary':'Local pinned Git objects and literal source AST, cross-checked against same-session catalog. Repository owner identity and source-to-executed-server identity are NOT authenticated by this offline tool. Independently verify remote publisher commit and Git tree through trusted external channel; source code is never executed.'}


def cli(argv=None):
    p=argparse.ArgumentParser(prog='risu-probe verify-mcp-origin')
    p.add_argument('trace',type=Path)
    p.add_argument('--contract',required=True,type=Path)
    p.add_argument('--source-manifest',required=True,type=Path)
    p.add_argument('--source-checkout',required=True,type=Path)
    p.add_argument('--witness',type=Path)
    p.add_argument('--format',choices=('text','json'),default='text')
    p.add_argument('--out',type=Path)
    p.add_argument('--fail-on-source-mismatch',action='store_true')
    a=p.parse_args(argv)
    try:
        res=verify(a.trace,_load(a.contract,MAX_CONTRACT),
              _load(a.source_manifest,32768),a.source_checkout,
              _load(a.witness,MAX_WITNESS) if a.witness else None)
        s=res['summary']
        out=json.dumps(res,indent=2,ensure_ascii=False,sort_keys=True)+'\\n' if a.format=='json' else (
            'RISU source provenance | matched='+str(s['matched_obligations'])+
            ' verified_mismatches='+str(s['SOURCE_CORROBORATED_MISMATCH'])+
            ' source_conflicts='+str(s['QUARANTINED_SOURCE_CONFLICT'])+'\\n')
        if a.out:
            with a.out.expanduser().absolute().open('x',encoding='utf-8') as f:f.write(out)
        else:print(out,end='')
        if a.fail_on_source_mismatch and (
            s['SOURCE_CORROBORATED_MISMATCH'] or s['QUARANTINED_SOURCE_CONFLICT']):
            return 1
        return 0
    except (OriginError,TraceError,ValueError,TypeError,UnicodeError,OSError,
            RecursionError) as e:
        print('RMO800 SOURCE_PROVENANCE_UNVERIFIED: '+type(e).__name__,file=sys.stderr)
        return 2

if __name__=='__main__':
    raise SystemExit(cli())
