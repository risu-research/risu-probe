"""RISU P5-A: backward output-schema compatibility from recorded MCP evidence.

Compares advertised schema constraints only, never asserts an actual consumer
crash or a legal/operator obligation. Unsupported JSON Schema fails closed.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys
from typing import Any
from risu_nested_schema import compare

MAX_BYTES = 5_000_000


def load_output_schema(path: str, tool: str | None) -> tuple[dict, str]:
    data = Path(path).read_bytes()
    if len(data)>MAX_BYTES:
        raise ValueError('Schema evidence exceeds size limit')
    text=data.decode('utf-8')
    try:
        messages=[json.loads(text)]
    except json.JSONDecodeError:
        messages=[json.loads(line) for line in text.splitlines() if line.strip()]
    matches=[]
    for msg in messages:
        if not isinstance(msg,dict):continue
        if isinstance(msg.get('wire_utf8'),str):
            try:msg=json.loads(msg['wire_utf8'])
            except json.JSONDecodeError:raise ValueError('Malformed wrapped JSON-RPC MCP wire')
        # P4-T snapshot; hash must verify before this data is accepted.
        if msg.get('format')=='risu-contract-snapshot-v1':
            from risu_contract_history import digest
            recorded=msg.get('snapshot_sha256')
            if recorded != digest({k:v for k,v in msg.items() if k!='snapshot_sha256'}):
                raise ValueError('P4-T snapshot hash mismatch')
            if tool and msg.get('tool') not in (None,tool):continue
            if isinstance(msg.get('schema'),dict):
                matches.append((msg['schema'],'verified-P4T-snapshot'))
            continue
        roots=[msg]
        if isinstance(msg.get('result'),dict):roots.append(msg['result'])
        for root in roots:
            if isinstance(root.get('tools'),list):
                for t in root['tools']:
                    if not isinstance(t,dict):continue
                    if tool is not None and t.get('name')!=tool:continue
                    if isinstance(t.get('outputSchema'),dict):
                        matches.append((t['outputSchema'],'recorded-tools-list'))
            elif isinstance(root.get('outputSchema'),dict):
                if tool is None or root.get('name') in (None,tool):
                    matches.append((root['outputSchema'],'explicit-tool-schema'))
            elif root.get('type') is not None or any(k in root for k in ('$defs','properties','items','anyOf','oneOf','$ref')):
                matches.append((root,'independent-schema'))
    if len(matches)!=1:
        raise ValueError(f'Expected exactly one outputSchema, found {len(matches)}. Supply --tool for tools/list.')
    return copy.deepcopy(matches[0][0]),matches[0][1]


def analyze(old_path:str,new_path:str,tool:str|None=None)->dict[str,Any]:
    old,old_kind=load_output_schema(old_path,tool)
    new,new_kind=load_output_schema(new_path,tool)
    d=compare(old,new)
    d['source_evidence']={
        'old_sha256':hashlib.sha256(Path(old_path).read_bytes()).hexdigest(),
        'new_sha256':hashlib.sha256(Path(new_path).read_bytes()).hexdigest(),
        'old_kind':old_kind,'new_kind':new_kind,
        'source_is_real_mcp_capture':old_kind=='recorded-tools-list' and new_kind=='recorded-tools-list',
    }
    return d


def cli(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser(prog='risu-probe schema-compat',description='Conservative backward output schema drift with closed-object witnesses')
    p.add_argument('--old',required=True,help='old tools/list JSON, wire JSONL or explicit schema')
    p.add_argument('--new',required=True,help='new tools/list JSON, wire JSONL or explicit schema')
    p.add_argument('--tool',help='MCP tool name, required when multiple tools appear')
    p.add_argument('--out',help='output JSON path (refuses overwrite)')
    p.add_argument('--fail-on-possible-break',action='store_true',help='exit 1 if a potential consumer validator break or unknown review issue is reported')
    args=p.parse_args(argv)
    try:
        result=analyze(args.old,args.new,args.tool)
        if args.out:
            output=Path(args.out)
            if output.exists():raise ValueError('Refusing to overwrite existing report')
            output.parent.mkdir(parents=True,exist_ok=True)
            output.write_text(json.dumps(result,sort_keys=True,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        else:
            print(json.dumps(result,sort_keys=True,ensure_ascii=False,indent=2))
        if args.fail_on_possible_break and result['consumer_output_compatibility']['status'] in ('POTENTIAL_VALIDATOR_BREAK','REVIEW_REQUIRED'):
            return 1
        return 0
    except (ValueError,TypeError,KeyError,OSError,json.JSONDecodeError,UnicodeError) as e:
        print('SCHEMA_COMPAT_ERROR: '+str(e),file=sys.stderr)
        return 2

if __name__=='__main__':raise SystemExit(cli())
