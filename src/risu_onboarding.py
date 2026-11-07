"""Zero-config, non-executing first check. Never starts MCP or HTTP."""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
from risu_static import scan, ScanError


def first_check(argv=None):
    parser=argparse.ArgumentParser(description='Safe offline inspection of Python / OpenAPI files')
    parser.add_argument('project',nargs='?',default='.',type=Path)
    parser.add_argument('--json',action='store_true',help='machine-readable summary')
    args=parser.parse_args(argv)
    try:
        result=scan(args.project)
    except (OSError,ValueError,ScanError) as exc:
        print('RISU first-check: '+str(exc),file=sys.stderr)
        return 2
    total=result['summary']['eligible_files']
    summary={'version':'0.9.7-experimental','status':result['status'],
             'execution':'NONE','network_requests':0,'files_examined':total,
             'findings':len(result['findings']),
             'incomplete':len(result['incomplete'])}
    if args.json:
        print(json.dumps(summary,ensure_ascii=False,indent=2))
    else:
        print('RISU Probe first check | offline, no server or HTTP executed')
        print(f"Files found: {total}; possible losses: {summary['findings']}; unreadable/unverified: {summary['incomplete']}")
        for finding in result['findings'][:5]:
            print(f"  {finding['path']}:{finding['line']} {finding['rule_id']} [SUSPECTED]")
        if total == 0:
            print('No supported Python or OpenAPI files here. Try: risu-probe first-check PATH')
        elif result['findings']:
            print('Review findings with: risu-probe scan .  (no code is executed)')
            print('A warning requires a controlled live check before claiming data loss.')
        else:
            print('No supported warning patterns found. This is not a runtime preservation guarantee.')
        if result['incomplete']:
            print('Some files were not verified. Review: risu-probe scan . --strict-incomplete')
        print('Live checks are opt-in. Inspect target code before using --allow-exec.')
    return 0
