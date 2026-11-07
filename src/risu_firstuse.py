"""P5-D: CLI usability layer over byte-identical P5-C scanning/causality code.

The default mode remains offline and read-only. We never import user code.
Timing is opt-in and measured end-to-end by the caller's stopwatch.
"""
from __future__ import annotations

import argparse
import json
import platform
from pathlib import Path
import sys
import time
from typing import Any


class InputIssue(ValueError):
    def __init__(self, code: str, explanation: str, remedy: str):
        self.code, self.explanation, self.remedy = code, explanation, remedy
        super().__init__(explanation)


def _explain(exception: Exception) -> InputIssue:
    from risu_static import ScanError
    message = str(exception)
    low = message.lower()
    if isinstance(exception, ScanError) and 'limit exceeded' in low:
        return InputIssue('RCHK103', 'The project exceeds the bounded static-scan file budget.',
                          'Run `risu-probe check ./path/to/package` on a smaller directory. The project has not been fully checked.')
    if 'cumulative file budget' in low or 'too large' in low or 'over' in low and 'byte' in low:
        return InputIssue('RCHK103', 'The scan or evidence exceeds a configured size limit.',
                          'Choose a smaller project folder or limit the evidence. No full-coverage claim was made.')
    if 'project does not exist' in low:
        if 'symlink' not in low or 'does not exist or is symlink' in low:
            return InputIssue('RCHK101', 'The project path was not found or points to a symlink.',
                              'Run `risu-probe check .` in a real existing project directory (not a symlink).')
    if 'symlink' in low:
        return InputIssue('RCHK102', 'A symlinked project or saved evidence was refused.',
                          'Choose the real project directory or a regular, local copy of the saved evidence.')
    if 'target must be an existing' in low or 'no such file' in low:
        return InputIssue('RCHK101', 'The project path was not found.',
                          'Run `risu-probe check .` in the project root or pass an existing path.')
    if 'report' in low and ('overwrite' in low or 'exists' in low):
        return InputIssue('RCHK105', 'An output report with this name already exists.',
                          'Choose a new `--out` filename; RISU will not overwrite existing reports.')
    if 'evidence' in low or 'mcp transcript' in low or 'wire' in low:
        return InputIssue('RCHK104', 'Saved consumer evidence is unavailable, incomplete, or failed validation.',
                          'Use `--evidence` with full_chain.json and both adjacent MCP JSONL transcripts. Verify the CI provenance separately.')
    if isinstance(exception, PermissionError):
        return InputIssue('RCHK106', 'The current user cannot read the requested project or evidence.',
                          'Check file permissions or run against a readable project copy. Do not elevate privileges by default.')
    if isinstance(exception, (ScanError, ValueError, OSError)):
        return InputIssue('RCHK199', 'The scan could not complete safely: ' + message[:100],
                          'Try `risu-probe doctor` and narrow the project. No compatibility verdict was issued.')
    return InputIssue('RCHK199', 'The check could not complete.',
                      'Try `risu-probe doctor`; inspect the project path and evidence inputs.')


def doctor(format: str = 'text') -> dict[str, Any]:
    from importlib import metadata, util
    version=metadata.version('risu-probe-preview')
    return {
        'tool': 'RISU Probe',
        'version': version,
        'python': platform.python_version(),
        'platform': platform.system(),
        'architecture': platform.machine(),
        'pypi_yaml_support_installed': util.find_spec('yaml') is not None,
        'default_scope': 'STATIC_ONLY_NO_PROJECT_IMPORT_OR_NETWORK',
        'commands': ['risu-probe check .', 'risu-probe check . --format json', 'risu-probe doctor'],
        'help': 'The default RISU Probe installation includes PyYAML for OpenAPI YAML. If YAML is unavailable, reinstall the package with its declared dependencies; skipped files are UNVERIFIED.'
    }


def doctor_cli(argv: list[str]) -> int:
    p=argparse.ArgumentParser(prog='risu-probe doctor',description='Read-only installation and capability self-check')
    p.add_argument('--format', choices=('text','json'), default='text')
    args=p.parse_args(argv)
    try:
        result=doctor(args.format)
    except Exception as ex:
        issue=_explain(ex)
        print(f'{issue.code}: {issue.explanation}\nNext: {issue.remedy}', file=sys.stderr)
        return 2
    if args.format=='json':print(json.dumps(result,sort_keys=True,ensure_ascii=False))
    else:
        print(f"RISU Probe {result['version']} | {result['platform']} {result['architecture']} | Python {result['python']}")
        print('Default: static/read-only; no project imports, HTTP requests, or MCP server starts.')
        print('YAML OpenAPI support: '+('available' if result['pypi_yaml_support_installed'] else 'not installed (reinstall with dependencies)'))
        print('Next: risu-probe check .')
    return 0


def cli(argv: list[str] | None=None) -> int:
    from risu_quickcheck import as_text, as_sarif, check, EvidenceError
    from risu_static import ScanError
    p=argparse.ArgumentParser(prog='risu-probe check',
        description='First-use offline diagnostics; never imports or executes your project')
    p.add_argument('project',nargs='?',default='.',help='existing project folder or Python/OpenAPI file')
    p.add_argument('--evidence',type=Path,help='saved P5-B evidence report, with paired raw MCP transcripts')
    p.add_argument('--format',choices=('text','json','sarif'),default='text')
    p.add_argument('--out',type=Path,help='new output path (existing files are never overwritten)')
    p.add_argument('--fail-on-confirmed',action='store_true',help='exit 1 for verified SAVED-REPLAY consumer issues')
    p.add_argument('--fail-on-suspected',action='store_true',help='exit 1 for static hypotheses (opt in)')
    p.add_argument('--strict-incomplete',action='store_true',help='exit 2 when scan coverage is incomplete')
    p.add_argument('--timing',action='store_true',help='include wall-clock scanning time (excludes Python startup)')
    args=p.parse_args(argv)
    start=time.perf_counter()
    try:
        report=check(Path(args.project), args.evidence)
        report['version']='0.9.20-experimental'
        # Preserve evidence classifications. Incomplete status must be plainly visible.
        if report.get('unverified'):
            report['coverage_note']='Coverage incomplete: at least one file or saved evidence input was not verified. No pass/compatible claim.'
        elif report['summary']['python_parsed']+report['summary']['openapi_parsed']==0 and not report['confirmed']:
            report['coverage_note']='Unsupported or empty source scope; no relevant source was analyzed.'
        else:
            report['coverage_note']='Eligible discovered sources parsed without reported gaps; static absence of findings does not guarantee behavioral preservation.'
        if args.timing:
            report['performance']={'scan_wall_ms':round((time.perf_counter()-start)*1000,3),
                                   'excludes_process_startup':True}
        if args.format=='text':
            content=as_text(report).replace('RISU Probe check 0.9.18', 'RISU Probe check 0.9.20', 1)
            if report.get('unverified'):
                remedies=[]
                for gap in report['unverified'][:8]:
                    reason=gap.get('reason','')
                    if 'PyYAML' in reason:remedies.append('YAML schema was skipped. Reinstall RISU Probe with dependencies so PyYAML is available, then rerun.')
                    if 'budget' in reason or 'limit' in reason:remedies.append('File limits reached. Scan a smaller package to improve coverage.')
                content+='\nCoverage: INCOMPLETE. No full-project compatibility conclusion.\n'
                for remedy in dict.fromkeys(remedies):content+='Next: '+remedy+'\n'
            elif report['summary']['python_parsed']+report['summary']['openapi_parsed']==0 and not report['confirmed']:
                content+='\nCoverage: UNSUPPORTED. Point RISU at a Python or OpenAPI project.\n'
            if args.timing:content+=f"Scan time: {report['performance']['scan_wall_ms']} ms (excludes startup)\n"
        elif args.format=='json':content=json.dumps(report,ensure_ascii=False,sort_keys=True,indent=2)+'\n'
        else:
            sarif=as_sarif(report)
            sarif['runs'][0]['tool']['driver']['version']='0.9.20'
            sarif['runs'][0]['properties']['coverage_note']=report['coverage_note']
            if args.timing:sarif['runs'][0]['properties']['performance']=report['performance']
            content=json.dumps(sarif,ensure_ascii=False,sort_keys=True,indent=2)+'\n'
        if args.out:
            dest=args.out.expanduser()
            if dest.exists() or dest.is_symlink():
                raise InputIssue('RCHK105', 'The report already exists.',
                                 'Choose a new `--out` path. RISU does not overwrite files.')
            dest.parent.mkdir(parents=True,exist_ok=True)
            with dest.open('x',encoding='utf-8') as stream:stream.write(content)
        else:print(content,end='')
        if report['status']=='INCOMPLETE_EVIDENCE' or args.strict_incomplete and report['unverified']:
            return 2
        if args.fail_on_confirmed and report['confirmed'] or args.fail_on_suspected and report['suspected']:
            return 1
        return 0
    except (EvidenceError,ScanError,ValueError,TypeError,KeyError,OSError,UnicodeError,RecursionError) as exception:
        issue=exception if isinstance(exception,InputIssue) else _explain(exception)
        print(f'{issue.code}: {issue.explanation}\nNext: {issue.remedy}',file=sys.stderr)
        return 2

if __name__=='__main__':raise SystemExit(cli())
