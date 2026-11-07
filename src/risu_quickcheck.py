"""P5-C: configuration-free, offline-first RISU Probe project entry point.

Reuses the installed RISU static analyzer. Does not import/run target modules,
open sockets, spawn servers, follow file symlinks, or silently certify unknowns.
Saved P5-B replay evidence requires both complete MCP wire transcripts and
internal crosschecks before reporting a confirmed-in-replay consumer impact.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

from risu_static import scan, ScanError

MAX_REPORT = 2_000_000
MAX_WIRE = 4_000_000
MAX_FRAME = 1_000_000
MAX_LINES = 400

class EvidenceError(ValueError):
    pass


def _safe_file(path: Path, root: Path, max_size: int) -> bytes:
    """Refuse path/symlink escapes and non-regular files; no calls to target code."""
    root = root.resolve(strict=True)
    if path.is_symlink() or any(x.is_symlink() for x in (path, *list(path.parents)[:12]) if x != root):
        raise EvidenceError('symlink in evidence path')
    actual = path.resolve(strict=True)
    if not actual.is_relative_to(root) or not actual.is_file():
        raise EvidenceError('evidence escapes project or is not a regular file')
    length = actual.stat().st_size
    if length > max_size:
        raise EvidenceError(f'evidence over {max_size} byte budget')
    return actual.read_bytes()


def _load_json(path: Path, root: Path, limit: int) -> dict:
    try:
        d = json.loads(_safe_file(path, root, limit))
    except (UnicodeError, json.JSONDecodeError) as ex:
        raise EvidenceError('evidence contains invalid JSON') from ex
    if not isinstance(d, dict):
        raise EvidenceError('evidence JSON root must be an object')
    return d


def _load_wire(path: Path, root: Path, expected_sha: str) -> list[dict]:
    raw = _safe_file(path, root, MAX_WIRE)
    if hashlib.sha256(raw).hexdigest() != expected_sha:
        raise EvidenceError('MCP transcript SHA-256 mismatch')
    lines = raw.splitlines()
    if not 3 <= len(lines) <= MAX_LINES:
        raise EvidenceError('MCP transcript frame count invalid')
    result = []
    for raw_line in lines:
        if len(raw_line) > MAX_FRAME:
            raise EvidenceError('MCP transcript oversized JSONL frame')
        try:
            item = json.loads(raw_line)
        except json.JSONDecodeError as ex:
            raise EvidenceError('invalid JSONL MCP transcript') from ex
        if not isinstance(item, dict) or not isinstance(item.get('frame'), dict):
            raise EvidenceError('invalid recorded MCP frame wrapper')
        result.append(item)
    return result


def _responses(frames: list[dict]) -> tuple[dict, dict, int, int]:
    calls = {}
    out = {}
    num_repairs = 0
    for entry in frames:
        direction, frame = entry.get('direction'), entry['frame']
        if direction == 'client_to_proxy' and frame.get('method') == 'tools/call':
            ident = frame.get('id')
            if type(ident) is not int or ident in calls or frame.get('params', {}).get('name') != 'get_index':
                raise EvidenceError('unexpected or duplicate test MCP tool call')
            calls[ident] = frame['params'].get('arguments')
        elif direction == 'proxy_to_client' and type(frame.get('id')) is int and 'result' in frame:
            out[frame['id']] = frame['result']
        elif direction == 'repair_event' and frame.get('changed') is True:
            num_repairs += 1
    if set(calls) != {3,4,5,6} or not set(calls) <= set(out):
        raise EvidenceError('not all four recorded MCP calls have responses')
    if not all(calls[i] == {'path_indexUid': 'movies'} for i in (3,4)):
        raise EvidenceError('positive control request changed')
    if not all(calls[i] == {'path_indexUid': 'does-not-exist'} for i in (5,6)):
        raise EvidenceError('error control request changed')
    return calls, out, len(calls), num_repairs


def _compatible_with_report(response: dict, case: dict) -> bool:
    m = case['raw_mcp']
    return (response.get('structuredContent') == m.get('structuredContent')
            and response.get('isError', False) is m.get('isError', False))


def audit_p5b(root: Path, report_path: Path) -> dict:
    """Derive consumer impact from raw wire and original/converted/repaired outcomes.

    It is a *saved* third-party replay, never a new live test. The report's
    provenance is not self-authenticating: verify the CI run separately.
    """
    report = _load_json(report_path, root, MAX_REPORT)
    if report.get('schema') != 'risu-p5b-original-converted-consumer-failure-repair-v1':
        raise EvidenceError('unsupported consumer evidence format')
    execution = report.get('execution', {})
    if not (execution.get('actual_cnoe_generated_mcp_stdio') is True
            and execution.get('actual_langchain_as_langchain_tool') is True
            and execution.get('no_vendor_production_requests') is True
            and execution.get('no_llm_run') is True
            and execution.get('unexpected_http') == []):
        raise EvidenceError('required P5-B execution boundaries missing')
    if not (report.get('original_consumer',{}).get('status') == 'PASS'
            and report.get('converted_consumer',{}).get('status') == 'EXPECTED_APPLICATION_CONTRACT_FAILURE'
            and report.get('repaired_consumer',{}).get('status') == 'PASS'):
        raise EvidenceError('source/conversion/repair outcomes do not match confirmed replay')
    original = report['original_consumer']['result']
    repaired = report['repaired_consumer']['result']
    code = original.get('code')
    if not isinstance(code, str) or not code or code != repaired.get('code'):
        raise EvidenceError('source and repaired error contract differ')
    if 'SOURCE_ERROR_CODE_UNAVAILABLE' not in str(report['converted_consumer'].get('reason','')):
        raise EvidenceError('the declared consumer error condition is not specific')
    info = report.get('wire_audits', {})
    outcomes = report.get('phase_results', {})
    checked = {}
    for name in ('passthrough','repair'):
        metadata = info.get(name, {})
        expected_sha = metadata.get('wire_sha256')
        if not isinstance(expected_sha,str) or len(expected_sha)!=64:
            raise EvidenceError('wire SHA-256 missing')
        frames = _load_wire(report_path.parent / (name+'_wire.jsonl'), root, expected_sha)
        calls, responses, count, repairs = _responses(frames)
        if metadata.get('client_tool_calls') != count or metadata.get('recorded_frames') != len(frames) or metadata.get('repair_events') != repairs:
            raise EvidenceError('wire counts disagree with report')
        cases = outcomes.get(name)
        if not isinstance(cases,list) or len(cases)!=2 or {x.get('case') for x in cases}!={'success','error'}:
            raise EvidenceError('expected source cases missing')
        cases_by_name = {x['case']:x for x in cases}
        for phase, ident in [('success', 4),('error',6)]:
            if not _compatible_with_report(responses[ident],cases_by_name[phase]):
                raise EvidenceError('MCP reply contradicts saved consumer report')
        success = responses[4]; error = responses[6]
        if success.get('isError') is not False or not isinstance(success.get('structuredContent'),dict):
            raise EvidenceError('read-only positive control not successful')
        checked[name] = {'success':success,'error':error,'consumer':cases_by_name['error']['langchain'],
                         'wire_sha256':expected_sha,'frame_count':len(frames)}
    baseline, fix = checked['passthrough'], checked['repair']
    old = baseline['error']; new = fix['error']
    old_fields = old.get('structuredContent',{}); new_fields = new.get('structuredContent',{})
    if not isinstance(old_fields,dict) or not isinstance(new_fields,dict):
        raise EvidenceError('MCP response must expose structured errors')
    if old.get('isError') is not False or new.get('isError') is not True:
        raise EvidenceError('MCP error flags do not support the claimed contrast')
    if code in json.dumps(old_fields,ensure_ascii=False) or new_fields.get('code') != code:
        raise EvidenceError('source error code contrast cannot be confirmed')
    if baseline['consumer'].get('status') != 'success' or fix['consumer'].get('status') != 'error':
        raise EvidenceError('third-party consumer statuses unexpectedly differ')
    if baseline['consumer'].get('artifact',{}).get('structured_content',{}).get('code') == code:
        raise EvidenceError('old consumer already had source error code')
    if baseline['success']['structuredContent'] != fix['success']['structuredContent']:
        raise EvidenceError('repair changed successful tool result')
    if not (info['passthrough'].get('repair_events') == 0 and info['repair'].get('repair_events') == 2):
        raise EvidenceError('repair intervention boundary not demonstrated')
    return {
        'rule_id':'RMC301','code':'SOURCE_ERROR_FIELD_LOSS','severity':'error',
        'confidence':'CONFIRMED_IN_SAVED_REPLAY',
        'path':report_path.relative_to(root).as_posix(),
        'line':1,
        'message':'Source HTTP error fields are unavailable to the recorded downstream consumer after MCP conversion; a test-only source-backed adapter restores the application condition.',
        'source':'Official Meilisearch public OpenAPI 404 example, with original SDK interpreter',
        'boundary':'CNOE-generated MCP -> LangChain ToolMessage -> fixed application contract',
        'structured_fields_unavailable':['code','type','link'],
        'consumer_results':{'original':'PASS','converted':'FAIL_APPLICATION_CONTRACT','repaired':'PASS'},
        'mcp_isError':{'converted':False,'repaired':True},
        'no_production_traffic':True,
        'replay_transcript_sha256':{x:checked[x]['wire_sha256'] for x in ('passthrough','repair')},
        'limits':'Saved externally executed replay, not a live scan of this project or proof of a general vendor defect. Repair needs access to trusted source HTTP error body; no automatic patch.',
        'next_step':'At a trusted producer boundary, preserve reviewed machine-readable HTTP error fields and the error flag; independently replay the affected consumer. Do not automatically expose unknown or sensitive error bodies.',
    }


def check(path: Path, evidence: Path | None = None) -> dict[str, Any]:
    target = path.expanduser()
    if target.is_symlink() or not target.exists():
        raise EvidenceError('project does not exist or is symlink')
    root = target.resolve() if target.is_dir() else target.resolve().parent
    if not root.is_dir():
        raise EvidenceError('project root is not a directory')
    static = scan(target)
    confirmed = []; gaps = []
    if evidence is not None:
        selected = evidence if evidence.is_absolute() else root / evidence
        if not selected.exists():
            raise EvidenceError('explicit evidence report unavailable')
    else:
        candidates = [root/'results'/'full_chain.json',root/'full_chain.json']
        selected = next((p for p in candidates if p.exists()), None)
    if selected is not None:
        try:
            confirmed.append(audit_p5b(root, selected))
        except (OSError,ValueError,KeyError,TypeError,UnicodeError,AttributeError,ScanError) as ex:
            gaps.append({'path':selected.relative_to(root).as_posix(),
                         'reason':'SAVED_CONSUMER_EVIDENCE_REJECTED: '+str(ex)[:130]})
    if static['status']=='UNVERIFIED' and not confirmed and not gaps:
        gaps.append({'path':'.','reason':'No parseable Python/OpenAPI code or verified consumer evidence found'})
    hypotheses = [{**f,'confidence':'STATIC_HYPOTHESIS'} for f in static['findings']]
    issues = list(static['incomplete']) + gaps
    status = ('INCOMPLETE_EVIDENCE' if gaps or static['status']=='UNVERIFIED' and not confirmed
              else 'PARTIAL' if issues else
              'CONFIRMED_IN_SAVED_REPLAY' if confirmed else
              'STATIC_HYPOTHESES' if hypotheses else 'NO_STATIC_FINDINGS')
    return {
       'tool':'RISU Probe','version':'0.9.18-experimental','command':'check',
       'scope':'LOCAL_READ_ONLY_NO_EXEC_NO_NETWORK', 'project':'.',
       'status':status,
       'summary':{'python_parsed':static['summary']['python_parsed'],
                  'openapi_parsed':static['summary']['openapi_parsed'],
                  'openapi_read_only_gets':static['summary']['openapi_get_total'],
                  'openapi_ready_candidates':static['summary']['openapi_get_ready_candidates'],
                  'openapi_need_review':static['summary']['openapi_get_needing_review'],
                  'static_candidates':len(hypotheses),'confirmed_saved_replay':len(confirmed),
                  'unverified':len(issues)},
       'confirmed':confirmed,'suspected':hypotheses,
       'openapi':static['openapi'],'unverified':issues,
       'next_step':'Use a reviewed explicit runtime configuration to test a live server; the default check never executes it.',
       'disclaimer':'No target import, HTTP call, MCP call, server startup, or auto repair. Saved replay claims require separately authenticated provenance. No findings is never a preservation guarantee.'
    }


def as_text(report: dict) -> str:
    s=report['summary']
    lines=[f"RISU Probe check 0.9.18 | {report['status']}",
           f"  {s['python_parsed']} Python files; {s['openapi_parsed']} OpenAPI specs; {s['confirmed_saved_replay']} replay-confirmed; {s['static_candidates']} suspected; {s['unverified']} unverified",'']
    for spec in report['openapi']:
        lines.append(f"  OpenAPI {spec['path']}: {spec['get_total']} GET; {spec['get_with_explicit_examples_or_no_required_arguments']} safe candidate plans; {spec['get_needing_examples_or_manual_review']} need review")
    if report['openapi']:
        lines.append('  Review candidates before any HTTP/MCP execution; default check performs no requests.')
        lines.append('')
    for c in report['confirmed']:
        lines.extend([f"  {c['path']}:{c['line']}: {c['rule_id']} {c['code']} [CONFIRMED IN SAVED REPLAY]",
                      '    HTTP error has machine-readable code, type, link; converted MCP result omits these fields.',
                      '    Consumer: original PASS  |  converted FAIL  |  repaired PASS',
                      '    Cause: upstream error metadata is not preserved at the converter boundary.',
                      '    Fix: '+c['next_step'],
                      '    Evidence: paired MCP stdio replay transcripts SHA-256 crosschecked; no production claims.',
                      ''])
    for f in report['suspected']:
        lines.extend([f"  {f['path']}:{f['line']}: {f['rule_id']} {f['code']} [SUSPECTED]",
                      '    '+f['evidence'], '    Next: '+f['next_step'],''])
    for gap in report['unverified'][:30]:
        lines.append(f"  UNVERIFIED {gap['path']}: {gap['reason']}")
    lines.append('Default is offline/read-only. Static findings are hypotheses; saved replay is not a current project execution.')
    lines.append('Commands: risu-probe check . --format json  |  risu-probe scan .  |  risu-probe check --help')
    return '\n'.join(lines)+'\n'


def as_sarif(report: dict) -> dict:
    from risu_static import RULES
    rules=[{'id':rid,'shortDescription':{'text':values[0]},
            'help':{'text':values[3]}} for rid,values in RULES.items()]
    rules.append({'id':'RMC301','shortDescription':{'text':'SOURCE_ERROR_FIELD_LOSS'},
                  'help':{'text':'Compare producer error fields with actual MCP and consumer replay.'}})
    issues=[]
    for entry in report['confirmed']+report['suspected']:
        issues.append({'ruleId':entry['rule_id'],
                       'level':'error' if entry in report['confirmed'] else entry['severity'],
                       'message':{'text':entry['message']},
                       'locations':[{'physicalLocation':{'artifactLocation':{'uri':entry['path']},
                                                        'region':{'startLine':entry['line']}}}],
                       'properties':{'confidence':entry['confidence'],
                                     'scope':report['scope']}})
    return {'$schema':'https://json.schemastore.org/sarif-2.1.0.json','version':'2.1.0',
            'runs':[{'tool':{'driver':{'name':'RISU Probe','version':'0.9.18','rules':rules}},
                     'results':issues,
                     'properties':{'status':report['status'],'summary':report['summary'],
                                   'unverified':report['unverified']}}]}


def cli(argv: list[str] | None=None) -> int:
    p=argparse.ArgumentParser(prog='risu-probe check',
        description='Zero-config offline-first project check. Never runs project code or connects to a server.')
    p.add_argument('project',nargs='?',default='.',help='existing Python or OpenAPI project directory')
    p.add_argument('--evidence',type=Path,help='explicit saved P5-B full_chain.json with adjacent raw MCP wire files')
    p.add_argument('--format',choices=('text','json','sarif'),default='text')
    p.add_argument('--out',type=Path,help='optional report file; refuses to overwrite')
    p.add_argument('--fail-on-confirmed',action='store_true',help='exit 1 when replay-confirmed consumer loss was discovered')
    p.add_argument('--fail-on-suspected',action='store_true',help='exit 1 on static-only hypotheses (opt in)')
    p.add_argument('--strict-incomplete',action='store_true',help='exit 2 if any source or evidence remains unverified')
    args=p.parse_args(argv)
    try:
        report=check(Path(args.project),args.evidence)
        content=(as_text(report) if args.format=='text' else
                 json.dumps(as_sarif(report) if args.format=='sarif' else report,ensure_ascii=False,sort_keys=True,indent=2)+'\n')
        if args.out:
            dest=args.out.expanduser()
            if dest.exists() or dest.is_symlink():
                raise EvidenceError('refusing to overwrite an existing report')
            dest.parent.mkdir(parents=True,exist_ok=True)
            dest.write_text(content,encoding='utf-8')
        else:
            print(content,end='')
        if report['status']=='INCOMPLETE_EVIDENCE' or args.strict_incomplete and report['unverified']:
            return 2
        if args.fail_on_confirmed and report['confirmed'] or args.fail_on_suspected and report['suspected']:
            return 1
        return 0
    except (EvidenceError,ScanError,ValueError,TypeError,KeyError,OSError,UnicodeError,RecursionError) as ex:
        print('RISU_CHECK_ERROR: '+str(ex)[:240],file=sys.stderr)
        return 2

if __name__=='__main__':
    raise SystemExit(cli())
