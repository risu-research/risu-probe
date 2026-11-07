"""Offline semantic audit of *saved* official MCP SDK validation + protocol replay.

Does not import scanned code, run a server, contact HTTP endpoints, or execute
saved text. The only origin authenticated here is the EXACT P6-B2 GitHub CI
fixture whose two SHA-256 digests were independently recorded and frozen.

All other syntactically consistent self-reported JSON is untrusted: this module
will NEVER turn it into an authenticated runtime finding or a blocking exit.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

MAX_CAPTURE_BYTES = 32_768
SCHEMA = 'risu-p6b2-public-mcp-native-runtime-v1'
KNOWN_CAPTURE = {
    'old': 'df0a4670874d49ebc0487dd528bbfddf65bfe857ba5e52d4c06ada7d5b8f8c0a',
    'fixed': 'c9677f8eec6afa72d3af2bace1ad4dc94bcbcc29cd14236eb674a6df4b579e74',
}
KNOWN_CI = 'https://github.com/risu-research/risu-probe/actions/runs/42342027675'
ISSUE_BOOL = 'https://github.com/modelcontextprotocol/python-sdk/issues/3353'
ISSUE_RECURSIVE = 'https://github.com/modelcontextprotocol/python-sdk/issues/3337'

class ReplayEvidenceError(ValueError):
    """Captured evidence is absent, incomplete, malformed or contradictory."""


def _object_no_duplicates(pairs: list[tuple[str,Any]]) -> dict[str, Any]:
    result = {}
    for key,value in pairs:
        if key in result:
            raise ReplayEvidenceError('Duplicate JSON key is forbidden: '+key[:50])
        result[key] = value
    return result


def _read_json(path: Path) -> tuple[dict, str]:
    # Refuse symlinks in all ancestors, not just the final file.
    p = path.expanduser().absolute()
    if any(candidate.is_symlink() for candidate in (p, *p.parents)):
        raise ReplayEvidenceError('Symlinked capture paths are not accepted')
    if not p.is_file():
        raise ReplayEvidenceError('Saved SDK capture not found: '+p.name[:80])
    if p.stat().st_size > MAX_CAPTURE_BYTES:
        raise ReplayEvidenceError('SDK capture exceeds the 32 KiB size limit')
    try:
        raw = p.read_bytes()
        content = json.loads(raw.decode('utf-8'), object_pairs_hook=_object_no_duplicates)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ReplayEvidenceError('Saved SDK capture must be valid UTF-8 JSON') from exc
    if type(content) is not dict:
        raise ReplayEvidenceError('Saved SDK capture must contain a JSON object')
    return content,hashlib.sha256(raw).hexdigest()


def _require(flag: bool, label: str) -> None:
    if not flag:
        raise ReplayEvidenceError('Inconsistent or incomplete SDK evidence: '+label)


def _yes(x: Any) -> bool:
    return x is True


def _no(x: Any) -> bool:
    return x is False


def _valid_report(d: dict, version: str) -> None:
    _require(d.get('schema') == SCHEMA, 'unknown capture schema')
    _require(d.get('official_package_versions') == {'mcp':version,'mcp-types':version}, 'SDK versions')
    _require(d.get('official_release_tag') == 'https://github.com/modelcontextprotocol/python-sdk/releases/tag/v'+version, 'release provenance')
    _require(_no(d.get('production_server_contacted')) and _no(d.get('third_party_checkout_executed')) and _no(d.get('model_calls')), 'production/AI execution boundary')
    b=d.get('scenario_bool')
    r=d.get('scenario_recursive')
    _require(type(b) is dict and b.get('issue')==ISSUE_BOOL, 'boolean-schema case ID')
    _require(type(r) is dict and r.get('issue')==ISSUE_RECURSIVE, 'recursive-schema case ID')
    validation=b.get('native_validation')
    _require(type(validation) is dict and set(validation)=={'2025-11-25','2026-07-28'}, 'native validator versions')
    for ver in ('2025-11-25','2026-07-28'):
        _require(type(validation[ver]) is dict and type(validation[ver].get('accepted')) is bool, 'native boolean acceptance')
        if _yes(validation[ver]['accepted']):
            _require(validation[ver].get('error') is None,'accepted validator with error')
        else:
            _require(type(validation[ver].get('error')) is dict,'rejected validator error detail')
    live=r.get('live_mcp')
    _require(type(live) is dict,'missing actual MCP capture')
    _require(live.get('protocol_transport')=='MCP_SDK_IN_MEMORY_LEGACY_JSONRPC', 'actual MCP transport')
    _require(live.get('client_mode')=='legacy' and live.get('negotiated_protocol')=='2025-11-25','actual negotiated protocol')
    _require(type(live.get('list_tools_success')) is bool and type(live.get('call_tool_success')) is bool,'MCP call outcomes')
    _require(type(live.get('tool_names')) is list,'MCP tools/list response')
    _require((not live['call_tool_success']) or live['list_tools_success'], 'call success without tool listing')
    _require(live['list_tools_success'] or bool(live.get('error')), 'missing failed call error')
    _require(live['list_tools_success'] or live.get('result') is None, 'failed call with successful result')
    _require((not live['call_tool_success']) or live.get('result') is not None, 'successful call without content')
    _require(_yes(validation['2026-07-28']['accepted']), 'modern protocol control must pass')


def evaluate_pair(old_path: Path, fixed_path: Path) -> dict:
    """Evaluate pair without changing the original source static-scan verdict.

    A fresh, user-supplied report can match the same structure but cannot be
    authenticated from self-reported booleans. It gets INTEGRITY_UNATTESTED,
    no confirmed findings and no blocking CI exit.
    """
    old, old_sha = _read_json(old_path)
    fixed, fixed_sha = _read_json(fixed_path)
    _require(old_path.absolute()!=fixed_path.absolute(), 'old/fixed are the same file')
    _valid_report(old, '2.0.0')
    _valid_report(fixed, '2.1.0')
    trusted=old_sha == KNOWN_CAPTURE['old'] and fixed_sha == KNOWN_CAPTURE['fixed']
    legacy_old=old['scenario_bool']['native_validation']['2025-11-25']
    legacy_new=fixed['scenario_bool']['native_validation']['2025-11-25']
    old_live=old['scenario_recursive']['live_mcp']
    new_live=fixed['scenario_recursive']['live_mcp']

    bool_delta=(
        _no(legacy_old['accepted']) and _yes(legacy_new['accepted']) and
        legacy_old.get('error',{}).get('class')=='ValidationError' and
        'dict_type' in legacy_old.get('error',{}).get('snippet','') and
        'properties' in legacy_old.get('error',{}).get('snippet','')
    )
    recursive_delta=(
        _no(old_live['list_tools_success']) and _no(old_live['call_tool_success']) and
        old_live.get('emitted_output_schema_root_type') is None and
        old_live.get('emitted_output_schema_root_ref')=='#/$defs/Node' and
        type(old_live.get('error')) is dict and
        _yes(new_live['list_tools_success']) and _yes(new_live['call_tool_success']) and
        new_live.get('emitted_output_schema_root_type')=='object' and
        new_live.get('emitted_output_schema_root_ref') is None and
        sorted(new_live.get('tool_names',[]))==['heartbeat','tree'] and
        new_live.get('result')=={'name':'root','children':[{'name':'leaf','children':[]}]}
    )
    results=[]
    for code,issue,kind,verified,detail in (
        ('RMC401',ISSUE_BOOL,'SDK_NATIVE_VALIDATOR',bool_delta,
         'MCP 2025-11-25 valid boolean property sub-schemas rejected before official fix; 2026-07-28 positive control accepted.'),
        ('RMC402',ISSUE_RECURSIVE,'IN_MEMORY_MCP_JSONRPC',recursive_delta,
         'Legacy tools/list failed for recursive output schema before official fix; fixed SDK lists both tools and calls tree.'),
    ):
        results.append({
            'rule_id':code,'issue':issue,'test_boundary':kind,
            'observed_in_saved_replay':verified,
            'verdict':('CONFIRMED_IN_PINNED_PUBLIC_CI_REPLAY' if verified and trusted
                       else 'CONSISTENT_BUT_UNATTESTED' if verified
                       else 'NOT_DEMONSTRATED_BY_THIS_PAIR'),
            'message':detail,
            'scope':'Synthetic public SDK 2.0.0->2.1.0 comparison only; not a live-user or external-server incident.',
        })
    findings=[r for r in results if r['verdict']=='CONFIRMED_IN_PINNED_PUBLIC_CI_REPLAY']
    return {
        'schema':'risu-mcp-saved-semantic-verification-v1',
        'source_analysis':'NOT_PERFORMED_BY_THIS_COMMAND',
        'semantic_verification':('CONFIRMED_IN_PINNED_PUBLIC_CI_REPLAY' if findings
                                 else 'EVIDENCE_CONSISTENT_UNATTESTED' if any(x['observed_in_saved_replay'] for x in results)
                                 else 'NO_VERIFIED_CONTRAST'),
        'origin_integrity':('PINNED_PUBLIC_CI_SHA256_PAIR' if trusted else 'UNATTESTED_SELF_REPORTED_JSON'),
        'capture_sha256':{'old':old_sha,'fixed':fixed_sha},
        'reference_ci':KNOWN_CI if trusted else None,
        'verified_case_count':len(findings),
        'cases':results,
        'coverage':{
            'static_source_parsed':'NOT_ASSESSED',
            'native_mcp_sdk_validator':'CAPTURED',
            'in_memory_mcp_legacy_protocol':'CAPTURED',
            'stdio_mcp_wire':'NOT_CAPTURED',
            'external_mcp_server':'NOT_TESTED',
            'production_behavior':'NOT_TESTED',
        },
        'disclaimer':('Exact CI fixture hashes verify identity relative to a known published run, not independent cryptographic attestation of what ran. '
                      'Unpinned JSON values can be fabricated and never trigger confirmed/blocking status. '
                      'This command reads a saved replay only; it performs no new SDK/server execution.'),
    }


def as_text(report: dict) -> str:
    lines=['RISU Probe MCP semantic verification | '+report['semantic_verification'],
           'Origin: '+report['origin_integrity'],
           'Source parse: NOT ASSESSED  |  SDK native validator: CAPTURED  |  in-memory MCP: CAPTURED',
           'External stdio or production MCP: NOT TESTED','']
    for finding in report['cases']:
        lines += [finding['rule_id']+' '+finding['verdict'],
                  '  '+finding['message'], '  '+finding['issue'],'']
    lines += ['Source parsing and MCP semantic validation are different operations.',
              'A saved CI replay is not proof of a current server problem.']
    return '\n'.join(lines)+'\n'


def as_sarif(report:dict)->dict:
    rules=[{'id':c['rule_id'],'shortDescription':{'text':c['message']}} for c in report['cases']]
    results=[{'ruleId':c['rule_id'],'level':'error',
              'message':{'text':c['message']},
              'properties':{'confidence':c['verdict'],'test_boundary':c['test_boundary'],'issue':c['issue']}}
             for c in report['cases'] if c['verdict']=='CONFIRMED_IN_PINNED_PUBLIC_CI_REPLAY']
    return {'version':'2.1.0','$schema':'https://json.schemastore.org/sarif-2.1.0.json',
            'runs':[{'tool':{'driver':{'name':'RISU Probe','version':'0.9.22','rules':rules}},
                     'results':results,'properties':{'semantic_verification':report['semantic_verification'],
                                                    'origin_integrity':report['origin_integrity'],
                                                    'coverage':report['coverage']}}]}


def cli(argv:list[str]|None=None)->int:
    import argparse
    import sys
    p=argparse.ArgumentParser(prog='risu-probe verify-mcp', description='Offline verification of saved, pinned MCP SDK replay records')
    p.add_argument('--old',type=Path,required=True,help='Official MCP SDK old-version synthetic replay JSON')
    p.add_argument('--fixed',type=Path,required=True,help='Official MCP SDK fixed-version synthetic replay JSON')
    p.add_argument('--format',choices=('text','json','sarif'),default='text')
    p.add_argument('--fail-on-confirmed',action='store_true')
    p.add_argument('--out',type=Path,help='New report; existing file will not be overwritten')
    a=p.parse_args(argv)
    try:
        report=evaluate_pair(a.old,a.fixed)
        output=as_text(report) if a.format=='text' else json.dumps(report if a.format=='json' else as_sarif(report),indent=2,ensure_ascii=False,sort_keys=True)+'\n'
        if a.out:
            if a.out.exists() or a.out.is_symlink():
                raise ReplayEvidenceError('Output report already exists; refusing overwrite')
            a.out.parent.mkdir(parents=True,exist_ok=True)
            with a.out.open('x',encoding='utf-8') as stream:stream.write(output)
        else:
            print(output,end='')
        return 1 if a.fail_on_confirmed and report['verified_case_count'] else 0
    except (ReplayEvidenceError,OSError,UnicodeError,TypeError,KeyError,ValueError) as exc:
        print('RMC400 INVALID_OR_INCOMPLETE_SDK_REPLAY: '+str(exc)[:230]+'\nNext: supply the exact pair of released SDK synthetic capture JSON files; verify external CI provenance before relying on them.',file=sys.stderr)
        return 2
