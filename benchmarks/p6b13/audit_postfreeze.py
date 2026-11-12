"""B13 independent postfreeze audit. Original data and first-pass outcomes immutable.

Reads downloaded artifacts from the original GitHub Actions run. No network,
server execution, detector modification, or in-place change of source scores.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from score_metamorphic import audit as first_pass_audit

SOURCE_SHA = {
    'FS2': 'e222228be7ad03ace2974df8ea12e2afc7f49a40e0c7a48e70622a86ad4fe313',
    'SQL2': '6f7a695496d7ad68236d0633466cd891c0636f78246d1730a6c72eed0081544b',
}
EXPECTED_CASES = ('FS2', 'SQL2')


def check(manifest: Path, dirs: dict[str, Path]) -> dict:
    cohort = json.loads(manifest.read_text(encoding='utf-8'))
    chosen = cohort['cohort']
    if (len(chosen) != 2 or {x['id'] for x in chosen} != set(EXPECTED_CASES)
            or len({x['owner'] for x in chosen}) != 2
            or sum(len(x['tool_calls']) for x in chosen) != 13):
        raise ValueError('Frozen cohort changed')
    if set(dirs) != set(EXPECTED_CASES):
        raise ValueError('Original cases were omitted or substituted')

    audited = []
    total_pass = total_unverified = total_mismatches = 0
    postfreeze_corrected = 0
    for case in EXPECTED_CASES:
        root = dirs[case]
        capture = root / '.b13-capture'
        original_bytes = (capture / 'original_stdio.jsonl').read_bytes()
        digest = hashlib.sha256(original_bytes).hexdigest()
        if digest != SOURCE_SHA[case]:
            raise ValueError(f'{case}: recorded original source stdout changed')
        meta = json.loads((capture / 'origin.json').read_text())
        if meta['original_stdio_sha256'] != digest or not meta['native_upstream_process'] or not meta['source_stdout_unmodified']:
            raise ValueError(f'{case}: original provenance contract violated')
        stored = json.loads((root / '.b13-firstpass.json').read_text())
        recomputed = first_pass_audit(case, capture, root / '.b13-risu.json', manifest)
        if stored != recomputed:
            raise ValueError(f'{case}: first-pass result changed from frozen evidence')
        core = json.loads((root / '.b13-risu.json').read_text())
        if stored['frozen_risu_findings'] != [x.get('rule_id') for x in core.get('findings', [])]:
            raise ValueError(f'{case}: RISU scanner findings not bound to score')
        calls = json.loads((capture / 'unmodified_calls.json').read_text())
        for call in calls:
            if not any(json.loads(line) == call['response'] for line in original_bytes.splitlines() if line.strip()):
                raise ValueError(f'{case}: scored server result not present in original stdio')
        passed = stored['oracles_pass']
        unverified = stored['oracle_unverified']
        mismatches = stored['candidate_mismatches']
        followup = []
        if case == 'FS2':
            pending = [x for x in stored['independent_oracles'] if x['oracle'] == 'literal_search_absent_has_zero_hits']
            if len(pending) != 1 or pending[0]['status'] != 'UNVERIFIED' or unverified != 1:
                raise ValueError('FS2 initial unverified outcome was overwritten')
            search = calls[4]['response']['result']
            met = search.get('_meta')
            if (not isinstance(met, dict) or type(met.get('totalMatches')) is not int
                    or met['totalMatches'] != 0 or met.get('matches') != []
                    or search.get('isError', False) is True):
                raise ValueError('Postfreeze zero-match confirmation lacks raw independent evidence')
            followup.append({'oracle': 'literal_search_absent_has_zero_hits',
                'initial': 'UNVERIFIED', 'postfreeze': 'PASS',
                'evidence': 'Untouched native server reply id 24 has _meta.totalMatches = 0 and _meta.matches = []; first-pass parser only checked structuredContent.'})
            postfreeze_corrected += 1
        elif unverified:
            raise ValueError('Unexpected SQL2 unverified oracle')
        audited.append({
            'case': case,
            'source_repo': stored['source_repo'],
            'source_commit': stored['source_commit'],
            'original_stdout_sha256': digest,
            'selected_calls': stored['selected_calls'],
            'firstpass': {'pass': passed, 'unverified': unverified, 'mismatch_candidates': mismatches,
                          'frozen_risu_findings': stored['frozen_risu_findings']},
            'postfreeze_recheck': followup,
            'postfreeze_pass': passed + len(followup),
            'postfreeze_unverified': unverified - len(followup),
            'confirmed_new_unknown_bugs': 0,
        })
        total_pass += passed
        total_unverified += unverified
        total_mismatches += mismatches
    return {
        'schema': 'risu-p6b13-independent-original-evidence-postfreeze-audit-v1',
        'original_github_run': 43276733731,
        'manifest_sha256': hashlib.sha256(manifest.read_bytes()).hexdigest(),
        'selected': audited,
        'summary': {'independent_publishers': 2, 'native_unmodified_mcp_servers': 2,
            'preselected_tool_calls': 13, 'independent_oracles': 11,
            'firstpass_pass': total_pass, 'firstpass_unverified': total_unverified,
            'postfreeze_pass': total_pass + postfreeze_corrected,
            'postfreeze_unverified': total_unverified - postfreeze_corrected,
            'candidate_mismatches': total_mismatches,
            'core_risu_findings': 0, 'confirmed_newly_discovered_bugs': 0,
            'discovery_rate': 'NOT_ESTIMABLE_NONRANDOM_COHORT'},
        'limits': ['The two publisher repositories were selected based on public documentation, not randomly sampled.',
            'First-pass scores and native stdout records are preserved unchanged.',
            'The one postfreeze parser recheck is credited separately, never as a first-pass success.',
            'No previously unknown MCP bug has been discovered or independently confirmed in these operations.'],
    }


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument('--manifest', type=Path, default=Path('benchmarks/p6b13/prelocked_native_cases.json'))
    p.add_argument('--record', action='append', default=[])
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    roots = {}
    for rec in a.record:
        case, sep, val = rec.partition('=')
        if not sep or case in roots:
            p.error('Pass unique --record CASE=path')
        roots[case] = Path(val)
    result = check(a.manifest, roots)
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
    print('B13_CROSS_ARTIFACT_INDEPENDENT_POSTFREEZE_AUDIT',
          json.dumps(result['summary'], sort_keys=True))


if __name__ == '__main__':
    main()