"""Auditable time-limited known-finding baseline (no raw API data stored)."""
from __future__ import annotations
import hashlib
import json
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

FINDINGS = {'LOSS', 'INVENTED', 'LOSS_AND_INVENTED'}

class BaselineError(ValueError):
    pass


def fingerprint(item: dict) -> str:
    # Only non-sensitive classifier tokens, case id and diagnostic strings enter
    # this digest. The baseline stores only the hash, never those strings.
    canonical = {'case_id': item.get('id'), 'verdict': item.get('verdict'),
                 'losses': sorted(item.get('losses') or []),
                 'inventions': sorted(item.get('inventions') or []),
                 'diagnostic_codes': sorted(x.get('code') for x in item.get('diagnostics', []) if isinstance(x,dict) and isinstance(x.get('code'),str)),
                 'scope': item.get('scope', 'lossless'),
                 'checked_paths': item.get('checked_paths'), 'target_root': item.get('target_root')}
    b = json.dumps(canonical, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()
    return hashlib.sha256(b).hexdigest()


def make_baseline(report: dict, expires: str | None = None) -> dict:
    if not isinstance(report, dict) or not isinstance(report.get('results'), list):
        raise BaselineError('expected RISU Probe JSON report with results array')
    today = datetime.now(timezone.utc).date()
    expiry = date.fromisoformat(expires) if expires else today + timedelta(days=30)
    if expiry <= today or expiry > today + timedelta(days=365):
        raise BaselineError('baseline expires date must be in the next 1–365 days')
    findings = [x for x in report['results'] if x.get('verdict') in FINDINGS]
    if not findings:
        raise BaselineError('report has no semantic findings eligible for a baseline')
    if len(findings) > 10000:
        raise BaselineError('too many findings for baseline')
    return {'format': 'risu-probe-baseline-v1', 'created_utc': today.isoformat(),
            'expires': expiry.isoformat(), 'fingerprints': sorted(set(fingerprint(i) for i in findings)),
            'description': 'Acknowledged known semantic findings only; invalid probes and missing coverage always fail'}


def load_baseline(path: str | Path) -> dict:
    try:
        obj = json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        raise BaselineError('could not read baseline JSON') from exc
    if not isinstance(obj, dict) or obj.get('format') != 'risu-probe-baseline-v1':
        raise BaselineError('invalid baseline format')
    try:
        expiry = date.fromisoformat(obj['expires'])
    except (KeyError, TypeError, ValueError) as exc:
        raise BaselineError('invalid baseline expiry date') from exc
    if expiry < datetime.now(timezone.utc).date():
        raise BaselineError('baseline expired; review and renew explicitly')
    stamps = obj.get('fingerprints')
    if (not isinstance(stamps, list) or len(stamps) > 10000 or
        not all(isinstance(x, str) and len(x) == 64 and all(c in '0123456789abcdef' for c in x) for x in stamps) or
        len(stamps) != len(set(stamps))):
        raise BaselineError('invalid or duplicate baseline fingerprints')
    return obj


def mark_baseline(report: dict, baseline: dict):
    found = set(baseline['fingerprints'])
    counts = {'known': 0, 'new': 0}
    for item in report['results']:
        if item.get('verdict') in FINDINGS:
            status = 'known' if fingerprint(item) in found else 'new'
            item['baseline'] = status
            counts[status] += 1
        else:
            item['baseline'] = 'not_applicable'
    report['baseline'] = {'expires': baseline['expires'], 'counts': counts,
                           'stale_fingerprints': len(found - {fingerprint(x) for x in report['results'] if x.get('verdict') in FINDINGS})}
    return report


def cli(argv):
    import argparse, sys
    p = argparse.ArgumentParser(description='Explicitly acknowledge known findings for a limited period')
    p.add_argument('action', choices=['make'])
    p.add_argument('report', type=Path, help='JSON report created by check --format json')
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--expires', help='ISO date, defaults to 30 days from today')
    p.add_argument('--force', action='store_true')
    a = p.parse_args(argv)
    try:
        if a.out.exists() and not a.force:
            raise BaselineError('output exists; use --force to replace')
        report = json.loads(a.report.read_text(encoding='utf-8'))
        baseline = make_baseline(report, a.expires)
        a.out.parent.mkdir(parents=True, exist_ok=True)
        a.out.write_text(json.dumps(baseline, indent=2)+'\n', encoding='utf-8')
        print(f'Baseline: {len(baseline["fingerprints"])} acknowledged fingerprints; expires {baseline["expires"]}')
        return 0
    except (OSError, ValueError, BaselineError) as exc:
        print('RISU Probe baseline: ' + str(exc), file=sys.stderr)
        return 2
