"""P5-C installed CLI: preserve existing project checks, add zero-config first use."""
from __future__ import annotations
import sys
from pathlib import Path


def _is_legacy_project(argv: list[str]) -> bool:
    if any(x in argv for x in ('--allow-exec','--allow-remote','--policy','--error-profile',
                                '--min-covered','--fail-on-review','--baseline','--fail-new-only')):
        return True
    # Parse known option values rather than treating `--format json` as a
    # project path; preserves `risu-probe check --format json` for legacy config.
    consuming={'--format','--out','--evidence','--min-covered','--policy',
               '--error-profile','--baseline'}
    first='.'
    i=0
    while i<len(argv):
        arg=argv[i]
        if arg in consuming:
            i+=2;continue
        if any(arg.startswith(x+'=') for x in consuming):
            i+=1;continue
        if not arg.startswith('-'):
            first=arg;break
        i+=1
    path=Path(first).expanduser()
    if path.is_dir():
        return (path/'risu-probe.json').is_file()
    if path.is_file() and path.suffix=='.json':
        # Explicit existing configuration file names retain existing semantics.
        return path.name=='risu-probe.json'
    return False


def main():
    args=sys.argv[1:]
    if args and args[0]=='check':
        rest=args[1:]
        if _is_legacy_project(rest):
            from risu_probe import check_project
            return check_project(rest)
        from risu_quickcheck import cli
        return cli(rest)
    from risu_p5a_cli import main as legacy_main
    return legacy_main()
