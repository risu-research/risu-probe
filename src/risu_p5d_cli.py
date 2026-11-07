"""User-facing P5-D entrypoint: P5-C unchanged except first-use ergonomics."""
from __future__ import annotations
import sys

def main():
    args=sys.argv[1:]
    if args and args[0]=='doctor':
        from risu_firstuse import doctor_cli
        return doctor_cli(args[1:])
    if args and args[0]=='check':
        from risu_p5c_cli import _is_legacy_project
        if not _is_legacy_project(args[1:]):
            from risu_firstuse import cli
            return cli(args[1:])
    from risu_p5c_cli import main as previous
    return previous()

if __name__=='__main__':raise SystemExit(main())
