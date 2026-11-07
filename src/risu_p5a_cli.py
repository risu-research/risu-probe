"""Single installed RISU Probe entry point: legacy CLI plus opt-in P5-A rule."""
from __future__ import annotations
import sys


def main():
    if len(sys.argv)>1 and sys.argv[1]=='schema-compat':
        from risu_compat import cli
        return cli(sys.argv[2:])
    from risu_p4t_cli import main as previous_main
    return previous_main()
