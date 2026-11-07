"""Additive installed command wrapper: preserve prior RISU Probe CLI behavior."""
from __future__ import annotations
import sys


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == 'contract-history':
        from risu_contract_history import cli
        return cli(sys.argv[2:])
    from risu_probe import main as previous_main
    return previous_main()
