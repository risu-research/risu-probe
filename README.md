# RISU Probe

**Status: experimental preview (`0.9.20.dev0`).** Official product source migrated from the verified P6-A branch. This is the public developer repository. This is the readable product source for the code that passed P5-E's Windows/Linux qualification. Do not confuse this preview with a PyPI release or MCP standards certification.

## Install from this source checkout

With [uv](https://docs.astral.sh/uv/):

```sh
uv tool install .
risu-probe doctor
risu-probe check .
```

Or with pip (Python 3.11+):

```sh
python -m pip install .
risu-probe doctor --format json
risu-probe check path/to/your/project --format json
```

> **Not published on PyPI.** Run these commands from the repository root or replace `.` with an actual path to the folder. Never run `pip install risu-probe-preview` expecting this preview to be available.

The default `check` uses read-only source scanning; it neither imports the project nor connects to a remote MCP server. Use `--strict-incomplete` to fail when scanning is incomplete. The static scan **cannot certify runtime behavior**. Running a live MCP or HTTP verification is an explicit, separately controlled action.

## Commands

```sh
risu-probe check .
risu-probe check . --format json
risu-probe check . --format sarif --out scan.sarif
risu-probe doctor
risu-probe schema-compat --help
risu-probe contract-history --help
risu-probe reproduce --help
```

Existing `risu-probe.json` configurations preserve the legacy check route. For existing CI, use the documented nonzero gates (`--fail-on-confirmed`, `--strict-incomplete`); do not treat zero findings with unsupported input as a certified pass.

## Source layout

- `src/risu_*.py`: **one, checked-in, human-readable, canonical LF source tree**, with the exact 38 modules from the successful P5-E Linux wheel, not a runtime-extracted archive.
- `pyproject.toml`: one build and installation definition; all existing module import names retained for backward compatibility.
- `P5E_SOURCE_PROVENANCE.json`: per-module SHA-256 from the exact verified P5-E reference wheel.
- `tests/`: package fidelity, installed CLI and conservative/safe-default tests.
- `provenance/` and `benchmarks/`: historic P5-E SHA verification and optional public-only 10-repository comparison tooling.

We deliberately preserve top-level module names to avoid risky import rewrites. Future package namespace refactoring should be separately tested and only undertaken when justified by developer benefits.

## Evidence boundaries

- The P5-E audit proved matching reported diagnostics on 10 fixed repositories across Windows and Linux. P6-A separately verifies the reconstructed package's same diagnostic output.
- The 38 product modules are byte-identical to the Linux P5-E CI wheel. The Windows P5-E wheel represented three identical-text modules with CRLF line endings; the single source tree fixes the cross-platform line-ending discrepancy with `.gitattributes`.
- Preserved historical experimental branches, published research RC1, previous CI outputs, and DOIs are **not modified**.
- License: Apache-2.0.

## Public-only development

Normal PR CI is read-only, runs no private code or secrets, and never publishes packages. Do not submit private source, customer data, credentials, raw nonpublic MCP/HTTP wire, or unpublished sensitive research. See [public-only policy](docs/PUBLIC_ONLY_POLICY.md), [SECURITY.md](SECURITY.md), and [CONTRIBUTING.md](CONTRIBUTING.md).

Older P4/P5 experimental masters, raw research evidence, and DOI-associated archives remain in the [research repository](https://github.com/risu-research/openapi-mcp-problem-semantics). The name RISU Probe remains provisional; no PyPI upload has occurred.
