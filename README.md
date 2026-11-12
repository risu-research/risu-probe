# RISU Probe

**Status: experimental preview (`0.9.25.dev0`).** Official product source migrated from the verified P6-A branch. This is the public developer repository. This is the readable product source for the code that passed P5-E's Windows/Linux qualification. Do not confuse this preview with a PyPI release or MCP standards certification.

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
- The P6-A baseline retained 38 modules byte-identical to P5-E. The P6-B3 experimental branch intentionally differs in four pre-existing modules: the static RPY204 addition, version metadata and CLI routing. The other 34 original modules remain byte-identical. The Windows P5-E wheel represented three identical-text modules with CRLF line endings; the single source tree fixes the cross-platform line-ending discrepancy with `.gitattributes`.
- Preserved historical experimental branches, published research RC1, previous CI outputs, and DOIs are **not modified**.
- License: Apache-2.0.

## Public-only development

Normal PR CI is read-only, runs no private code or secrets, and never publishes packages. Do not submit private source, customer data, credentials, raw nonpublic MCP/HTTP wire, or unpublished sensitive research. See [public-only policy](docs/PUBLIC_ONLY_POLICY.md), [SECURITY.md](SECURITY.md), and [CONTRIBUTING.md](CONTRIBUTING.md).

Older P4/P5 experimental masters, raw research evidence, and DOI-associated archives remain in the [research repository](https://github.com/risu-research/openapi-mcp-problem-semantics). The name RISU Probe remains provisional; no PyPI upload has occurred.

## P6-B public defect benchmark

The P6-B benchmark compares original public bug code against merged fixes and unsupported controls. Its first detector is a static hypothesis based on FastMCP #5030, not a verified runtime claim. See [benchmark](benchmarks/p6b/README.md). This is still an experimental preview, not a PyPI release.

## Saved MCP semantic verification (P6-B3 preview)

`risu-probe verify-mcp --old tests/fixtures/sdk_old.json --fixed tests/fixtures/sdk_fixed.json --format json` verifies **public, synthetic saved** official SDK 2.0.0 vs 2.1.0 replay. `check .` now keeps static source coverage separate from semantic-verification coverage, with explicit `--mcp-sdk-old` and `--mcp-sdk-fixed` inputs when appropriate. Only exact SHA-pinned, published public CI records can yield a confirmed-in-saved-replay finding. A modified or fabricated capture is never authenticated by a self-reported claim. This is **not current production server testing**. See [the evidence contract and limitations](docs/P6B3_PRODUCT_SEMANTIC_EVIDENCE.md).

## P6-B4 · General recorded MCP JSON-RPC checks (experimental)

```sh
risu-probe verify-mcp-trace local-mcp.jsonl --protocol-version 2025-11-25 --format json
risu-probe check . --mcp-trace local-mcp.jsonl --mcp-protocol-version 2025-11-25 --format json
```

The generic trace verifier matches `tools/list` with `tools/call` responses and checks declared output schemas without contacting an MCP server. Its reports distinguish source parse, captured semantic inconsistencies and incomplete evidence. **Captures are unauthenticated; observations in supplied files are not proof of production incidents.** The CI tests only synthetic public data. See [P6-B4 evidence and scope](docs/P6B4_GENERIC_MCP_TRACE.md).

## P6-B15 · Opt-in MCP result and effect contracts

The offline `check-mcp-observations` command verifies user-declared result and
persistent-state obligations against recorded, correlated MCP JSON-RPC messages:

```sh
risu-probe check-mcp-observations original_stdio.jsonl \
  --contract observation_contract.json \
  --witness state_witness.json \
  --format json --out observation-report.json
```

`--witness` is required for state-change checks; JSON result checks work
with only the contract and recorded trace. The checker uses strictly
bounded, declarative rule IDs `RME610` (effect mismatch) and `RME620`
(declared JSON result mismatch). It abstains on missing or unsupported
evidence and never executes the input project.

The three-publisher qualification checked 14 native source calls.
Thirteen valid obligations passed; one preregistered rule contradicted
the source server's original tool description, and was correctly
separated from confirmed upstream bugs. The B14 original replay detects
two existing development-set discrepancies. See the
[B15 reproduction, independent audit and evidence boundaries](docs/P6B15_FROZEN_OBSERVATION_AND_EXTERNAL_AUDIT.md).

## P6-B16 · Catalog-bound authority qualification

`qualify-mcp-observations` is a separate, optional offline authority gate
for the B15 `check-mcp-observations` records. It ties exact calls to a **complete,
contemporaneous, in-band `tools/list` catalog**, respects list-change
notifications and paginated catalogs, and distinguishes structured-output
obligations from untrusted behavioral hints.

```sh
risu-probe qualify-mcp-observations local-mcp.jsonl \\
  --contract observation_contract.json \\
  --witness state_witness.json \\
  --format json --out qualified-report.json
```

A captured `outputSchema` can qualify a narrow `structuredContent` field
assertion; `readOnlyHint` is **advisory only**. A mismatching caller contract
with no applicable authoritative catalog declaration is **quarantined** and
not claimed as a product or upstream defect. Original evidence and source
identity remain user-supplied and unauthenticated. The new-source tests used
2 independent public publishers (7 real stdio calls), plus three separately
labeled synthetic error injections. See the
[B16 source-audited research record](docs/P6B16_CATALOG_BOUND_AUTHORITY_RESEARCH.md).

## P6-B17 · Independently corroborated source contracts

The new opt-in `verify-mcp-origin` command checks whether a captured,
session-specific MCP tool `outputSchema` is consistent with the literal schema
in an independently pinned publisher Git source file.

```sh
risu-probe verify-mcp-origin original_stdio.jsonl \
  --contract output_contract.json \
  --source-checkout ./pinned-publisher-source \
  --source-manifest origin_manifest.json \
  --format json --out origin_report.json
```

It uses Git commit/tree/blob object inspection and non-executing Python AST
extraction. Only narrow, literal structured-result declarations are eligible
for `SOURCE_CORROBORATED_*` findings. Schema conflicts are quarantined;
incomplete catalog epochs or advisory read-only hints cannot be promoted.
A local checkout alone cannot authenticate a publisher's identity, so the
external CI also cross-checked GitHub's remote Git tree against the pinned
checkout and independently verified the published source commit.

The new GoogleCloudPlatform original MCP server passed 2/2 real native calls
against its source-pinned `outputSchema`; separate source/catalog and
synthetic-result mutations were correctly classified. No external new bug is
claimed. Full experimental evidence and provenance limits:
[B17 independent contract-origin audit](docs/P6B17_INDEPENDENT_CONTRACT_ORIGIN_AUDIT.md).

## P6-B18 · Actual executed MCP binary provenance

The opt-in offline command `verify-mcp-runtime` correlates a pinned
original source commit with **two independent byte-identical compiled
executables**, an independently verified GitHub Actions Sigstore build
attestation, live `/proc/PID/exe` hashes, and original native MCP
request/response transcripts.

The public qualification rebuilt the original
`modelcontextprotocol/go-sdk` toolschemas server from a frozen Git commit
with Go 1.25.0, signed the original build output in RISU's GitHub Actions,
verified the signer with `gh attestation verify`, and executed the
same original binary in **two independent CI runs**. Both running process
images matched the signed executable's SHA-256 at the start and end of
each session, and all eight selected native MCP responses were consistent.
Separate controls rejected 16 deliberately corrupted evidence variants.

This is evidence about the **RISU-signed qualification build**, not
an upstream publisher-signed official release. The verifier itself does
not execute untrusted code or cryptographically validate signatures:
those independent steps are carried out and recorded in CI. No new
upstream behavioral defect was found in the original example server.

Read the [B18 full source-to-executable research record](docs/P6B18_EXECUTED_ORIGINAL_GO_BINARY_PROVENANCE.md)
for the complete reproducible run, signatures, Git blobs, original
stdout, source/runner trust boundaries and controls.
