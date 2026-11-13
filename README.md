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

## P6-B19 · Upstream signed releases, real security repair and invisible MCP side effects

RISU's opt-in `compare-signed-mcp-repair` evaluates the original
**publisher-attested official releases** and an independently observed
persistent effect against a frozen, explicit historical repair contract:

```sh
risu-probe compare-signed-mcp-repair \
  --evidence-root original-signed-release-captures \
  --freeze benchmarks/p6b19/FROZEN_PUBLISHER_WHEELS_REAL_GIT_REPAIR.json \
  --format json --out real_repair.json
```

B19 is grounded in upstream
`modelcontextprotocol/servers` `mcp-server-git` PyPI **Trusted Publishing**
wheel files for vulnerable `2026.11.4` and fixed `2026.11.11`,
independently Sigstore-verified using the official PyPI attestation client.
The wheels, exact Git source code and installed modules matched byte-for-byte.

The public `core.fsmonitor` read-only `git_status` security defect
(GHSA-6hqx-gqrx-c5r2) was reproduced with a harmless isolated
marker-writer: only the old release executed it, while both versions
returned successful normal tool results. **All four original MCP tool
result JSON bodies were identical** across the vulnerable, fixed and
normal controls. The complete experiment was independently rerun
under fresh original processes; all eight actual results matched.

This is a reproducible **known upstream security repair**, not a new
vulnerability discovery. It is a narrow research comparator with
independent effect witnesses, not an arbitrary exploit scanner. A PyPI
publish attestation authenticates the publisher's release artifact, not
a complete upstream SLSA build or running-process identity.

[Detailed B19 source-and-effect audit](docs/P6B19_PUBLISHER_SIGNED_HIDDEN_EFFECT_REPAIR.md).

## P6-B20 · Generic original MCP effect-matrix verification

The opt-in `verify-mcp-effects` command evaluates original native MCP
responses together with bounded **independent before/after effect witnesses**.
It has no Git-specific rule, advisory identifier or package version embedded
in the classifier.

```sh
risu-probe verify-mcp-effects \
  --plan frozen_effect_matrix.json \
  --evidence-root original_native_observations \
  --format json --out effect_report.json
```

Each effect is a strictly typed boolean, counter or SHA-256 digest, bound to
an original observer JSON file by SHA-256 and exact JSON pointers. Four
predeclared paired cases support suppressed, preserved, absent or custom
effect truth tables. The original `tools/list`, one successful
`tools/call`, raw trace hash, arguments and response hashes must match
before any effect result is admitted.

The developer positive is the previous **official publisher-attested
B19 historical security repair**, explicitly excluded from the independent
denominator. The frozen generic checker then passed a genuine
**unmodified non-Git source** from `kujirahand/filesystem-mcp==1.0.2`
with three different state observables, two independently reexecuted
four-case original runs and byte-level independent audits.

The new external cohort is a **normal functionality holdout**, not a new
upstream bug or software fix. Effects from a CI-supplied observer are
source-bound but not cryptographically remotely attested; an observed
state change is not itself authorization or causal proof.

See the [B20 research and evidence report](docs/P6B20_GENERIC_NATIVE_EFFECT_EVIDENCE_RESEARCH.md).

## P6-B21 · Directed MCP effects and pinned owner-signed permission scopes

The opt-in `verify-mcp-effect-authority` command adds **directional**
state transitions (activation/deactivation, creation/deletion/replacement,
counter increase/decrease) and post-execution conformance to a
separately pinned **resource owner's Ed25519-signed pre-call policy**.

```sh
pip install '.[effect-authority]'
risu-probe verify-mcp-effect-authority \
  --plan PREDECLARED_EFFECT_MATRIX.json \
  --evidence-root ORIGINAL_MCP_AND_EXTERNAL_EFFECTS \
  --authority-manifest SIGNED_OWNER_AUTHORITY_MANIFEST.json \
  --trust-root OWNER_PUBLIC_KEYS.json \
  --trusted-root-sha256 OUT_OF_BAND_TRUST_ROOT_SHA256 \
  --format json --out directional_scope_report.json
```

The verifier independently binds the actual original `tools/call` and
target resource **argument value** to the signed scope, exact source
distribution digest, actor claim, unique nonce, validity interval,
and external actual before/after observations. MCP annotations are
informational only and never grant resource authorization.

In two independent runs, a fresh Ed25519 owner key was generated for
each run **before executing** the unmodified third-party
`filesystem-mcp==1.0.2` server. Normal file creation, unchanged writes,
a deliberately policy-prohibited creation, and a genuinely shorter-file
replacement were audited. The source-native external calls, signatures
and byte-level effects were independently revalidated.

**Important scope:** The owner and target are synthetic CI temporary
fixtures actually controlled by the CI runner. This is a verified
*fixture-owner scope audit*, not end-user OAuth permission verification,
upstream software wrongdoing, or runtime prevention. A key signature
alone cannot prove legal or production resource ownership. The tool is
post-hoc and does not block an action before the MCP server runs.

[Complete B21 research and trust-boundary report](docs/P6B21_OWNER_SIGNED_DIRECTIONAL_EFFECTS.md).

## P6-B22 · Execute original MCP only after independently scoped owner approval

`enforce-mcp-preflight` is a narrow opt-in **pre-execution** gate for
source-original local MCP `write_file`. A separate POSIX resource-owner
principal issues an Ed25519-signed exact request grant; an unprivileged
executor checks the pinned owner root, actual file/directory OS DAC,
original vendor artifact hash, precondition state, signed directional scope,
revocation epoch and atomic one-time nonce **before** it starts the original
MCP server process.

```sh
pip install '.[effect-authority]'
risu-probe enforce-mcp-preflight \
  --request ORIGINAL_CALL.json \
  --grant OWNER_SIGNED_PRECALL_GRANT.json \
  --trust-root OWNER_PUBLIC_ROOT.json \
  --trusted-root-sha256 PINNED_ROOT_SHA \
  --revocations LATEST_OWNER_SIGNED_REVOCATIONS.json \
  --revocations-sha256 PINNED_REVOCATION_SHA \
  --original-wheel PINNED_ORIGINAL_WHEEL.whl \
  --ledger EXECUTOR_PRIVATE_NONCE_LEDGER \
  --server-python ORIGINAL_ISOLATED_SERVER_PYTHON \
  --out VERDICT.json
```

In two fresh GitHub-hosted Ubuntu VMs, the unmodified third-party
`filesystem-mcp==1.0.2` server ran **only** for 3 separately approved
operations per VM; **7 operations per VM were rejected before server
`execve`**, with no changed file bytes, checked against actual Linux
syscall traces. File existence, bytes and SHA-256 before/after were
**separately signed by the OS owner principal** using its unreadable-to-
executor private Ed25519 key. Independent audit read both runs without
importing RISU's product code.

The two principals are real separate unprivileged POSIX identities, **not
independent natural-person participants**. GitHub's privileged CI operator
controls the synthetic test identities and could impersonate them. A
verified external human consent, OAuth provider, production resource-owner
registry, and comprehensive race-free filesystem sandbox are outside this
qualification. The module deliberately supports a bounded original file
writer, rather than arbitrary external actions.

[Detailed B22 source and authorization audit](docs/P6B22_REAL_OS_OWNER_PRECALL_ENFORCEMENT.md).

## P6-B23 · GitHub-attested repository-owner grants for original MCP execution

B23 extends B22's synthetic OS-resource owner research to a **real
organization-owned GitHub repository** and a real authenticated repository
administrator, with issuer and executor in different GitHub Actions jobs.
The explicit, narrowly scoped owner-account grant is signed via GitHub
OIDC/Sigstore provenance and independently verified against the original
GitHub organization/repository IDs, administrator permission, tool,
arguments, branch, file path, pre-existing Git blob, intended new bytes,
publisher binary and one-use nonce before the official GitHub MCP server runs.

The unmodified **GitHub MCP Server v2.1.0** then changed the real owner
repository file through one source-native `create_or_update_file` call.
A separate **read-only** auditor used GitHub's own immutable Git blob,
original write commit, exact single-file diff, the complete original
MCP stdio and the externally verified grant attestation as evidence.
Five forged or wrong-scope requests plus one reuse were declined before
the original source call. The added local nonce-first product path also
distinguishes replay from a later stale remote Git blob.

```sh
risu-probe enforce-mcp-github-owner \
  --grant OWNER_AUTHORIZATION.json \
  --original-server ./github-mcp-server \
  --original-archive ORIGINAL_GITHUB_MCP_RELEASE.tar.gz \
  --authenticating-run AUTHENTICATED_OWNER_WORKFLOW_RUN_ID \
  --approval-mode DELEGATED_OWNER_ACCOUNT_GIT_COMMIT_AUTOMATED_DEVELOPMENT \
  --actor VERIFIED_REPOSITORY_ADMIN_ACCOUNT \
  --out NEW_RESULT_DIRECTORY
```

**Authorization classification matters:** This real GitHub admin grant
was a user-authorized **delegated connected-account action**, attested
by a real GitHub identity service. It was not a distinct external
human's manually clicked consent. The executor also had a repository
write token, so the gate is not yet an unbypassable credential broker.

See [B23 real GitHub owner provenance and independent remote-effect report](docs/P6B23_REAL_GITHUB_ADMIN_ATTESTED_OWNER_PRECALL.md).
