# RISU Probe P6-B8: bounded catalogs, diagnostic attribution and explicit behavior contracts

Status: **implemented and verified on a qualification branch**. Not merged into `main`, not an external release. Date: 2026-11-08 (UTC).

## Experimental separation and no retrospective scoring

- Frozen pre-improvement P6-B7 result, `0.9.25.dev0`: 2 upstream bug families reproduced, **0/2 independently detected**. It remains unchanged at `qualification/p6b7-prelocked-upstream-heldout-20261107`.
- This P6-B8 branch was created from that development history. After code changes, the two original B7 cases became **development regression cases**. Their revised outcomes must not retroactively change P6-B7's 0/2 baseline.
- Before the new external trial, the B8 analyzer was frozen at Git blob `f11a080976688b7e4076b0e2ab9f83b350b6bf3a` in commit `a6a23c7c77c626ec53256eb998e61c06bf7f69ed`. The newly selected upstream `CYAN846` pair and source blob IDs are preregistered in `benchmarks/p6b8/independent_holdout_frozen.json`. No analyzer rules were changed after reading its result.

## What was changed

1. **Bounded real tool catalog ingestion.** `tools/list` has a separate 65,536-node bounded parse budget (still max 512 KiB per JSONL line, 4 MiB trace and 32 levels of depth). A large `tools/list` is indexed as a whole. Tool schemas are checked only on successful calls with recorded declarations. Duplicate declarations, malformed metadata and partial pagination still fail closed. New counters distinguish indexed declarations from actually checked declarations.
2. **Error attribution.** An `isError=true` result with recognizable upstream SDK error text is classified as `REPORTED_OUTPUT_VALIDATION_REJECTION` or `REPORTED_INPUT_VALIDATION_REJECTION`; generic tool failures remain `EXECUTION_ERROR`. These are **unverified server reports**, not RISU-confirmed schema contradictions or mandatory MCP conformance violations. No untrusted text is echoed.
3. **Caller-supplied behavior contracts.** `--behavior-contract path.json` accepts a bounded, locally loaded and explicitly opted-in contract of argument-conditioned exact text assertions. A matched successful call that contradicts the declared expectation produces `RMC506`; unsupported envelopes are unverified. Neither a tool name nor the analyzer alone creates semantic obligations.

Example (known **development** case only):

```bash
risu-probe verify-mcp-trace original_stdio.jsonl --format json \
  --behavior-contract benchmarks/p6b8/fs5184_explicit_dev_contract.json
```

This comparison is performed **offline** against recorded evidence. The caller is responsible for ensuring that behavior expectations are correct, authorized and appropriate to the target service.

## Verified original upstream development regression

GitHub Actions: https://github.com/risu-research/risu-probe/actions/runs/42506808663

| Source | Original old version | Official fixed version | Correct scope |
|---|---|---|---|
| Community-Access/accessibility-agents #205 | All 39 tools indexed; `REPORTED_OUTPUT_VALIDATION_REJECTION` on the old tool | No corresponding reported rejection | Diagnostic classification only, no independently proven output mismatch |
| modelcontextprotocol/servers Filesystem #5184 | Opt-in `head=0` expectation emits `RMC506` | No `RMC506` | Explicit behavioral contract only, no autonomous semantic inference |

Both are actual pinned public server execution on synthetic inputs, using separate MCP subprocesses. The original B7 files remain frozen. Public-only evidence artifact: `risu-p6b8-pinned-development-pairs`, SHA-256 `4e2c7d3be9cd94d3a24bdae6a4d87c74808ce6a9fb8ab36027927e828aefb7b9`.

## NEW independent holdout: CYAN846

Preregistered issue: https://github.com/cyanheads/mcp-ts-core/issues/846
Fixed upstream PR: https://github.com/cyanheads/mcp-ts-core/pull/848

- Actual old and fixed upstream trees were checked out at their pinned commits with pinned Git blob identity.
- Both versions ran a synthetic tool against an **actual MCP SDK client connected by in-memory transport**. The resulting SDK `tools/list` and `tools/call` values were wrapped in JSON-RPC records by the test adapter for offline analysis. **This is NOT byte-for-byte stdio or an independently authenticated wire trace.**
- Independent, RISU-free adjudication verified the old output-validation rejection, the fixed successful parsed boolean, and the unaffected normal control.
- Frozen RISU classified the old tool failure as `REPORTED_OUTPUT_VALIDATION_REJECTION`, did not emit that diagnosis on the fixed version, and did not warn on the normal control.
- **Independent diagnostic classification: 1/1 selected verified new bug family.** This does not establish autonomous discovery of the root cause, a confirmed schema mismatch, or broad precision/recall. `independently_proven_schema_mismatch_by_risu=false`; `new_rule_confirmed_mismatch_count=0`.

CI and evidence: https://github.com/risu-research/risu-probe/actions/runs/42507190355

Artifact name: `risu-p6b8-cyan846-independent-public`. SHA-256 `71aa90790ab8af1f214ab357cf783b2e825474b1d310754acca0ec5837da6f37`.

## General regression and reproducibility

Latest full installed-wheel qualification at https://github.com/risu-research/risu-probe/actions/runs/42507190273 passed **163 tests on each of Linux, Windows and macOS**. The separate B7-development upstream pair CI and CYAN846 holdout CI also succeeded. GitHub artifacts expire after 21 days (currently 2026-11-29), but source, pinned refs and workflows remain in this branch for re-execution.

## Remaining limitations and decision gate

- A passed run is bounded to these synthetic examples, supported schema dialects, exact client/library versions and configured checks.
- A parseable 39-tool catalog is not 39 checked output schemas. Exact coverage counters must be reported.
- Text matching an SDK error is second-hand evidence. Direct values, contract metadata or reproducible independent validation are needed to upgrade it to a confirmed mismatch.
- Behavioral expectations are explicit and opt-in; no claim that arbitrary tool names imply correct semantics.
- The captured records are not authenticated production observations. The new holdout used an in-memory SDK client with reconstructed JSON-RPC envelopes, not the original stdio bytes.
- A new independent sample size of one is insufficient to estimate the detection rate or false-positive rate. A broader preregistered holdout with at least several unrelated bug families and many normal controls is required before P6-C or a public accuracy claim.
- Keep the original engine hash and selected holdout score unchanged; use any new examples *after* this measurement only as subsequent development cases.
- Before tagging a new package version, synchronize package, CLI and SARIF version identifiers and run a clean distribution audit. This branch is still qualification-only, not a released `0.9.26`.

**Next recommendation:** broaden unexposed normal controls, capture more genuine SDK/stdio bug-and-fix pairs under isolated pinned environments, and separately validate exact output causes rather than only classifying reported errors. Delay P6-C until repeated independent held-out evidence exists.
