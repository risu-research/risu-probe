# RISU Probe P6-B9 — Prelocked External Bug-Fix Generalization Audit

**Date:** 2026-11-08 UTC. **Status:** complete source-level heldout qualification on a dedicated branch; not merged into `main`, not a new package release, and not a population-wide performance study.

**Base product:** RISU Probe 0.9.25.dev0. The B9 analyzer snapshot was fixed at Git blob SHA-1 `b709cc61e37657ff18f90b15113aa500334e6762`, reached in commit `94804eebeb40412b2957d416c47d9c174a8f1df5`. The actual original product `main` and prior P6-B7, P6-B8 source evidence remain intact. The seven-family source/commit/blob register was recorded **before any of these seven external source executions** in `benchmarks/p6b9/prelocked_seven_families.json`.

## Executive result, with correct denominator

| Frozen-score metric | Actual result | Interpretation |
|---|---:|---|
| Selected external upstream defect families | 7 | Hand-picked public bug reports, **not random** |
| Source/component-level before/fix reproductions independently adjudicated | **7/7** | Each genuine pinned source pair changed as described |
| Frozen RISU reported relevant mismatch or diagnostic only on BEFORE | **5/7** | Only selected set; some reconstructed envelopes |
| Direct schema/structured-content mismatches (adapter-supplied contract) | **3** | PHP673, GO1139, RUST137 |
| Catalog incompleteness / duplicate tool diagnostics | **2** | PROXY253, AG23262; not root-cause proofs |
| Confirmed reproduced defects **missed** | **2** | CYAN760, CYAN785, preserve both negative results |
| Families whose selected normal control failed | **0** | Controls narrowly targeted to case, not an unbiased false-positive sample |
| Ecosystem precision / false-positive rate | **Not estimable** | No random normal-set sampling, some witness shaping |

**Do not cite 5/7 as an ecosystem-wide recall estimate, 0 control failures as zero false positives, or 7/7 as a representative defect prevalence.** This was a preregistered *selected-case technical generalization* experiment.

## Original frozen engine enhancement

- `tools/list` now accepts an ordered, fully cursor-linked sequence of pages. It rejects incomplete records, repeated cursors, orphan continuation pages, mismatched opaque cursor requests, invalid declarations across pages, and budgets above 100 pages / 1,024 tools. Catalog contracts become usable only upon a verified terminal page. Single-page usage, semantic types and previous tests remain supported.
- Parser budget and evidence limits remain bounded. The baseline `src/risu_mcp_trace.py` is an offline analyzer and never executes target code.
- `tests/test_p6b9_cursor_completeness.py` adds 13 unit scenarios, including a 100-seed randomized-but-reproducible paging partition check. `tests/test_p6b9_score_aggregation.py` adds 9 independent-ledger safety checks, including missing-case accounting and fabricated score rejection.
- Latest complete installed-wheel regressions passed **185 tests on Linux, Windows, and macOS**, in https://github.com/risu-research/risu-probe/actions/runs/42510565798.

## Seven independently registered source-family results

| Family | Actual public upstream defect, old versus official fix | Frozen RISU result | Evidence / limits | CI source |
|---|---|---|---|---|
| PHP673 | `modelcontextprotocol/php-sdk` #673; explicitly supplied `structuredContent: null` dropped through constructor and `fromArray`; fixed serializer retains null | **RMC501** on old (two manifestations), none on fixed | Original PHP SDK serializer, synthetic result wrapped into adapter JSON-RPC. Normal omitted, `false`, `0`, `''` controls | [42508748186](https://github.com/risu-research/risu-probe/actions/runs/42508748186) |
| GO1139 | `mark3labs/mcp-go` #1139; invalid `RawStructuredContent` ignored by old output validator, rejected by fix | **RMC502** on old, none on fixed | Real Go `MCPServer.HandleMessage` handler results and actual `tools/list`, adapter correlates IDs; valid structured number control. Large integer *input* subcase not tested | [42508965048](https://github.com/risu-research/risu-probe/actions/runs/42508965048) |
| PROXY253 | `sparfenyuk/mcp-proxy` #253; proxy forwards no opaque cursor, so page 1 is repeated; official fix forwards `params` | **INVALID_CATALOG** on old, not fixed | Genuine proxy handler with local fake remote MCP peer and reconstructed JSON-RPC. Symptom only, four affected handlers count as one root cause | [42509194567](https://github.com/risu-research/risu-probe/actions/runs/42509194567) |
| CYAN760 | `cyanheads/mcp-ts-core` #760; error text contains unescaped Markdown-active input; fix safely escapes display while structured error message stays raw | **MISSED** | Actual source error builder and normal control; text rendering semantics outside frozen schema checker | [42509461777](https://github.com/risu-research/risu-probe/actions/runs/42509461777) |
| CYAN785 | `cyanheads/mcp-ts-core` #785; rendered enrichment value is escaped so copying query changes it; fix uses suitable code literal | **MISSED** | Actual source enrichment handler and normal control; exact copy-paste semantics not part of frozen schema checker | [42509461777](https://github.com/risu-research/risu-probe/actions/runs/42509461777) |
| AG23262 | `ag2ai/ag2` #3262; old MCPToolkit discovery drops page 2, fixed toolkit accumulates it | **INCOMPLETE_CATALOG_PAGINATION** on old only | Actual AG2 toolkit logic with in-memory MCP SDK result test double; reconstructed JSON-RPC, not full stdio. Single-page normal control | [42509724198](https://github.com/risu-research/risu-probe/actions/runs/42509724198) |
| RUST137 | `avelino/mcp` #137; old Rust `ToolCallResult` serde roundtrip drops `structuredContent` / `resultType`; fixed preserves them | **RMC501** old only | Genuine pinned Rust typed-result serde, adapter JSON-RPC and normal unstructured control; **full Rust CLI was not executed** | [42509963619](https://github.com/risu-research/risu-probe/actions/runs/42509963619) |

### Source artifacts and SHA-256 provenance anchors

The following GitHub artifacts are public-only synthetic runs, each archived for 21 days from 2026-11-08 (approximately expiring 2026-11-29). SHA-256 identifies the archived ZIP, **not a digital signature**.

| Source family | CI artifact name | ZIP SHA-256 |
|---|---|---|
| PHP673 | `risu-p6b9-php673-public-independent` | `effed6fc5d78370b890dc8b211536833a8c58e9e2d2a79b914d4f073cdeeb5f5` |
| GO1139 | `risu-p6b9-go1139-public-independent` | `867af40f659b5d9577f3ad75adf2a2260e45c0951722fa073d532da17f29b16e` |
| PROXY253 | `risu-p6b9-proxy253-public-independent` | `44962d0f286fd7217799c0683ca2103da46f6538f36eb175b1d03d9584dea4e5` |
| CYAN760 and CYAN785 | `risu-p6b9-cyan760-785-independent-public` | `b90a7770a642d3b9f128713b31471f1b3cdde07bc022e473f376ce11f40d8f5e` |
| AG23262 | `risu-p6b9-ag23262-public-independent` | `4134217c51575271dd36764ebc6d2b7f313f2f2e93841e41e361e39383a5fe21` |
| RUST137 | `risu-p6b9-rust137-public-independent` | `ad969f92a57236efe86fad814e7a3195c5b4afc510f1ea6742594a5caafb3ef2` |

**Independent cross-run aggregation:** The read-only GitHub workflow downloaded all six source artifacts from their exact immutable execution IDs, extracted all seven source-score JSONs, verified that every preregistered family was represented, and independently tallied 7 verified, 5 detected, 2 missed, 3 direct adapter mismatches and 2 catalog diagnostics. [GitHub Actions aggregate #42510565833](https://github.com/risu-research/risu-probe/actions/runs/42510565833). Separate ledger artifact: `risu-p6b9-seven-family-frozen-ledger`.

The reconciler is `benchmarks/p6b9/aggregate_scores.py` with protective tests in `tests/test_p6b9_score_aggregation.py`. It deliberately reports how many selected cases are absent or unverified; it will not silently remove a failed case from the selected count. An `actions:read` token is used exclusively to download the seven prior source scores, with `persist-credentials:false` at checkout; the aggregation does not execute third-party target code.

## Interpretation

This is genuine cross-project evidence that the general-purpose JSON-RPC contract analyzer can reuse rules across **PHP, Go, Rust, Python MCP proxy and Python AG2**, but the source-facing adapters in several cases construct analyzable JSON-RPC envelopes around genuine upstream object results. That establishes **frozen-rule compatibility with those independently executed source components**, and must be separated from full black-box end-to-end MCP wire verification.

A second lesson is equally important: the two reproduced but missed TypeScript text/Markdown cases reveal a general family of **value fidelity** errors that are invisible to basic JSON Schema checking. Fixing this requires a separate, explicitly justified text-to-value relation (raw object versus rendered value), and a new prelocked independent holdout. Reusing CYAN760 and CYAN785 as an *independent* validation after adding such a rule would be leakage.

## Next engineering gate

1. Turn two misses into *development* cases; make an optional, bounded and non-LLM `display-fidelity` checker where both original scalar value and rendered text exist and an explicit decoding policy is supplied. Never attempt to infer semantic equality from arbitrary prose or tool names.
2. Collect **new, unseen** independent real upstream text/display and protocol bugs, with normal rendered Markdown and literal-text controls. Freeze test selection and engine before any scoring.
3. Gradually replace source-level adapters with actual stdio/SDK-wire recordings wherever safe and possible. Label any remaining reconstructed envelopes.
4. Keep B7, B8, B9 score files immutable. Avoid merging this qualification branch to `main` or claiming production-ready accuracy until a more heterogeneous, independently held-out suite and real consumer integration passes.
