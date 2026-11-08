# RISU Probe P6-B10 — Value preservation and display fidelity

**Qualification date:** 2026-11-08 UTC. **Status:** implemented, preregistered three-family source-level holdout completed and independently aggregated; not merged into `main` or published as a product release.

## Summary of what is proven

RISU now includes an **opt-in, bounded offline value-fidelity verifier**, separate from JSON Schema validity and MCP tool success. The caller supplies an explicit relationship between a captured `structuredContent` string and one named Markdown output line. It tests that the string remains meaningful when rendered or copied.

- **Display literal, `markdown-literal`**: parses the declared value segment using CommonMark and checks whether rendered literal text reconstructs the original string. Active links, HTML and images in the segment are rejected. Escaped emphasis syntax is not misreported as text corruption.
- **Copyable value, `code-copy`**: the declared value must be available as a code literal, or as a strictly limited plain, safely copyable token. An escaped-but-visually-correct raw text value may fail this stricter policy.
- **Special JSON string, `json-string-special`**: for an empty string, line break, tab, or leading/trailing whitespace, the rendered value must be a valid JSON string code literal recovering the exact original string. Ordinary safe values use Markdown literal comparison.

The engine never guesses the origin path, semantics, or intended output label from a tool name. It requires a caller-authored JSON contract with a bounded JSON pointer, tool name, line prefix, error status and comparison mode. Outcomes are `RDF601` (observed mismatch), PASS, or explicit UNVERIFIED. No untrusted result values appear in output reports. A capture remains unauthenticated.

Entry point:

```bash
python -m pip install '.[fidelity]'
risu-probe verify-display-fidelity recorded.jsonl --contract explicit-contract.json --format json
```

The optional `markdown-it-py>=4,<5` dependency is intentionally scoped to the fidelity feature; when absent, that feature cannot claim checked results. The new `src/risu_display_fidelity.py` module is packaged in the installed wheel, and the CLI dispatches `verify-display-fidelity` without affecting the existing `verify-mcp-trace` interface.

## Frozen detector and development/holdout separation

- P6-B9 seven-family result remains **7/7 source reproduction; 5/7 related detections**, with CYAN760 and CYAN785 recorded as **misses** at B9. The B9 ledger is not altered.
- CYAN760 and CYAN785 are now **development regressions**, not a second independent test. Their genuine, pinned upstream source captures were retrieved from immutable B9 Actions artifact `13629135201` with matching ZIP digest `sha256:b90a7770a642d3b9f128713b31471f1b3cdde07bc022e473f376ce11f40d8f5e`. Both now produce one B10 RDF601 on the original and none on the official fixed source; both normal controls remain warning-free. Replay CI: https://github.com/risu-research/risu-probe/actions/runs/42513407913
- The **new** three external holdout families were preregistered in `benchmarks/p6b10/prelocked_three_display_fidelity.json`, with their exact upstream Git commits and blobs, before rule-specific implementation or upstream execution.
- The detector was frozen **before any new external source execution**, at `src/risu_display_fidelity.py` Git blob SHA-1 `8bc96f64eba96a314479dfaea17af46b38e1ad0a`; freeze details in `benchmarks/p6b10/detector_freeze.json`. Later edits adjusted testing, Git fetch, archiving and aggregation, **not** the detector.
- Historical Git fetch diagnostics exposed a 39-character abbreviation of the old ClinicalTrials revision. It was corrected to the original 40-character committed source ID, without changing the selected issue or source blob. Intermediate failed CI attempts remain visible.

## New independent source-family outcomes

| Family | Genuine fixed upstream source | Independent old/fix causal reproduction | Frozen B10 detector | Normal control |
|---|---|---|---|---|
| GEONAMES28 | `cyanheads/geonames-mcp-server` issue #28 | URL text was defanged in old renderer, preserved in official fix | RDF601 old, none fixed | Pass |
| CLINICAL177 | `cyanheads/clinicaltrialsgov-mcp-server` issue #177 | Search condition became active Markdown link in old renderer; fixed code literal recovers original | RDF601 old, none fixed | Pass |
| FDIC25 | `cyanheads/fdic-banks-mcp-server` issue #25 | Newline collapsed and empty string became ambiguous in old renderer; official fix emits JSON code literals | RDF601 old, none fixed | Pass |

**Selected source families:** 3. **Genuinely reproduced:** 3. **Issue-relevant diagnostic on old only:** 3. **Unverified:** 0. **Selected normal control failures:** 0.

These are three *nonrandom selected defect families*. No ecosystem-wide precision, population recall, or false-positive rate can be estimated. Every case executed a genuine pinned original TypeScript **source module or tool definition** against synthetic inputs, not a complete live server or genuine wire capture. The JSON-RPC envelopes and source-to-display association were explicitly produced by a test adapter. That distinction is an essential limitation and is machine-readable in the score JSON.

Independent source runs, using the original detector hash:
- GEONAMES28 + FDIC25: https://github.com/risu-research/risu-probe/actions/runs/42513633746
- CLINICAL177: https://github.com/risu-research/risu-probe/actions/runs/42513638014

## Independent aggregation and artifact reproducibility

`benchmarks/p6b10/aggregate_three.py` reads only previous, immutable source score JSON files, verifies the selected set, evidence types, booleans and selection labels, and marks missing/failed reproductions as unverified rather than quietly removing them. `.github/workflows/p6b10-aggregate-three.yml` verifies the GitHub artifact names and ZIP SHA-256 digests, downloads by exact original run IDs, and reconciles all three sources without running third-party target code. Read-only `actions:read` permission is sufficient.

Original source evidence artifacts were initially uploaded with hidden folders excluded by default; the first aggregation **failed** as it should have. The workflows were corrected with `include-hidden-files:true`, and the public, synthetic original pairs were rerun. A successful source CI log is no substitute for preserved evidence files. The reruns are:
- `risu-p6b10-prelocked-source-holdouts`, artifact ID `13629319972`, ZIP digest `sha256:9fee610207f415aa386a37a9152ac0200051e4ed211326dbf64f51edfd6f7cb3`.
- `risu-p6b10-clinical177-prelocked`, artifact ID `13630985205`, ZIP digest `sha256:168484eca8e764e08a284559d955b54878c650e27be07b92d56558f72c5c6bb2`.

Read-only aggregate CI: https://github.com/risu-research/risu-probe/actions/runs/42513707420
Result: **3 selected, 3 reproduced, 3 detected, 0 misses, 0 unverified, 0 selected normal-control failures**. The second archiving run with hidden results included is tracked in the same workflow family.

SHA-256 anchors artifact identity, **not** independently attested execution. The artifacts have the configured 21-day retention period; source, commit pins, workflows and scripts remain in the repository.

## Cross-platform and safety checks

The full, freshly installed wheel was tested on Linux, Windows and macOS. The observed comprehensive suite passed **197 tests on each operating system**, for example https://github.com/risu-research/risu-probe/actions/runs/42513637983. Tests include the existing B9 behavior and the B10 adversarial Markdown checks. The production-facing scanner remains offline and read-only, with no external project execution or network requests. Upstream source execution happens only in dedicated, pinned, synthetic public GitHub Actions experiments, not on external pull requests.

## Remaining limits before merging

1. The selected source tests use explicit value-mapping assertions; RISU has not autonomously inferred semantic obligations from arbitrary server output.
2. Three hand-selected source defects and narrow normal controls do not establish broad correctness. Expand independent diverse normal corpus, pathological Markdown and multiline cases, and compare parser dialects without changing the frozen B10 score.
3. End-to-end authentic SDK/stdio wire capture should replace adapter reconstruction where the real servers can safely run offline with synthetic inputs.
4. Add a stable machine-readable contract specification and sample CLI fixtures before a release. Package version is still `0.9.25.dev0`; do not advertise a new release or merge into main without a deliberate release audit.
5. Avoid interpreting a Markdown formatting policy as universal. B10 must only assert the caller-requested display/copy policy. A valid Markdown display and a copy-safe raw value are different obligations.

**Next recommended gate: P6-B11:** build a larger, independently frozen mixed positive/normal holdout, particularly existing real-world converter and Markdown edge cases. Do not use the B10 three examples as independent test data again after further rule tuning.
