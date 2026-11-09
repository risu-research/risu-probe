# RISU Probe P6-B10 — Explicit Display & Copy Fidelity Qualification

**Date:** 2026-11-08 EST / 2026-11-09 UTC. **Status:** qualification-branch implementation and source-level heldout completed, with one independently re-executed actual stdio upgrade. **Not merged** to `main`. **Not a new public package release**: package remains `0.9.25.dev0`.

## Why this is a new semantic class

A tool response can satisfy a declared JSON Schema while containing a misleading, lossy or syntactically escaped human/model-facing `content[]` text. Checking `structuredContent` against `outputSchema` cannot detect this category. Yet the two surfaces do **not** universally need to contain identical information. Many tools intentionally return a short summary and a detailed structured object.

B10 therefore provides **opt-in, caller-declared correspondence only**. RISU never invents which structured field a sentence represents. A rule identifies the exact tool, a JSON pointer inside `structuredContent`, a specific `content[]` text block and an unambiguous text prefix. Only that declared scalar relationship is checked.

The two new rules are:

- **RMC507, Markdown-rendered drift:** parse a single bounded CommonMark paragraph locally and compare its displayed scalar text to the declared structured source string. Emphasis that swallows literal asterisks, loss of a newline and URL defanging can now be observed.
- **RMC508, raw/code-span copy drift:** compare a segment that an automation or model copies as raw text, or the content of a lone Markdown inline-code span, with the declared structured source. Unnecessary backslash escapes are observable without assuming arbitrary GUI copy behavior.

All observations remain `OBSERVED_IN_UNATTESTED_CAPTURE` until accompanied by an independent upstream execution artifact. The standard schema and behavioral checks from B9 remain separate and intact.

### CLI and exact opt-in mapping

For an authentic saved JSONL trace, create a *separate*, explicit, small `display-contract.json`:

```json
{
  "schema": "risu-mcp-display-contract-v1",
  "rules": [
    {
      "id": "search_query_echo",
      "tool": "search_records",
      "source": "/effectiveQuery",
      "content_index": 0,
      "prefix_raw": "**effectiveQuery:** ",
      "mode": "raw-copy",
      "on_error": false
    },
    {
      "id": "search_error_message",
      "tool": "search_records",
      "source": "/error/message",
      "content_index": 0,
      "prefix_raw": "Error: ",
      "mode": "markdown-rendered",
      "on_error": true
    }
  ]
}
```

```shell
risu-probe verify-mcp-trace saved_mcp_stdio.jsonl \
  --display-contract display-contract.json --format json
```

The JSON pointer is relative to the `structuredContent` object, **not** the full JSON-RPC envelope. `content_index` is the position in `content[]`. A prefix must appear **exactly once** in the chosen text block. The `on_error` flag distinguishes success and tool-level failure. A rule is an **asserted contract**, not an inference from tool names or field coincidence.

### Fail-closed safety and boundaries

- Maximum 48 rules and a 32 KiB regular local JSON contract; duplicate JSON keys and invalid JSON Pointer escapes rejected.
- At most 16 potential content positions, max 4,096 characters for a source scalar or extracted value, bounded pointer depth/segment size, at most 1,024 parsed inline tokens.
- Only one plain CommonMark paragraph is interpreted. HTML-like markup, links, unsupported block syntax, nontext carriers, multiple possible prefixes, missing sources and ambiguous extraction yield **UNVERIFIED**, not a mismatch.
- Raw-copy is the semantics of copying the raw recorded tool text (or a complete standalone inline code span), **not** a claim about every rendered website or model client.
- The product does not connect to servers, execute user projects or load schemas remotely for this check. Findings and gaps are generic and do not echo raw source strings; only rule-ID hashes and tool hashes appear in the public report.
- `isError=true` results are eligible only for explicitly declared display assertions. They continue to be excluded from successful output-schema assertions, with the original execution-error gap retained.
- `markdown-it-py>=3,<5` is an installed-wheel dependency, not a network parser.

## Proof layer A: original B9 development families, excluded from new independent score

B9's two **previously missed** source-real upstream defects were switched to **development regression**. The B10 job reused the actual old and fixed pinned `cyanheads/mcp-ts-core` TypeScript result artifacts produced by B9, rather than replacing those results with hand-written strings.

| Previous B9 miss | B10 new rule | Actual old upstream output | Official fixed upstream output | Development control |
|---|---|---|---|---|
| CYAN760 — unescaped Markdown in error text | RMC507 | mismatch found | no corresponding finding | passed |
| CYAN785 — escaped query in copyable enrichment | RMC508 | mismatch found | no corresponding finding | passed |

[Original B9 source output replay under B10](https://github.com/risu-research/risu-probe/actions/runs/42545327577) succeeded. These **do not count** in B10's new independent detection denominator.

## Proof layer B: separately preregistered new external source-family holdout

The new 3-case selection was committed **before any of these three original upstream source pairs was executed**, in [prelocked_three_heldout.json](../benchmarks/p6b10/prelocked_three_heldout.json). Recorded immutable analyzer identity:

- `src/risu_mcp_trace.py` Git blob SHA-1 `f722cd7fdc380e04a3416ba5defba99f249af950`
- `src/risu_display_fidelity.py` Git blob SHA-1 `f4f6dc4241ce4cfed355f9dddae2307e642b35ad`

Each case is pinned to a public issue, an exact before and official fixed Git commit and exact source-file blob hash. The original upstream TypeScript function was executed with Bun using a synthetic input. The evaluator then constructed an explicitly labeled JSON-RPC envelope using the genuine returned `content[]` scalar. No third-party source code was patched and no live external services or user credentials were needed.

| New family / public issue | Source-level before/fix discrepancy, with explicit structured comparator | Before | Official fix | Narrow normal control |
|---|---|---|---|---|
| [GEONAMES28](https://github.com/cyanheads/geonames-mcp-server/issues/28) | `inlineText('www.example.com')` changes a literal URL trigger to `www[.]`; fixed function retains literal | RMC507 | no finding | passed |
| [OPENALEX128](https://github.com/cyanheads/openalex-mcp-server/issues/128) | `escapeMarkdown('alpha\nbeta')` flattens the newline; fix retains the rendered line break | RMC507 | no finding | passed |
| [MITRECWE16](https://github.com/cyanheads/mitre-cwe-mcp-server/issues/16) | `formatCatalog({literal:'CWE-80'})` adds an unnecessary backslash to copyable identifier; explicit `Value: > ` prefix selects the literal from the genuine output block | RMC508 | no finding | passed |

**Frozen per-source trials:** [GitHub Actions #42544822432](https://github.com/risu-research/risu-probe/actions/runs/42544822432), all 3 families succeeded.

**Separate artifact-based cross-run tally:** [GitHub Actions #42545552991](https://github.com/risu-research/risu-probe/actions/runs/42545552991), original three artifacts downloaded and reconciled against the initial manifest. **Preselected 3, reproduced with normal controls 3, relevant rule findings 3, missed 0, unverified 0.**

**Important independence caveat:** All three projects are separately pinned source repositories but share the **same open-source publisher (`cyanheads`)**. This supports reuse across three distinct codebases, **not** vendor independence or a population-wide detection rate. The reported detections are also **source-function outcomes carried in reconstructed JSON-RPC envelopes**, not unmodified actual stdio or end-to-end remote MCP tool executions. Only a narrow normal control was checked per source. Therefore neither recall nor a false-positive rate for all MCP software is estimable.

### External source artifact identity

The 3 GitHub ZIP artifacts, expiring around November 30, 2026 UTC, have these GitHub-reported SHA-256 checksums, **not signed attestations**:

- `risu-b10-public-display-GEONAMES28`: `ea9cc8b3ac77cbbd2d1774c159d9be7b9f025b9e5152ec4ca4e801e41bf11cea`
- `risu-b10-public-display-OPENALEX128`: `55c3434de7779dc04c5dfa305a4c62c56a8f7b78ad6cd636bd60315999ee0f46`
- `risu-b10-public-display-MITRECWE16`: `9945a275e561dd9f2bbfb3e3d6ee2f256804afaed949409e3f3b20e77d8d9d8f`
- Reconciled `risu-b10-prelocked-three-independent-source-ledger`: `5e5d786fe4bcc94a4102a88eac2b791f3f3519ed0f0b24dc0e287cf9d73935d8`

The manifest's authored `registered_utc` field is **not a trusted audit clock**. Establish actual ordering from the GitHub commit timestamp for `2ae9eb214d72d7b46af02a42fe04c728cbc5da97` versus the source execution CI start timestamp.

## Proof layer C: replace one earlier adapter-based source result with authentic stdio bytes

**Previously used B9 case GO1139, not a new independent B10 family.** The source-level Go MCP SDK raw-output validation evidence was rerun with an original pinned Go SDK `StdioServer` linked into a minimal synthetic test server. Python sent an actual MCP JSON-RPC initialize, initialized notification, `tools/list` and two `tools/call` requests through real process stdin and preserved complete, original stdout response byte lines without reserializing them.

- Original public `mark3labs/mcp-go` source commit before fix `c0e5b67f97375fa284ec854d92cb2df49c2ef959`; official fix `8995d9b137ef36511e6f03a79f6ff0e5ba4d7574`.
- Genuine protocol negotiation: `2025-11-25` on both.
- Genuine original stdio: old invalid `RawStructuredContent` accepted but directly reported by RISU as `RMC502`; official fix emits tool error instead and no false successful-output violation is claimed. Valid control passes on both.
- Original recorded stdout response bytes are archived along with synthetic harness request bytes and SHA-256 trace fingerprints.
- [GitHub Actions #42545123488](https://github.com/risu-research/risu-probe/actions/runs/42545123488): **verified success**. Artifact `risu-b10-go1139-original-stdio-public`, SHA-256 `78fe95e5ebd4baee2c93f48aef1fcf2175b45986a5ae27514b30800d3472a7be`.
- **Scope:** this is a genuine stdio process for original SDK code with **test-registered synthetic tools**. Not a production MCP server with live services, and not a new heldout datapoint.

The B7/B8 Filesystem and Accessibility upstream tests already captured original stdio as development cases. B9's PHP serializer, Rust typed-result, Python proxy/AG2 in-memory, and the new three B10 source helpers remain appropriately classified as non-stdio, unless a future explicitly equivalent real stdio harness is built and rerun.

## Cross-platform and synthetic controls

- [Installed-wheel CI #42545445474](https://github.com/risu-research/risu-probe/actions/runs/42545445474) passed **209 tests on each of Linux, Windows and macOS** with `RISU_P6A_TEST_CLI` pointed to the genuinely installed entrypoint. Later full regressions after separate scorer additions also passed.
- New tests include user-declared mapping refusal, two previously missed development cases, correctly escaped and code-spanned normals, malformed contract rejection, unsafe Markdown refusal and confidential source-value redaction.
- `tests/test_p6b10_metamorphic_display.py` additionally exercises a **deterministic 600-pair** copy-scalar/control mutation corpus and **400-pair** Markdown old-versus-escaped-fix corpus under fixed seeds. These are generated synthetic tests, **not** additional external defects and **not** a representative false-positive-rate study.

## Architectural conclusion and next gate

B10 expanded RISU's useful semantic checks beyond JSON Schema. It uses an explicit, reviewable contract so summaries and structured data that were never intended as identical will not be compared. **The holdout proves this narrow checker transfers to three new same-publisher source projects**, while Go original-stdio upgrading shows how to raise evidentiary rigor for an older case.

Further work should prioritize: (1) **unseen defect/fix pairs from genuinely different organizations and languages**, with the entire selection preregistered, (2) actual MCP **stdio or wire records for B10 display cases** rather than output adapters, where feasible and safe, (3) declared, bounded structured multiline/table/code-fence transformations and content-to-structured partial mapping with strong false-positive controls, and (4) retaining all failures and uncertain provenance instead of chasing a 100% result. Do not put B10 on `main`, ship a new release or claim generalized accuracy until those gates are cleared.

**All outcomes are reproducible from code and published GitHub Actions workflows in this qualification branch.**
