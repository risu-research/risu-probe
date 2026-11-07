# P6-B2 — independent real-issue holdout and released MCP runtime replay

**Scope:** independent measurement, not a new marketing claim and not a merge into main. This repository contains PUBLIC artifacts and synthetic payloads only. The historical P6-B #5030 case trained RPY204; it and the earlier #3717 and #40471 test cases are excluded from the new independent numerator.

## Independent source evaluation

The labels, official commits, and Git blob SHA-1s were preregistered in \`frozen_cases.json\` at commit \`d845688599d0a3beddcbfd29763e52c9078923bc\`. The manifest is locked to SHA-256 \`77d17e853127090e59d01579b930dba4518151b97bdce67015793ce83c138071\`. The runner fetches only exact public Git objects (read only), verifies them, and scans **without importing or executing** the upstream project.

Frozen independent positives and upstream fixes:

- [Python SDK #3353](https://github.com/modelcontextprotocol/python-sdk/issues/3353) / merged [#3354](https://github.com/modelcontextprotocol/python-sdk/pull/3354): boolean JSON Schema sub-schemas are invalidated by the historical 2025-11-25 generated model, fixed by accepting booleans.
- [Python SDK #3337](https://github.com/modelcontextprotocol/python-sdk/issues/3337) / merged [#3376](https://github.com/modelcontextprotocol/python-sdk/pull/3376): a recursive tool return emits a root \`$ref\` without required legacy object root, fixed by resolving the root definition.

Four case-level negative/control records (not proved globally defect-free): those two exact official fixes, a newer protocol's already-accepting schema model, and a [FastMCP #3590](https://github.com/PrefectHQ/fastmcp/issues/3590) report whose author withdrew the upstream-bug claim after recognizing that the consumer read \`structuredContent\` instead of the modified text block. A TypeScript SDK case is excluded as unsupported.

## Results and interpretation

The actual \`risu-probe-preview 0.9.21.dev0\` installed wheel parses all six in-scope Python source files with zero parse gaps. It reports **zero static findings** on all of them. Against the two independent official source defects, **0/2 matched detections, 2/2 misses**. Against the four specific negative/control records, **0/4 issue-matched alarms**, with no incidental warnings; this does NOT establish general false-positive rate or specificity because there is no issue-specific detector for these cases. Precision is undefined. These are only seven deliberately selected public records, not representative of an ecosystem population.

A successful Python AST parse does not mean the tool inspected the MCP schema, its negotiated protocol, or the client's runtime validator. We explicitly report this **semantic assurance gap** for both positives instead of pretending that "no findings" means "safe".

## Genuine released SDK runtime

The independent job installs **official mcp==2.0.0 / mcp-types==2.0.0** and **2.1.0 / 2.1.0** in *separate* virtual environments.

- #3353: calls the genuine SDK \`validate_server_result\` on public, non-malicious synthetic \`tools/list\` schemas. At 2025-11-25, old rejects and fixed accepts boolean property schemas. At 2026-07-28, both versions accept (positive control). This test is **real SDK validation, not an MCP wire session**.
- #3337: registers a recursive Pydantic return and a healthy \`heartbeat\` tool using actual \`MCPServer\`; a genuine \`Client(mode="legacy")\` executes the 2025-11-25 in-process MCP JSON-RPC route. Old fails \`tools/list\`, hiding *both* tools, while fixed lists both and successfully calls the recursive tool. It is a **real SDK in-memory protocol call, not external stdio or production traffic**.

These runtime results prove the two bugs had an observable effect and the official released fix corrects it in the tested scenario. They do **not** mean RISU automatically diagnosed them. The product scanner remains unchanged in P6-B2.

## Method comparisons without artificial rankings

- **Ruff:** use per-rule negative tests, unchanged-rule regressions, stable output codes. A Python source scanner may analyze the relevant file, but there is no guarantee it understands MCP semantics.
- **Schemathesis:** use a frozen testcase corpus, paired before/fix examples, deterministic local reproduction and distinct baseline vs newly introduced failures. No HTTP fuzzing was run in P6-B2.
- **oasdiff:** compare OpenAPI versioned contracts when available. The present two cases concern Python SDK implementation and negotiated MCP protocol; oasdiff is **NOT APPLICABLE**, not a detection failure.
- **mcpdiff:** compare two actual MCP tool catalogs where supported, including schema drift. The #3353 failure involves a *client validator version*, and #3337 involves the *publisher's schema generation*, so a catalog diff alone is not the same test. No scored mcpdiff execution is claimed here.
- **MCP Inspector:** its live protocol inspection is a useful interoperability path; the P6-B2 legacy session is through the official SDK, not Inspector.
- **Renovate:** treat verified upstream fixes as reviewed, reproducible change candidates. No automatic upstream source modification or public PR is made.

## How to reproduce (public CI)

\`\`\`sh
python -m unittest discover -s tests -v
python benchmarks/p6b2/evaluate.py --manifest benchmarks/p6b2/frozen_cases.json \
    --cli /path/to/installed/risu-probe --scratch /tmp/p6b2-public-git \
    --out /tmp/p6b2-static.json
\`\`\`

The benchmark runner requires public Git connectivity but never imports third-party checked-out sources. The released SDK runtime is performed by \`.github/workflows/p6b2-independent-runtime.yml\` in isolated pip environments; PRs run **only** the safe installed-product tests, never the external-source or protocol jobs. All CI jobs use \`contents: read\`, no secrets, and checkout \`persist-credentials: false\`.

## Next gate before P6-C

Expand to another organization and a truly independent positive with an issue-specific existing detector; compare rule false alarms on larger in-domain negatives, and decide whether native protocol-checking belongs in RISU's optional executable evidence flow. A plain zero-warning report on valid Python source must continue to mean "nothing detected by these rules", not "MCP runtime correctness proved".
