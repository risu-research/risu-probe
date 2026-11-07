# P6-B6: real external Memory MCP server and official merged fix

**This is a known-defect targeted regression, not a new discovery rate or an unseen holdout.**

## Frozen provenance

Upstream public repository: https://github.com/modelcontextprotocol/servers

- Independent user reports: https://github.com/modelcontextprotocol/servers/issues/3074 and https://github.com/modelcontextprotocol/servers/issues/3144 (both share ONE root cause).
- Official merged PR: https://github.com/modelcontextprotocol/servers/pull/3213 (January 14, 2026).
- Before: 861c11b786b3efbc87eb2e878a4039d33846a031
- Official fixed merge: 72e11113edff5919e74de1d69b71203991fe2f05
- Frozen Memory Server source Git blobs: old c7d781d2c4315f8806b6c4d217a3be4e00774c1e; fixed 600a7edcc81e2b5b73d20c90f7502203c6c93956.
- Both package versions are 0.6.3 with identical package-lock Git blob 1ad7eae64faf23ee5d7c0a7dad8d64a120ed2372.
- Exact Git pins and blobs are independently verified before installation. npm install scripts are disabled.

## Actual process execution

The compiled, unmodified upstream Node Memory Server runs in a separate process. The harness saves literal MCP JSON-RPC stdin/stdout messages, including initialize, tools/list and tools/call, for three read operations and a negative control. The input is a temporary PUBLIC synthetic JSONL file with two entities and one relation. A second variant adds an extra custom_id to an entity, as reported in #3144. A third empty-file scenario checks an ordinary safe read. Both source commits receive identical inputs.

Before the fix, the server still returns isError=false; the outgoing structuredContent contains storage-only type discriminator fields, forbidden by its declared strict outputSchema. Official fixed code returns clean records.

The original RISU 0.9.24 abstained because the server declares JSON Schema Draft-07, which it did not support. P6-B6 repairs **general bounded schema dialect recognition**, without introducing server-name- or field-name-specific rules. Draft-07 receives Draft7Validator. Draft 2020-12/default retains Draft202012Validator. Unsupported or mixed dialects, remote schema refs, complex regex and format assertions remain unverified.

Against actual unmodified upstream stdio recordings, candidate RISU 0.9.25 returns RMC502 on each of three affected read calls for both defective-data variations (6 observed mismatches total, one root bug), no findings on either official fixed recording and no findings on either empty-store control. The independent oracle uses a separate Draft7Validator directly on raw stdio, yielding 7 instance-level schema errors before and 0 after for each positive variation.

- Real upstream CI: https://github.com/risu-research/risu-probe/actions/workflows/p6b6-real-memory.yml
- Three-OS installed-wheel CI: https://github.com/risu-research/risu-probe/actions/runs/42380166663
- 150 unit tests passed on each OS, 36 of 40 prior source modules byte-identical.

## Boundaries

One upstream defect family, not 6 independent bugs; two different real upstream user reports are corroborating observations. The actual server is real but data synthetic. Captures remain UNATTESTED_LOCAL_CAPTURE, even if bundled with CI run receipts. No private repository, customer data, credentials, external MCP URL, model API, or live production service were used.

The issue informed Draft-07 support, so this is a targeted before/fix regression; do not claim heldout recall. Previous P6-B2 independent static score 0/2 remains unchanged. A new source family and independent preregistered holdout are worthwhile before moving to P6-C.

CI uses read-only contents permission, credentials are not persisted, and full upstream compilation runs on push/maintainer dispatch only, never on external PR.
