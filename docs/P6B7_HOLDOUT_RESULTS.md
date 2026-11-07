# RISU Probe P6-B7 — unchanged-product independent external server holdout

**Status:** final CI SUCCESS, frozen original product **0.9.25.dev0**, no scanner rule changes. **NOT merged into main**.

## Reproducibility pointers

- Original P6-B6 product commit: \`601f086903b20b61df2f44e8a569d82df67f03a7\`
- Original test set preregistered in commit \`98d6f4e4774aa0b7449b227094941ec48287b881\`
- Frozen manifest Git blob SHA-1: \`f91f15fc8324ebe8741fb295bbd70f258197f136\`
- Final GH Actions success: https://github.com/risu-research/risu-probe/actions/runs/42385025402
- Final CI test and data capture commit: \`3fa971b85d6416dad5d65edb256db2f26d8699bd\`
- Original public-only CI artifact SHA-256: \`e3a55b03466b7a830574d5dcdd62437c504fce1903c94e5f42f46228f2b93e08\`

All four execution settings used exact upstream public commit IDs, checked Git blob hashes, installed npm dependencies with install scripts disabled, and executed the real public MCP servers over stdio with synthetic inputs. They did NOT access customer files, accounts, remote MCP endpoints or cloud credentials. The RISU analyzer itself did not execute target code.

## Independent cases fixed before the baseline

1. **Community-Access/accessibility-agents issue #205**, old commit \`284865a7\`, official fix \`decf6bac\`. Calling \`check_contrast\` against genuine server version 7.0.2 returned \`isError=true\` and a text error saying the SDK rejected the missing structured result required by \`outputSchema\`. In 7.0.3, the same call succeeded and returned schema-valid \`structuredContent\`. The original 39-tool \`tools/list\` is beyond RISU 0.9.25's bounded JSON complexity budget. Both raw BEFORE and AFTER captures returned CLI exit 2, **not a successful scan**. A clearly marked *secondary*, one-tool-catalog projection preserved the original call/response, but the old tool's error result was classified \`EXECUTION_ERROR\`, not an issue-specific finding. No source reimplementation or error injection was used.
2. **modelcontextprotocol/servers Filesystem Server issue #5184**, old commit \`3bd13377\`, merged fix PR #5377 commit \`0dce8bd9\`. Real \`read_text_file\` with \`head=0\` returned the entire synthetic four-line file before the fix, and empty text after. Both outputs conformed to the declared output schema. The official head=2 ordinary read was unchanged. Original (unprojected) RISU scans parsed both versions and reported \`CHECKED_NO_MISMATCHES\`, so the behavioral error was missed.

**Metric table:**

| Metric | Frozen 0.9.25 result |
|---|---|
| Verified independent upstream bug families | 2 |
| Detected by the original RISU product | 0 |
| Missed families | 2 |
| Per-case recall, selected sample only | 0/2 |
| Issue-related false alarms on official fixed versions | 0/2 |
| Raw capture scanner refusals (defect cases) | 1 |
| Extra one-tool-catalog projected detections | 0 |
| Correct ordinary head=2 control calls | 2 |
| Precision | Undefined (no positive detections) |

These are *two selected cases*, not a representative or random test population. Their selection was motivated by published upstream bug reports, rather than hidden adjudication. No ecosystem-wide precision, specificity, or recall estimate follows. A failed-to-parse raw catalog is an **unverified scan**, not a passing no-warning scan.

## Causal lessons, with engineering action

- **P6-B8a — large real catalogs:** selectively index and bound \`tools/list\` to requested tool(s) without omitting, fabricating, or silently excluding catalog errors. Test full real 39-tool source; emit explicit coverage and budget accounting.
- **P6-B8b — tool output validation errors:** capture \`isError\` outcomes as separate error diagnostics, including *known SDK output-schema rejection forms*. Never assume every \`isError\` denotes a bug; distinguish expected tool errors, server/tool exceptions, validation errors and incomplete evidence. A server error text is not independent proof of a root cause.
- **P6-B8c — behavioral oracles:** a conformant JSON Schema does **not** guarantee a correct value. Add optional, explicit replay assertions or safe metamorphic properties such as \`head=0 => empty\` where justified by tool semantics. Never infer all method semantics from a name or create a false conformance guarantee.
- **Retest:** move #205 and #5184 to a development/regression split after a rule is implemented; separately freeze other real upstream bugs as a *new* independent holdout before measuring generalization. Use Ruff-style per-rule positive and negative tests and Schemathesis-style stored reproductions/baselines. oasdiff and mcpdiff apply to contract/version comparisons only; do not award them a fake failure on a purely behavioral correctness issue.

**Security:** public repository only; read-only GitHub token; no PR-triggered execution of third-party servers; temporary synthetic data; no secrets. Raw captured tool metadata is public upstream content. The artifact is untrusted, has no cryptographic signature. SHA-256 identity anchors it to the recorded artifact only.

**Version disclosure:** P6-B7 measures existing \`0.9.25.dev0\`; it introduces no product release and does not change \`main\`.
