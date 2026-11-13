# P6-B37 | Independent source holdout and evidence-based product decision

**Outcome: B37 independent Python source-hypothesis recall was 0/7 on seven pinned, upstream-repaired MCP defects, with one additional Rust case explicitly unsupported.** The read-only full original Git-blob evaluation completed successfully. This remains the permanent out-of-sample result even if later research on these cases succeeds.

## Frozen chronology and provenance

1. Original public product `main`: `8d622b792b4ae58b7157fd81ee5f95d6febcfd53` / `risu-probe-preview==0.9.23.dev0`.
2. [B37 preregistration](PREREGISTRATION.md) committed **before B37 original source inspection or detector implementation**, commit `59de1a6afeb09a330849e2640ddba29fc8e3121e`.
3. [B37 sealed eight independent original external fixes](SEALED_HOLDOUT.json), commit `cab656d25c44fc4b9a12e2faa5aabf0cdeb28fa4`, file Git blob `7e71d523996a0cb1a2387d161c93eb0c34ef33d1`. Seven primary Python cases + one Rust gap. Nine source files each pinned at exact immutable original pre/post Git tree and Git blob. No B34/B35/B36 upstream organization reused.
4. B37 detector developed **solely on previous B34/B35/B36 source and controlled normal tests**, new algorithm at `qualification/p6b37-development-robust-semantic-20261113@fd025a31a18d5d1c57f089af19ab8342b25f6cd4`, source Git blob `412165214a181cf43ef62c69c9711b737f73c268`, inherited unchanged B34 algorithm blob `79c8b45901766179c7e39b17969c726a276e543d`.
5. The [B37 unit-controls workflow](https://github.com/risu-research/risu-probe/actions/runs/43511962074) passed 15 test scenarios on Ubuntu, Windows, and macOS (normal pass-through, error content, JSON output shape, partial parse and fail-closed coverage).
6. [Prior B36 development-only workflow](https://github.com/risu-research/risu-probe/actions/runs/43512214650) passed: original 5 prior Python cases, 4 complete, 1 partial. New B37 algorithm localized **one previously missed Daimon error-payload loss source**, official post-fix file no longer triggered RSEM104. Other 3 complete cases missed. The AgentArea whole-file syntax fault was salvaged to **partial coverage**, not a clean full-parse success. Results SHA-256: `10209805ab9d6767e461e4e483f250ff901654d61b3bbffa0ac8af6982f7a4e3`. These are development observations, never out-of-sample B37 outcomes.
7. **First and original external holdout**: [B37 run 43512648259](https://github.com/risu-research/risu-probe/actions/runs/43512648259) succeeded. Frozen source evaluator, published 0.9.23 CLI and original B34 source algorithm ran on the same before/after original Git blob bytes. Output JSON SHA-256 `6617edbda41aa939cd95d1cfd6d61e801adbbe5f6eec963b5f463c77d03dee6c`.
8. **Result 0/7 complete Python cases**, 7 misses, 0 partial, 0 unverified, one Rust unsupported. All original source Git trees and blobs validated. No original external server/process execution in the sealed first look; no native upstream protocol witness in that evaluation. The seven officially repaired counterpart source files were compared as narrow controls, not an independently validated population FPR.
9. Any subsequent original upstream runtime investigation or source analysis of these now-exposed B37 files is **post-first-look development**, and MUST be reported separately. Never retrospectively count it toward the frozen 0/7.

## Per-case frozen results

| Case | Previously independently fixed upstream issue | Source | Verdict |
|---|---|---|---|
| B37A | [Atomic Agents #360](https://github.com/Eigenwise/atomic-agents/pull/360): structured-only output lost with empty content array | Python | MISSED |
| B37B | [KitAgent #14](https://github.com/zed123214/kitagent/pull/14): native MCP `isError` failed to propagate, content appeared as success | Python | MISSED |
| B37C | [Scholar MCP #583](https://github.com/pvliesdonk/scholar-mcp/pull/583): unnecessary JSON-in-string wrapping | Python | MISSED |
| B37D | [AI Scraping Defense #1883](https://github.com/rhamenator/ai-scraping-defense/pull/1883): SDK 2.3 structured result normalization | Python | MISSED |
| B37E | [Auto Browser #192](https://github.com/LvcidPsyche/auto-browser/pull/192): non-object structured content invalid to client | Python | MISSED |
| B37F | [VoucherVault #2](https://github.com/mmarquezs/vouchervault-mcp/pull/2): bare list return invalid FastMCP structured output | Python | MISSED |
| B37G | [MCP UniFi #227](https://github.com/pete-builds/mcp-unifi/pull/227): full data omitted from model-visible text for certain MCP clients | Python | MISSED |
| B37H | [Pctx #173](https://github.com/portofcontext/pctx/pull/173): application error message dropped | Rust | UNSUPPORTED_LANGUAGE |

## Why coverage failed

The inherited B34 detector tracks specific source forms: a variable bound from `await session.call_tool(...)`, typed `CallToolResult` attributes and direct content projection. Real clients often use **raw JSON mappings** (`response.get("content")`, `response.get("isError")`) or multi-step transformations. MCP servers can register tools via function wrappers rather than direct `@mcp.tool` decorators, and the success/error content contract is version- and host-dependent. Source-level AST matching without cross-function alias/dataflow analysis cannot safely infer those semantics. Those are *observed coverage limits*, not demonstrations that a novel B37 heuristic would have caught each defect.

B37 development repaired one earlier B36 defect and made partial parsing possible, but **new source-form coverage remained insufficient** on genuinely different external implementations. Adding one issue-specific regex per upstream fix would only overfit the now-exposed data.

## Strongest next research direction

1. **Runtime-first independent contract checks**: collect original MCP JSON-RPC `tools/call` result and the consumer-observed outcome with stable request ID, tool name, source/consumer version and a stated channel contract. Detect `isError=true` delivered as success, a structured-only result projected to empty, or loss of required text/image blocks. Mark intentional redaction, summarization and host visibility choices separately: copying all blocks blindly is not universally correct.
2. **Execute original upstream implementations safely where possible** rather than only authored simulations. Prefer a standalone original client that imports only Python stdlib, exact pre/post source Git blobs, and a bounded first-party stdio server with no network or credentials. Preserve raw native requests/responses. This is independent of original server runtime; label every component's provenance precisely.
3. **Normal/negative controls**: upstream original post-fix versions, and actual lossless consumers over the same native server/result; compare required channels and error status. Estimate FPR only after the normal behavior contract is independently defined for each control. Nonzero exceptions and unsupported paths must remain visible.
4. **Static analysis role**: use source analysis for *localization after a confirmed dynamic discrepancy*, with explicit `COMPLETE_AST` vs `PARTIAL_AST`. It may be effective as an opt-in assistant for diagnosis; empirical evidence currently does not justify a universal standalone static MCP data-loss validator.
5. **Next independent generalization**: any new algorithms incorporating B37 errors require a *new untouched B38 external holdout sealed before development*. Neither B37 originals nor the now inspected source can be reused to claim fresh sensitivity.

**Product decision:** keep B37 research branches separate. No merge of speculative RSEM104–RSEM106 rules to public `main`. Published B31–B33 functionality and three-OS CI should remain unchanged until value, false-alarm behavior, and external runtime provenance are independently demonstrated.

## Post-first-look original external client runtime reproduction (reported separately)

After the B37 source-only 0/7 result was sealed, a separate [B37 original KitAgent native stdio branch](https://github.com/risu-research/risu-probe/tree/qualification/p6b37-native-original-kitagent-20261113) **executed the exact independent KitAgent client source at its original before/fix Git commits** against the same credential-free controlled first-party MCP JSON-RPC stdio server on Ubuntu, Windows and macOS.

- [Run 43513309234](https://github.com/risu-research/risu-probe/actions/runs/43513309234) verified that original before-fix KitAgent treated two `isError=true` application failures as successful content/empty content; original after-fix KitAgent raised a proper MCP tool error. Normal success, two text blocks and JSON-RPC transport-error controls were preserved in both original versions, all 3 operating systems PASS.
- [Run 43513916615](https://github.com/risu-research/risu-probe/actions/runs/43513916615) added a **generic source-independent, read-only native protocol-to-consumer evidence checker**. Eleven positive/negative/mismatch/tampering unit tests plus original source before/after executed on all 3 operating systems PASS. Original wire message request ID, tool name, consumer classification, application error status and SHA-256 integrity are checked together. On each OS the checker counted before-fix **2 errors disguised as success** versus repaired **0**, with repaired **2 correctly propagated errors**, and 3 normal successful calls and 1 JSON-RPC error preserved in each version.
- [Detailed post-first-look original upstream runtime report](https://github.com/risu-research/risu-probe/blob/qualification/p6b37-native-original-kitagent-20261113/research/B37_ORIGINAL_KITAGENT_RUNTIME_RESULTS.md).

This is **original third-party client code executed** with an authored test server, rather than only RISU-authored simulations. It is neither an original third-party server execution nor an independently collected user observation. It does not retroactively improve the B37 static independent 0/7 result or imply population false-positive measurements. It motivates focusing future RISU Probe development on **protocol-to-consumer runtime evidence with explicit contracts** rather than ungrounded static source heuristics.
