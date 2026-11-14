# P6-B40 — Original external MCP consumer holdout: native evidence and eligibility audit

**Audit date:** 2026-11-14. **Decision: B40 selected-source execution audit complete at current evidence tier; three original external organizations executed and one remained build-blocked. Public product unchanged; independent in-band normal-client FPR remains UNMEASURED.**

This report includes original-source execution verified in this round and explicitly retains incomplete original build conditions. B40's preregistration preceded opening original candidate source. Claims below must not be construed as a generic MCP detector recall estimate, ecosystem error rate, or a new public product release.

## Frozen foundations

- **Public RISU Probe:** `main` git commit `8d622b792b4ae58b7157fd81ee5f95d6febcfd53` (`0.9.23.dev0`), unchanged.
- **B38 original generic detector:** commit `425d3d8272c4e725064010ed8fbf5b8217080cab`, source git blob `67bbb607d277dda3a1ead60a2ccd9ba807afd7ae`, unchanged.
- **Original preregistration:** [PREREGISTRATION.md](./PREREGISTRATION.md), prereg commit `afe997ea0363c32110091b54bce59eb0940d02b7`.
- **Source selection and hashes:** [SEALED_COHORT.json](./SEALED_COHORT.json), independent cohort seal commit `4ab60daab3e33e6a317b7a79d221800948ee0b40`.
- **Selected four external organizations:** `mastra-ai/mastra` P1; `langchain-ai/langchainjs` P2; `vercel/ai` N1; `openai/openai-agents-js` N2. These do not reuse the B34–B39 organizations. Selection was based on official merged PR metadata, not random sampling.
- All upstream applications and clients remain at exact author commit and original Git source blob. Test-only overlays and CI setup repairs are separately identified. No original app code was edited.

## Per-original result and proof strength

| Case | Author's intended contract | Confirmed evidence / limitations | Original execution tier |
|---|---|---|---|
| **P1 Mastra** | In-band `isError:true`, `structuredContent` kept in MCPClient return and structured reason in throw branch | PR [#27564](https://github.com/mastra-ai/mastra/pull/27564) and pre/post source blobs verified. Local owner-authored live-HTTP test was **not executed successfully**: test discovery project mismatch, then missing original `@mastra/core` exports, then original full-workspace build blocked by absent vendored/enterprise type exports and source type errors. [First test attempt](https://github.com/risu-research/risu-probe/actions/runs/43632003561); [project corrected](https://github.com/risu-research/risu-probe/actions/runs/43632251098); [core build attempt](https://github.com/risu-research/risu-probe/actions/runs/43632634864); [additional pinned vendored build attempt](https://github.com/risu-research/risu-probe/actions/runs/43633045357). No detected defect/normal score from this execution. | **INCOMPLETE** original source verified, behavior unverified. |
| **P2 LangChain.js** | In-band MCP tool error must become model-visible `ToolMessage(status='error')` for named tool call, without throwing the original tool error | Original author's [test RED before and GREEN after](https://github.com/risu-research/risu-probe/actions/runs/43632255010) (one selected test, 24 skipped), with test-file-only overlay. Original before produces `ToolException: ... denied`; official after returns failed ToolMessage. Separately, [live original external client adapter over real SDK native JSON-RPC InMemoryTransport](https://github.com/risu-research/risu-probe/actions/runs/43632840674) executed success + tool-error calls **on both original versions**: four native request/response pairs and actual downstream observations. Test-only controlled client/server adapter is RISU authored; upstream `loadMcpTools` and SDK sources remain original. | **ORIGINAL_SOURCE_FUNCTION_NATIVE_PEER** plus original author's separate regression; no whole agent application. |
| **N1 Vercel AI** | Claude Code stream bridge preserves non-text typed tool output; external MCP JSON object may be parsed, scalar text remains string; parallel result fallback retains content | [Exact owner test under original source](https://github.com/risu-research/risu-probe/actions/runs/43631951162): **3 passed, 13 deselected**. Tests describe mapping of external Claude Code stream into model-facing representation, **not** an original MCP `tools/call` JSON-RPC client. No actual native request/response or downstream status observed. | **ORIGINAL_UPSTREAM_PARSER_OR_TEST**, not eligible for B38 native-client FPR. |
| **N2 OpenAI Agents JS** | Original native borrowed MCP tool error policy respects custom/default/disabled/raise/cancel paths | PR [#2582](https://github.com/openai/openai-agents-js/pull/2582), exact source and owner native tests Git blobs verified. [Initial test discovery run](https://github.com/risu-research/risu-probe/actions/runs/43632056439) did not execute tests. [Second attempt](https://github.com/risu-research/risu-probe/actions/runs/43632174560) reached five original tests but all stopped on missing native Rust `codex.node` addon **before policy assertions**. [Original native build + author-owned integration run](https://github.com/risu-research/risu-probe/actions/runs/43632330698) subsequently **SUCCEEDED**: independently pinned upstream Rust `codex.node` built; the exact original native borrowed MCP client and Agent session executed locally, with custom, default, disabled, raise, and cancel failure-policy tests all passing (**5/5**). The original author test file was only relocated to an upstream Vitest-included path; the selected original implementation was unchanged. However, the controlled failure was **HTTP 500 transport response**, not a native `tools/call` JSON-RPC result with `isError:true`. | **ORIGINAL_NATIVE_END_TO_END_CLIENT** under local synthetic HTTP transport; **B38 in-band error FPR ineligible** because selected failure is transport-level rather than tool-result status. |

## Additional successful original native agent evidence: N2

[OpenAI Agents JS original author native session test, fully passed](https://github.com/risu-research/risu-probe/actions/runs/43632330698) after the runner built the repository's original pinned Rust `codex.node` bundle. The exact post-repair package source is commit `6e11314da6d4560f1143784fba4a58d218ff2080`. Five distinct author-selected policies all passed: **custom errorFunction**, **inherited default toolErrorFormatter**, **explicit null disabled fallback**, **raise**, and **cancel**. Tests used a real borrowed `MCPServerStreamableHttp`, independent loopback HTTP peer and original native Agent session, with synthetic local credentials only and no external model API. The test also verifies one tool-side effect, cache invalidation and correct fallback behavior without exposing the private synthetic server error message in model output.

**Scope:** In the selected original author test, the server emits HTTP **500** with a plain-text error for `tools/call`. That transport error is different from the in-band MCP `{"result":{"isError":true,"content":[...]}}` studied by frozen B38. The passing test establishes genuine original intentional error policy compliance and significantly improves executable normal-source evidence, but does **not** produce a valid B38 native `wire.response.result.isError` pair. Its status contract is therefore *not scored* as a native-tool normal, not “zero detector false positives.”

## Original LangChain live protocol versus frozen B38 detector (the central result)

The experimental additional adapter [langchain_native_client_witness.test.ts](./runners/langchain_native_client_witness.test.ts) executes the **unmodified original external client**, the official MCP SDK client/server and matching JSON-RPC request/response IDs. It is a test-only after-selection integration adapter, not an original author-created test.

- `before` ordinary `ok`: original client returns ToolMessage success; native `isError` absent, `outcome='success'`.
- `before` `fail`: official native `isError=true`; **original client throws ToolException**, so observed outcome is still a tool error.
- `after` ordinary `ok`: ToolMessage success, unchanged.
- `after` `fail`: official native `isError=true`; original client returns ToolMessage with **`status='error'`** and the correct call ID/name.

The B38 auditor, loaded from the exact frozen Git SHA, scored **four of four native status comparisons as `OBSERVED_CONTRACT_PRESERVED`**, zero native-status discrepancies. This is a **correct constrained result**: the before client did not misclassify the tool error as success, although its choice to throw prevented the desired ToolMessage. That difference needs a **new, separate declared return-format contract** if users actually need it, not a retroactively added B40 detector rule.

[Original P2 native wire + immutable checker workflow](https://github.com/risu-research/risu-probe/actions/runs/43632840674). Sanitary synthetic-only evidence SHA-256:
- Frozen detector outcome JSON `f863cfd41109fad5ed1f882ae70c59b8d1de1babea3fa2790afcab866e5a0178`
- Native original before JSON `ae05ad55f3bc24debdea44974107818363a4d2f751ebe0029d6b40bdb1de42cf`
- Native original after JSON `1febae080330a4437b8345293ff6c2e60d8524b13175e762434ffb8fe7592926`
- Workflow artifact ZIP SHA-256 `27ed4a77d10cde7cf724aa687a9514aedb274f30934c8e20be47cd383f70f271`.

The exact frozen checker did **not** show a new detected semantic loss here; its existing status invariant genuinely held. This prevents false credit for detecting every known upstream repair and narrows what it can promise.

## Preregistered independent normal FPR denominator (do not inflate)

**Planned:** two independently authored normal organizations N1 and N2. **Executed original normal organizations:** 2/2 at differing levels (N1 stream bridge unit tests; N2 original Rust-backed agent/client native HTTP). **Eligible in-band original native-tool normal organizations:** 0/2.

- N1 original code executed through maintainer tests, but is a stream adapter, not a native MCP client with in-scope observed `tools/call` outcome. **FPR-ineligible.**
- N2 original Rust-backed agent/client and five author-owned error-policy paths **executed successfully** using a controlled local HTTP service. All five passed. The original service deliberately returns HTTP 500 to a tool call; this is a **transport failure** without a paired native MCP result `isError:true` to be compared to an original downstream observation under B38. Therefore N2 is also **ineligible for the preregistered in-band normal-client FPR denominator**, despite being a full original native-client execution.
- Confirmed independently authored *external original client with in-scope native normal contract*: **0 organizations**. Observed false-alarm numerator **UNMEASURED**, denominator `m=0`; **no Wilson interval**, no estimated FPR.
- LangChain's matched normal `ok` results are from P2's positive organization, not separate independent normal holdouts and cannot be counted as one of N1/N2.

Successful zero-warning tests under the original author’s own presentation policy do **not** license a statement like “FPR 0/2.” Likewise P2's status-only agreement is not an estimate of the full generic detector sensitivity; its repair targets the external ToolMessage delivery contract.

## CI setup chronology, preserved

- P2 first failed due to missing generated `@langchain/core/errors`; then due to the original generator's `INIT_CWD` assumption; corrected by running the unchanged upstream build from its package directory. Final official author test and separate native evidence both passed.
- P1 original test was initially attempted as an `e2e` Vitest project, but the owner's test is a unit test; corrected project then lacked compiled `@mastra/core` packages. Original core source was compiled after vendored dependencies, but its shipped workspace has unresolved internal/enterprise TypeScript exports. These are **evaluation setup failures**; they neither establish nor disprove the real Mastra bug.
- N2 original owner's native test was initially outside that package's static Vitest include glob; test-only path relocation ran the original tests but failed because the verified native addon was absent. A full independently pinned upstream Rust source build then completed and the same original tests **passed 5/5**. The source was unchanged and no fake native addon was used.

All unsuccessful CI runs remain accessible and the original candidate source identities remain unchanged. A CI job marked failed for setup reasons must never be scored as `false_positive` or `defect_detected`.

## Decision and next independent evaluation

**Do not publish, merge or tune the public product on these outcomes.** The B38 checker was not modified for B40, and the original public `main` stays frozen. B40 has real external client-function native protocol evidence, a full original Rust-backed normal-client integration test across five declared policies, and a trustworthy example of a known repair **outside** the frozen detector's claim, but does **not** yet meet its planned independent normal-client FPR threshold.

**B41 recommended direction:** before opening implementation or results, preselect *genuinely runnable external MCP client/adapter source* from two or more new non-overlapping independent organizations with maintainer-documented **normal** outcome contracts that expose status and selected structured/text channels over real native `tools/call`. Require original executable consumer, matched raw JSON-RPC request/response, direct original client outcome, scope-specific normal policy and frozen checker blob. Also include new independently authored original known pre/post status-as-success positive repairs, not repairs that change only exception versus message-form policy. First gate should verify package/test runtime reachability and actual protocol suitability at metadata level without inspecting results, and retain every failed selected organization rather than replacing it post hoc. Evaluate B40-exposed cases only as development observations after this point.

**Key research conclusion:** A policy-preserving MCP diagnostic must distinguish *transport status*, *tool-result status*, *consumer presentation*, and *intentional output shaping*. A frozen checker should remain precise in its declared domain rather than accumulate superficially impressive detections from unrelated output contracts. This is a useful negative result with full provenance, not a release claim.
