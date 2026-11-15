# P6-B43 Preregistration — original MCP result → original agent outcome → terminal receipt

Date: 2026-11-14. **Registration before inspecting source implementation/test content**. Selection below relied on merged PR descriptions, repository Git trees, exact paths and immutable Git object hashes only. Original source files must stay byte-identical in all experiments. Public product main remains frozen.

## Goal and limits

For each single *original*, externally-authored MCP tool execution, link the native `tools/call` response `result.isError` to the original agent's **explicit** terminal classification. Strongest proof additionally requires an immutable persisted original per-call receipt, with an identity chain. Distinguish *tool-result status*, *consumer label* and *actual effect*: a reported success cannot prove a business side effect. Never infer success from no thrown exception or absent failure logs.

A B43 result is not B38's population sensitivity. Use the unchanged B38 auditor at original commit `425d3d8272c4e725064010ed8fbf5b8217080cab` Git blob `67bbb607d277dda3a1ead60a2ccd9ba807afd7ae` only when original explicit observed downstream outcome and comparable actual native wire exist. Separate new research-only `B43-LINK-1` for identity/outcome event matching; freeze before running selected external implementations.

## Frozen B43-LINK-1, three independent proof levels

**Level A / native status:** Actual native `tools/call` JSON-RPC message + its matching ID + `result.isError:boolean` captured from independently observed wire (not an evaluator-invented response object).

**Level B / original agent settlement:** The *same original invocation*, with a stable original `tool_call_id` (or documented deterministic binding to wire request), enters original consumer/agent dispatch and emits an explicit `success`/`error` terminal outcome. The producer and consumer identities must connect; joining by tool name alone under multiple concurrent calls is **not sufficient**. The original consumer may return a typed `isError` without a durable receipt; this meets Level B only when original agent emits a terminal output, not just an SDK return. If no ID binding, mark `LINK_INCOMPLETE`.

**Level C / durable completion:** The original implementation writes a persistent per-invocation terminal event (not evaluator-created), with call ID and final status; read original store after synchronous settled/closed run, verify exactly one matched start and exactly one matched terminal for settled calls. Evidence missing when pending/transport disconnected is `INCOMPLETE`, not automatically `OMITTED`. Independent observation of execution (not merely model-facing string) is required to claim real external effect.

Scoring per selected original organization and case: `PRESERVED` if native error and original application terminal error match, `ORIGINAL_FALSE_SUCCESS` if original app explicitly calls native error a success, `ORIGINAL_MISSING_TERMINAL` if original run is settled and originally persisted start has no originally persisted terminal, `LINK_INCOMPLETE` when native/request or original call ID/receipt cannot be proven, `NOT_EXECUTED` for blockers. A PR with a bug explicitly advertised in selection is an **owner-confirmed historical positive**, not a newly discovered blind holdout. For pre/post claim, run identical original code version pre/post with unchanged test-only peers.

## Preselected, source-disjoint original sample (no post-result replacement)

### P1 — primary original external agent (TypeScript)

`Nano-Collective/nanocoder`, merged original [PR #1926](https://github.com/Nano-Collective/nanocoder/pull/1926), original before commit `39d8fa2a8cf0a710d192720daf966fd68b6eaf26`, original official after `2c87d801ef4779f7e4344c287f3feb9f4b0be054`. Before original implementation `source/mcp/mcp-client.ts` blob `eb153d44c9d0cf9c2dafefe36e046c1d17812454`, official after blob `1e3a3fd5ba1cbab962f69883789dc725c1a26a0a`. Official tests before `source/mcp/mcp-client.spec.ts` blob `75a861ee86f7125bd25c6571e93ddfd380163294`, after `85e7b05f1d7542b5988a68aaccf911caa862068a`; ACP original tests before blob `98daa2243fd7a4669363fc45d0f0a9e59fc1d4ce`, after `1ab85a485a41aa75a845c4797715840099690e7b`. PR reports native MCP `isError:true` pre-fix falsely marked successful in ACP and JSON CLI, post-fix correct error, normal echo unaffected. Aim: original exact native MCP source and original agent/ACP endpoint with test-only local MCP server and fake model. If original API does not preserve wire request ID into the original agent's tool call ID, do not overclaim strong same-ID link; report weaker explicit source-path/transitive test with identity limitation.

### P2 — independently authored second original agent + persistence (Rust)

`EratoLab/erato`, merged original [PR #1486](https://github.com/EratoLab/erato/pull/1486), original pre `5c3eac23d6efdff9f275ad45da7cf63e24f77e3d`, post `f9e5f47bf948e16f441b09b40bcfb4565ce0433c`. Original Rust agent dispatch `backend/erato/src/server/api/v1beta/message_streaming.rs` blob pre `9895f44f18652c2d67aaf1586bb506fe7826a66d`, post `33d8b04c628f5f465b563c77c4f4296fbc20dd45`. Original integration test `backend/erato/tests/integration_tests/api/messages/mcp_file_outputs.rs` blob pre `5742b686240d6d01a7f533608009a7055c3813d1`, post `3943008917fcd7e026267c77ef69bec2b4429c30`. PR says status false success both main and approval paths, persisted + streamed status as success, with original tests. Target actual original integration test with local peer and DB. If provisioning external production components prevents execution, record all blockers; source-only evidence cannot count as original runtime result.

### N1 — independent external original agent lifecycle control (TS)

`Parcha-ai/agentrun`, original PR [#2767](https://github.com/Parcha-ai/agentrun/pull/2767), original before `a3a0317c38bf3186feb80c5df37bd2c6a9f17733`, after `90385367d64a581727f2f73bd29a7e69b18c3b90`. Original runner `packages/serve/src/runner/adapter-loop.ts` blob pre `012e50405411c62d0e385900b7691d8940e045db`, after `1975bd36291b8341204fa7d08d14493cf60f1af0`. Original conformance `packages/serve/src/runner/conformance/harness.ts` pre `56ce99b9f0dcccdca18d6fcd2af7b27be58750d1` after `46f2ddc8928dfc96b68d282f2a2cecee35cc25fe`. Original tests `packages/serve/test/conformance-facts.test.mjs` blob post `9424c2805c8de216c5c04c3cd6d359a6d4837942`. PR covers nested result events and cancelled approval waits; **no prior claim that original wire isError is observable**, so N1 is deliberately a lifecycle comparative control. If only nested records without tool status or native MCP, label `NOT_ELIGIBLE_NATIVE`, never inflate full end-to-end denominator.

### N2 — external MCP gateway activity classification (Go, not agent)

`smart-mcp-proxy/mcpproxy-go`, original merged [PR #1502](https://github.com/smart-mcp-proxy/mcpproxy-go/pull/1502), official pre `39a49907b24118bf62b0e04c343a6fc70e2e45fa`, post `fa4a8a4cc09da1927eff7829d8919e437e129b9d`. Original new classification `internal/callerr/classify.go` blob post `f7e579da004d9d7491208fe817349c8cd6822ad1` and first-party `internal/callerr/classify_test.go` blob `e2a2eba551776dd6fddeab1b79ba6f07d1d49923`. This is an independent classifier of `tool_error`, `cancelled`, timeout, JSON-RPC, http; its per-call activity is **not automatically an agent completion receipt**. Execute independent original owner unit tests and determine eligibility of terminal ID; do not count in full agent denominator without native matched call, original agent and durable receipt.

## Frozen challenge matrix

Run, where original source supports it, with one local official native server and a fake model (no external secrets or writes):

- **A normal:** `isError:false` text, one settled call, explicit success, exactly one original receipt where implemented;
- **B business error:** `isError:true` text with HTTP/protocol success, original agent must classify error, exactly one error receipt;
- **C transport exception:** no native successful `result`; require error/unknown terminal only if original settled, never call it equivalent to in-band `isError:true`;
- **D cancellation while pending:** incomplete while pending; if original terminal cancellation receipt emitted after join, classify cancelled and not failed/succeeded by assumption;
- **E retry:** individual attempt IDs separately; if same logical call retried, distinguish attempt ID from effect id, and no double-counted completion or invented effect success;
- **F duplicate/collision:** two identical tool names/inputs but different original IDs must remain two distinct calls; duplicate terminal for same original ID should be flagged;
- **G missing receipt:** only if original durable start and independently proven settled with original store snapshotted after join; not a test fixture simply deleting an event from evaluator's own memory.

No pre-fix source rewrites, no patching original app to make tests pass. A first-party author's new regression may be overlaid as a *test-only* file onto original pre version for red/green, but mark `AUTHOR_TEST_OVERLAY`. Same external author remains one organization no matter how many cases or modes. Report all failures, incomplete and excluded cases with original run and hashed logs.

**Gate before any public promotion:** no changes to `main`/PyPI. Only a source-independent small algorithm proven on a *new*, source-disjoint B44 holdout may be considered for release. P1/P2 exposure precludes blind B44 testing.
