# P6-B44 prospective first-look preregistration: native → agent → durable receipt → effect

Date 2026-11-14 (America/New_York). This preregistration is committed **before opening any of the four selected upstream implementations or test file contents**. Candidate selection was based exclusively on public README descriptions, official PR summaries, file path names and immutable Git blob IDs. The experiment will not silently substitute post-exposure candidates or change scoring requirements. Public RISU Probe product `main` stays `8d622b792b4ae58b7157fd81ee5f95d6febcfd53`.

## Aim and original-source boundaries

Can an independent, author-written MCP/agent implementation itself emit evidence proving, for **the same original call**, the complete chain:

`original serialized MCP tools/call request (connection, JSON-RPC request ID, params)`
→ `original model/agent tool call ID`
→ `original durable start receipt`
→ `original durable terminal receipt`
→ `independently queried actual effect state`?

A controlled local peer and a scripted model may replace networked production services, but the MCP consumer/server, agent dispatcher, durable storage and effect execution must all be ORIGINAL unchanged implementation code. Merely running a repo's `test` or building an evaluator-owned event trace DOES NOT prove full chain. No writes outside disposable temporary local directories and test databases. Never reach a real production API.

**Originality exclusion:** no B34–B43 evaluated organization. Explicit prior samples include AgentScope, Hermes Agent, Python MCP SDK, confident-ai/deepeval, Tencent/AI-Infra-Guard, Significant-Gravitas/AutoGPT, PostHog, Nano Collective, Microsoft Playwright, langfuse, teamcity-mcp, affinidi, AgentArea, Daimon, Microsoft Agent Framework, Stitch Manager, OPNsense, data-fair/agents, arcships, tarsy, atomic-agents, kitagent, scholar-mcp, anti-scraping-defense, auto-browser, vouchervault, mcp-unifi, pctx, waterworks, Deepseek harness, claude-mem, onyx, mark3labs, Langboard, OpenClaw, Mastra, LangChain, Vercel AI SDK, OpenAI Agents, Go MCP SDK, Prefect FastMCP, Personal-Assistant, leather, Metoro, Agentmetry, Erato, AgentRun, mcpproxy-go and other earlier owners. Four B44 repo owners below are new.

## Frozen four B44 original-source candidates

P1 **XAGI-Lab/melra** at `ab59ffa134decd9613a378c7bd8a0e8d495c7e89`, based on public claims of MCP, original persistent hash-linked receipts and independent effect validation. Pinned Git blobs: original MCP server `packages/server/src/mcp-server.ts` `17e3d6e7f0b63eb8395c4b5a9553dce3505d1a21`, verification gate `packages/runtime-core/src/verification-gate.ts` `67854f90eda0319580e08ced57e0426afe95e18f`, original receipt schema `packages/receipt-schema/src/index.ts` `72c1c5638fd22f6607c7b68988d0b6a44a46cd8d`, original external effect test `packages/server/test/http-effect.test.ts` `f9ca067f727469dc4c00893b10e601249a5ce3bc`, original independent verification test `packages/server/test/independent-verification.test.ts` `4b4e71c93fe0eb73b62e7295bfa998bc8be474e1`, original stored receipt test `packages/storage-sqlite/src/workflow-store.test.ts` `710d07293423066a80f34b4fc4904461d165252b`. **No assumption that an MCP host's external agent ID reaches MELRA.**

P2 **heggria/taskflow** at `f4e29406b78a1e16c9b69a50f62096fb6e4ae74c`, based on published native MCP, effect claim/commit and persistent journal features. Original source Git blobs: `packages/taskflow-mcp-core/src/mcp/jsonrpc.ts` `c79c7c67845d4a1accd0c7229ef6dbd6fae8f9c5`, MCP server `packages/taskflow-mcp-core/src/mcp/server.ts` `af8c198f654582c1f1dc4835e813ef2fd4c8833d`, original journal `packages/taskflow-control/src/store/journal.ts` `be847b22f41d37da15379ebdb692af9405589bf6`, original effects `packages/taskflow-core/src/effects/runtime-apply.ts` `2e3b4dfd80ab848acd377cf1f45b767b127e7186`, original stored terminal test `packages/taskflow-core/test/runtime-terminal-persist.test.ts` `db4bdae88ba0ccd18df448fc11ec6273ad1f7f4f`, original trusted effects test `packages/taskflow-core/test/effects-trusted.test.ts` `6b6bfc397bd6e2c6615c777fa73012362b2d8220`, original MCP e2e `packages/codex-taskflow/test/e2e-mcp-comprehensive.mts` `f99af34ff162d84a92db824637d5b4f3931cd432`. No inference that an internal phase ID equals the caller's JSON-RPC ID.

P3 **edgar4/yada** at `4066bb21fd3f1dd358d1d82166755671cd8e2b50`, based on independent upstream owner PR #13's promise of reviewed MCP writes with durable approvals/reconnect/receipts, owner-reported tests. Git blobs: `src/connectors/mcp/rpc.ts` `37944406413d5fd53c9015d65ac4f7181b2dcab4`, `src/connectors/mcp/write.ts` `6d64fbe2502459775991a0b912825f42f75c3b10`, `src/core/agent-tool.ts` `bea03ef85e9bb0f6f94d79c2e6f40643d19cd2a2`, `tests/mcp-write-durable.test.ts` `f4573c47edae2ce3bbed9490c547914781c9b7af`, `tests/mcp-write-http.test.ts` `297461b71a7556e8ccd9be1d0a650b1234552127`, `tests/mcp-write-protocol.test.ts` `78b182adc21a79689ed01420e5aad0a1e2e07432`, `tests/helpers/mcp-write-server.ts` `20a113a7a96fbff87a0239e1597b671454e5fb31`. Strictly distinguish original authorization/receipt from the actual external state effect.

P4 **haibaoseal/sentinel-mcp** at `1692d38a20221da7d62fb6268a3a0097ebb1f523`, based on independently authored Python agent loop + MCP server + original hash-chain audit, original real tools. Pinned blobs: `apps/api/app/agent/loop.py` `83c30f614f6b0c6c8909643faed7f2c50e56dcf3`, `apps/api/app/mcp/client.py` `0d9c011a8d8ca0ae46c8cc56c9789620a7406f37`, `apps/api/app/mcp/server.py` `fdf22c15e3e80f472dcc31967c98f90af15077d3`, `apps/api/app/audit/logger.py` `55664a6a1c4861180ac69ceb159a26a35342c55c`, `apps/api/app/tests/test_agent_loop.py` `112883b9ee0556ab90a47d854f4df8f52155ff14`, `apps/api/app/tests/test_audit_chain.py` `91b7c2446fcada578788e33c28d8a572bbcee332`, `apps/api/app/tests/test_mcp_gateway.py` `c9ffcfcbc5763b824fad2837cf8e9bf571db3825`. No assumption that audit chain implies immutable or full native source binding.

Selection is *purposive*, not representative. **No swapping** if a selected original source cannot execute. A repository that only produces server-side receipts, without native client/agent linking, is counted INCOMPLETE for full-chain criteria, even if individual tests pass.

## Frozen B44 E2E-1 eligibility and decision rubric

All five original-evidence edges must be observed in one original execution with one isolated run ID and two independent observation surfaces, not stitched from unrelated examples or different upstream runs. Original source is immutable at pinned SHA, verified with `git rev-parse HEAD:<path>` before evaluator overlays.

**W — Original serialized native wire**: capture the actual outgoing JSON-RPC 2.0 `tools/call` request `id` and response `id` from a real original sender/receiver at stdio bytes or HTTP body (state whether byte tap or SDK parsed transport). `result.isError` boolean must be observed; `error` JSON-RPC is a distinct kind. Connection/session ID needed because different streams can reuse request IDs.

**A — Original model→tool call ID**: capture actual original agent model-invocation ID, not evaluator-invented. The original source must retain durable or native fields that identify exactly which original model tool call created which native MCP call. A test-only mapping keyed by order, unique tool name, arguments, or an evaluator injected ID is **not** original proof. Without original mapping, mark `LINK_INCOMPLETE`.

**S — Original durable start**: original app writes a per-invocation start record to original persistent storage (SQLite/append-only FS/transactional DB) with exact agent tool-call ID and original native connection/request ID or durable, originally minted bijective join key recorded at BOTH sides; read after original run from a fresh process. Hash-linked receipts prove only internal consistency if no external anchor.

**T — Original durable terminal**: original app writes exactly one matching terminal result linked to its original start, plus explicit `success,error,cancelled,unknown` status. Verify after join and fresh-process reopen. Pending/unjoined/no read is `INCOMPLETE`, *not omission*. Duplicate terminal or wrong parent is distinct discrepancy **only** when independent original log evidence proves it.

**E — Independently checked real effect**: a declared mutation of a disposable filesystem/SQLite/HTTP fake service executed by the original application's chosen tool implementation. Inspect final file bytes, SQLite row or server-side state using an independent reader **not just the returned tool text or original self-reported receipt**; record before and after digests and side effect attempt count. A response that reports success but had no committed effect is `EFFECT_UNPROVEN`, not success. For errors/refusal, prove the absence of unauthorized mutation. A post-execution final state cannot prove one *specific* attempt caused the effect if concurrent writes are allowed; use unique test resources, exact IDs and bounded attempts.

- `FULL_CHAIN_VERIFIED`: all W+A+S+T+E original and separately observed for one invocation with original stable join keys; effects independently checked. All five flags true and source unchanged; no skipped step. Report normal and business-error separately.
- `FULL_CHAIN_DISCREPANCY`: all identity/provenance edges original, but original persisted terminal status contradicts observed native result/effect, or duplicate/missing terminal in independently confirmed settled run.
- `LINK_INCOMPLETE`: original native wire and agent outcome execute, but original ID binding to agent/durable record missing.
- `EFFECT_UNPROVEN`: identity and durable receipt present but only self-report or no independent effect state.
- `PARTIAL_ORIGINAL_RUNTIME`: real original unit/functional test verifies some edges, but no same execution full chain.
- `SOURCE_ONLY`: original code read but not runtime verified.
- `NOT_EXECUTED`: setup, original environment or dependencies block running tests; never a pass or false-positive count.
- `NOT_ELIGIBLE_AGENT`: gateway/server has no original agent/model-call ID by design.
- `UNKNOWN_TIMEOUT`: native response missing after dispatch; do not replay a mutation unless original recovery proves first attempt produced no effect.

Original source-disjoint **organization** is the denominator, not tool count, retry count or package count. Report all 4. Report **0/n** only if n truly eligible; otherwise FPR or full-chain capability UNMEASURED. No population inference.

## Frozen challenge scenarios (only where original implementation supports executable observables)

1. **Normal mutation:** one native `isError:false` call, unique disposable output, real independent effect digest, exactly one persisted original start/end and actual model call ID join.
2. **In-band failure or denial:** `isError:true` (not HTTP/JSON-RPC failure), original terminal error, no unwanted effect.
3. **Same-name collision:** two identical tool names/args on different native and model call IDs, concurrency where feasible, originally persisted bijective join required.
4. **Lost response after effect:** original dispatch effect occurs but return lost, original status unknown/recovery-required until independent original reconciliation; no blind duplicate mutation.
5. **Safe retry:** new attempt ID and stable operation identity, separately original recorded, side effect count exactly once.
6. **Cancelled pending:** incomplete before settle; only original end after join can support cancellation.
7. **Tamper:** a test-only copy of original receipts altered after original execution; verifier must distinguish journal digest/anchor mismatch from effect state. Does not prove malicious tamper resistance.

Never create fake production original events in evaluator and treat as original. If the upstream only has HTTP MCP server and no agent, evaluate native→original server→receipt→effect but report `NOT_ELIGIBLE_AGENT`. A response lost test is not proof of side effects unless real independent state read.

## Scoring and tool constraints

Frozen B43 post-exposure candidate code `benchmarks/p6b43/development/verified_receipt_bridge.py` at original research branch commit `9dd37df63614416979052b30f3def8bac6f573e6`, original Git blob `3c20076a39ebf3529f600b59c3b38930d3d17d41`. It is a **research development algorithm**, NOT public main and NOT B43 blind sensitivity. For B44 evaluate frozen file without editing. Its required `original_persistent_journal` schema is strict; if a source has equivalent evidence but differently shaped, write a lossless extractor that copies original source fields without creating missing IDs or records, publish extractor provenance and keep any source-dependent adapter scored separately. No post-result rule fixes counted as blind.

Instrument test-only transparent byte relays. Never modify original author implementation logic, imported original libraries, persistent journal semantics or model-call attribution. Source test overlays may use original first-party tests and real external local test peer but must be explicitly labeled. Every run logs original Git SHAs + blobs, used original function names, native wire (or why unavailable), original journal raw record references and hashes, independent postrun output digests, actual Actions run ID and failed environment attempts.

**Stopping decision:** if no selected original app emits an original native-to-model call ID bond or independently verifiable effect despite honest execution, freeze this as a genuine capability gap: `FULL_CHAIN_UNMEASURED`, with source-level confirmed missing edges and runnable real statuses. Reserve any new bridge design for B45 source-disjoint validation. No user action needed and do not alter published main.
