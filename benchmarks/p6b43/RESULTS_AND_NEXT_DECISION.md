# P6-B43 final audit — How far does an MCP tool failure reach?

**2026-11-14 (U.S. Eastern date).** Source-disjoint external implementations. No changes to public RISU Probe `main`, CLI, version, or frozen B38.

## Summary of independently supported results

A real original Nano-Collective Nanocoder MCP client and its original ACP agent were executed as a **single linked functional path** using the official MCP SDK's actual serialized stdio JSON-RPC transport. Before the owner's official patch, the MCP server's `tools/call` returned `result.isError:true`, but the original agent emitted a final `completed` status. After the patch, the exact same *class* of native error produced an original ACP `failed` final status. In both versions the normal `isError:false` call emitted `completed`; the original model-facing tool text was unchanged; exactly one ACP final status per controlled model tool call was observed. The original code executed; a **scripted model and a controlled native MCP peer** replaced production services.

The unmodified B38 detector identified the known pre-fix `APPLICATION_ERROR_AS_SUCCESS` in the controlled one-to-one functional test and preserved the three remaining normal/fixed observations. B43's stronger preregistered cross-layer contract **correctly declines to score any of these four as fully linked**: original Nanocoder does not persist a native JSON-RPC request ID ↔ model ACP tool-call ID mapping, nor a durable original per-call terminal receipt. There is no original original-system ID chain from a native request to an original persistent completion record, no business-effect proof, and **zero eligible original strong-link cases**, **not** evidence of zero bugs.

Two further independent organizations' genuine owner-written tests were run: AgentRun's original stop/cancellation/reclaim/conformance tests passed **17/17**; smart-mcp-proxy's original call-error taxonomy including `isError:true`, JSON-RPC, network and cancellation passed its original test suite (11 top-level test functions, including table subtests). Those are **scope controls**, not evidence that the same external app provided a complete native-to-agent-to-persisted receipt chain. The fourth selected original owner Erato provides a potentially stronger native HTTP → Rust original agent → actual PostgreSQL row → SSE terminal path, but its Rust integration execution is **not yet reproducibly confirmed** at the first B43 audit snapshot due a test stack overflow; an original-code-preserving larger-stack recovery is separately logged.

**Research outcome:** meaningful original native-to-agent conformance and a real historical false-success counterexample; fully verified original persisted-ID chain **still UNMEASURED**. No general false-positive, sensitivity, production deployment or actual effect claims.

## 1. Registration frozen before selected implementation contents opened

[Original B43 preregistration](./PREREGISTRATION.md) was committed at `520961aa3dcc637fe90d0fa6b19a01cba6369341` before code inspection. [Sealed source-disjoint cohort](./SEALED_COHORT.json) was committed at `cb8715d60e29716ef2ce96f5387d12724a6ff71a` with selected original Git SHAs and original implementation Git blobs for four distinct developers.

Public RISU Probe main pinned at `8d622b792b4ae58b7157fd81ee5f95d6febcfd53` (version `0.9.23.dev0`). Source-independent B38 file `research/b38_native_contract_auditor.py` pinned at `425d3d8272c4e725064010ed8fbf5b8217080cab`, Git blob `67bbb607d277dda3a1ead60a2ccd9ba807afd7ae`. Neither was edited. Evaluator test overlays never changed selected upstream Git source implementations; all run initial source identity checks, and known harness setup failures remain visible.

### Preregistered B43-LINK-1 tiers

| Proof property | Minimum original evidence | B43 observation |
|---|---|---|
| **A — native sender/receiver** | Actual `tools/call` JSON-RPC request and matching reply ID, boolean `result.isError` from original SDK/transport | **Nano demonstrated** |
| **B — agent result and identity binding** | The same original invocation reaches original agent's explicit final status **with an original native request ID → agent tool-call ID linkage** | **Nano original functional path demonstrated but exact cross-ID binding absent** |
| **C — durable end receipt** | Original durable store's separate per-call start/end events, matching original call ID, joined settled run and post-join read | **Nano did not expose**, Erato original full test pending independent execution |

The absence of a terminal receipt does not establish omission unless original start is recorded, run settled, and original post-join persistent read confirms no result. A receipt for completion does not prove an external action was effective or authorized. With concurrent same-name calls or retries, tool name/order is not a valid substitute for stable identities.

## 2. P1 Nanocoder: original native MCP → original ACP source pre/post

Original upstream [PR #1926](https://github.com/Nano-Collective/nanocoder/pull/1926), pre `39d8fa2a8cf0a710d192720daf966fd68b6eaf26`, official post `2c87d801ef4779f7e4344c287f3feb9f4b0be054`. Original implementation `source/mcp/mcp-client.ts` Git blobs pre `eb153d44c9d0cf9c2dafefe36e046c1d17812454` and post `1e3a3fd5ba1cbab962f69883789dc725c1a26a0a`.

### Independent original author regression (source test overlay only)

[Source-first-party regression run #43663478236](https://github.com/risu-research/risu-probe/actions/runs/43663478236) **SUCCESS** as a red/green experiment:

- The owner-authored latest `MCPClient.callTool` `isError` regression test **failed before, passed after**.
- The original `runAcpConversation` test with a fake SDK client, 2 distinct named tool calls and explicit ACP IDs **failed before, passed after**.
- Failures before were the *expected original* wrong success, not test setup errors. One of each selected test; source patch was never copied onto the original pre implementation.
- An earlier experiment [run #43663411643](https://github.com/risu-research/risu-probe/actions/runs/43663411643) failed at **evaluation-only setup-node caching** before pnpm existed; kept as unsuccessful setup evidence and repaired in workflow.

### Higher-tier actual native JSON-RPC to actual original agent

[Original source real-native integration run #43663669412](https://github.com/risu-research/risu-probe/actions/runs/43663669412) **both original pre and post passed the preregistered evaluator's expected output**.

The evaluator-owned synthetic **official MCP server** was a real `@modelcontextprotocol/sdk` process over original `StdioClientTransport`. Original native `tools/call` requests and matching JSON-RPC responses were separately captured at **SDK transport logical frame hooks** before the original Nanocoder client returned. Original Nanocoder `MCPClient` (not a port or reimplementation) supplied actual handlers to the **original** `runAcpConversation` and **original** `AcpSession`. Test-only model issued exactly two different named calls `b43_denied` and `b43_success` with ACP model tool IDs. The original ACP session emitted the final `tool_call_update` statuses; original model history preserved tool text.

| Controlled native tool | Native original isError | Original pre ACP final | Original official post ACP final |
|---|---:|---|---|
| `b43_denied` | true | **completed** (original false success) | **failed** (owner repair) |
| `b43_success` | false | completed | completed |

Each of four phase×tool comparisons emitted **one** original ACP terminal event and one matching native JSON-RPC reply in that original session. Tool error response content `B43 native denied: no external effect` remained identical in the original agent's model-visible message. Native original JSON request IDs and ACP model tool IDs are both captured as **separate identity domains**, not fabricated joins.

Pre-fix original witness JSON SHA-256 `911226bc57174fc2d8f91888309554acb4c0f71f37ab9d64832aa81f16fbe453`; post-fix `3f10dfa534825d9633c65cfe13afa5e08ba7ed35cb138c9b1547e0622a5bbd37`. **Proof level:** original native SDK transport → original MCP client → original ACP agent **functional result** with scripted model, **not original durable-ID linkage**, not raw independent stdio byte tap, not external production operation.

### Frozen original B38 vs strict B43

[Independent source-independent evaluation run #43663955500](https://github.com/risu-research/risu-probe/actions/runs/43663955500) **SUCCESS**, seven predeclared positive/negative B43-LINK-1 self-controls. Evaluator used unmodified original B38 from original immutable Git SHA, with `status:true` and content channels explicitly `none`. A B38 record's `observed` contains the **original ACP explicit terminal status** and matching tool name only; it **omits native `request_id` because original ACP output never exposed it**. Matching the two is justified *for these evaluator-controlled single-distinct-tool cases*, not independently by original native-to-ACP ID linkage.

| Original version | Tool | Frozen B38 | Original B43-LINK-1 |
|---|---|---|---|
| Before | Native in-band error | `DISCREPANCY: APPLICATION_ERROR_AS_SUCCESS` | `LINK_INCOMPLETE` |
| Before | Native success | `OBSERVED_CONTRACT_PRESERVED` | `LINK_INCOMPLETE` |
| After | Native in-band error | `OBSERVED_CONTRACT_PRESERVED` | `LINK_INCOMPLETE` |
| After | Native success | `OBSERVED_CONTRACT_PRESERVED` | `LINK_INCOMPLETE` |

Scorer output SHA-256 `2d216f26d3d005df4ad418039f7971566337c630f69fc8ecd4a7f67ee3c669e9`. **0/4 strong-link eligible**, hence original-source *strong cross-ID and persisted receipt accuracy UNMEASURED*. The known published owner fix does not become a newly discovered detector hit or a general sensitivity estimate.

## 3. P2 Erato Rust app, original PostgreSQL persistent status and SSE (separate run)

Original [PR #1486](https://github.com/EratoLab/erato/pull/1486), before `5c3eac23d6efdff9f275ad45da7cf63e24f77e3d`, official after `f9e5f47bf948e16f441b09b40bcfb4565ce0433c`.

The official upstream patch at source `backend/erato/src/server/api/v1beta/message_streaming.rs` changes **both** main streaming tool-call path and approval continuation to consider original RMCP `tool_call_result.is_error == Some(true)`, setting original **stored message tool-use status, emitted terminal update and background status** to error rather than success while preserving the tool error payload to model. Original before implementation blob `9895f44f18652c2d67aaf1586bb506fe7826a66d`; after `33d8b04c628f5f465b563c77c4f4296fbc20dd45`.

Official author integration `backend/erato/tests/integration_tests/api/messages/mcp_file_outputs.rs` (post blob `3943008917fcd7e026267c77ef69bec2b4429c30`) contains `approved_mcp_error` and `uninterrupted_mcp_error`. Original test creates its own local Axum HTTP MCP peer replying with real `result.isError`, an original mocked-model server, a PostgreSQL `Messages` store, tests original stream and stored message `tool_use.status`, verifies SSE `tool_call_update.status`, error content still reaches model, and original local fixture file writes are absent for error. **This would be a stronger original persisted-status result if a test successfully completes.**

[Initial actual original Rust/postgres integration run #43663839936](https://github.com/risu-research/risu-probe/actions/runs/43663839936) did compile the original pre-fix Rust application **successfully** after 9+ minutes of original dependency build, then the first `approved_mcp_error` original test **aborted with a Rust test-thread stack overflow SIGABRT** before comparing stored status. Therefore that run is **INCOMPLETE due test runtime infrastructure**, not the expected pre-fix misclassification. Original post-fix job was still compiling at snapshot. Its outcome cannot be assumed.

A [source-unmodified 128 MiB stack recovery](https://github.com/risu-research/risu-probe/actions/workflows/p6b43-erato-stack-recovery.yml) was launched as a separate test environment experiment and retains exact original source and author test blob identities, original PostgreSQL 16 service, and `RUST_MIN_STACK=134217728`. If it fails or remains pending, report honestly; do not merge Erato into verified full-chain denominator. **Even if the official Erato DB test passes, its status is a persisted tool result; original native JSON-RPC ID ↔ stored tool-use ID provenance may still need separate evidence** for the strongest B43-LINK-1 guarantee.

## 4. N1 and N2 independent controls, measured at their actual layer

### N1 — original AgentRun cancels/retries and agent ownership

Original owner [PR #2767](https://github.com/Parcha-ai/agentrun/pull/2767), original post `90385367d64a581727f2f73bd29a7e69b18c3b90`. [Original test run #43664186939](https://github.com/risu-research/risu-probe/actions/runs/43664186939) **passed 17/17 original tests** across original `adapter-pi-native`, `adapter-pi-cap-stop`, and original conformance facts. Includes original agent's task memo reuse under re-claim without rerunning effects, cancellation bounding and explicit harness support. Original `npm ci` and original full build executed; no source patch. Initial [run #43664080176](https://github.com/risu-research/risu-probe/actions/runs/43664080176) was blocked because GitHub's Node `24.22.2` was below original project's `>=24.22.3` required version. Source unchanged; evaluator switched to Node 26. Successful log SHA-256 `867066f20186c5c7c7c3a2938e0d5df1c24ec158289bcb95496569a1e234a0fb`.

**Scope:** original external agent lifecycle tests, *not* original native MCP `isError`→persistent completion ID chain. Thus **not counted** in strong end-to-end status denominator.

### N2 — original MCP gateway error-type differentiation

Original owner [PR #1502](https://github.com/smart-mcp-proxy/mcpproxy-go/pull/1502), post `fa4a8a4cc09da1927eff7829d8919e437e129b9d`. [Original author run #43664023070](https://github.com/risu-research/risu-probe/actions/runs/43664023070) original `go test ./internal/callerr -count=1 -v` **passed**, including 11 top-level original functions and 58 Go test subtest passes; e.g. `TestClassifyIsErrorWinsOverFacts`, caller cancellation, network/http and JSON-RPC errors.

**Scope:** original independently authored gateway error-class taxonomy. No original agent or durable per-call terminal proof; **not counted** in full chain.

## 5. Separate post-exposure future bridge design, not B43 held-out accuracy

After inspecting Nano's missing native→agent ID and original persistent receipt, the new research-only `benchmarks/p6b43/development/verified_receipt_bridge.py` was created. [Development-only run #43664319307](https://github.com/risu-research/risu-probe/actions/runs/43664319307) passed **12 synthetic** normal/failure/duplicate/ID-mismatch/journal-tamper/cancellation/pending controls. It requires **original** durable journal event digest, native connection ID, wire request ID, original agent tool-call ID, original parented terminal event, plus settled/joined provenance. It neither reads target code nor changes B38.

Feeding actual original Nano after evidence **correctly yields `INCOMPLETE: CONNECTION_ID_NOT_RECOVERABLE`**. No original journal or connection binding was invented. **All twelve cases are synthetic test design after exposure, NOT a B43 independent original-client sample or production functionality.** The exact code is a prospective B44 independent evaluation candidate only.

### Two same-name calls are mathematically unidentifiable without an original join key

A separate **post-exposure synthetic** [counterexample run #43665279219](https://github.com/risu-research/risu-probe/actions/runs/43665279219) systematically enumerated **two valid matchings** of the same observable pair of concurrent `tools/call` requests (same tool name and arguments, native statuses one `isError:true`, one false) to two original-agent-style terminal records (one failed, one completed) with no source-provided native-request-to-agent-ID link. One matching is fully preserved; the other entails both an error-as-success and success-as-error. Both agree with the same observed unlabeled IDs. Thus the correct source-independent verdict is **`INCOMPLETE_CROSS_BOUNDARY_IDENTITY`**. Verified generated JSON SHA-256 `27d20fdc36559d42b28111a87ad518e7cd67463c41ea85d8ffc787a7c9dcb623`. This is a constructed **identifiability demonstration**, not a real original-code fault or extra holdout sample.

## 6. Research verdict, denominators, and next choice

| Question | Actual executed evidence | Valid conclusion |
|---|---|---|
| Does the real original native MCP tool error reach a real original ACP agent status? | **One external organization, two source versions, four native calls and four original ACP finals** | **Yes**, before error misclassified as completed, after corrected to failed, clean controls preserved |
| Can original B38 identify that known upstream historical bug in a unique-name controlled run? | One known upstream source owner, frozen B38, 4 comparable observations | **Yes**, one pre-fix discrepancy; **not** unbiased detector recall |
| Are native request ID, agent tool ID, original durable start/end receipt and joined run all independently linked? | **0 original fully eligible cases** | **UNMEASURED, not clean** |
| Are independent original agent retry/cancel principles executable? | AgentRun owner 17/17 original tests | **Yes for that source's test scope**, not Nano or real side effects |
| Does a separate original MCP gateway classify errors and cancellations? | mcpproxy-go original tests PASS | **Yes at gateway classification layer only** |
| Does a different external original Rust app persist and stream correct MCP tool error statuses? | Official Erato source + real Rust app original integration attempt, initial stack overflow | **INCOMPLETE** until successful source execution |

**Next:** A truly stronger B44 must source-disjointly sample externally authored *original persistent receipts* **before** reading original implementations, and require an original join key linking `(native connection, request ID)` to `(agent tool call ID, durable start event, terminal event)`. Separate request accepted/queued, terminal reported and independent effect receipts. Include same-name concurrent calls, retries with distinct attempt IDs, cancellation during pending, timeout, missing records and duplicate terminals, and original no-write normal controls. Do not treat completion status as effect success; do not infer joins from tool names or ordering.

The successful results make a narrow practical tool direction clearer, but **no release or public `main` modification** is justified by B43 alone. All cases in this report are now exposed development cases and cannot be recycled as B44 blind holdout.
