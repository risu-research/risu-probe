# P6-B44 — Native MCP Call, Agent Identity, Durable Receipt, and Independent Effect

**Research date:** 2026-11-14 (America/New_York); GitHub Actions UTC 2026-11-15.
**Public main frozen:** `8d622b792b4ae58b7157fd81ee5f95d6febcfd53` (RISU Probe `0.9.23.dev0`). No product/release changes.

## Executive finding

In a new four-organization prospective, source-disjoint cohort, **all four original owner-written source test subsets executed successfully (320/320 original first-party tests)** without modifying any original application code. One selected original owner, **XAGI-Lab MELRA**, was then tested further in a single genuine **byte-serialized MCP stdio JSON-RPC → original Node MCP server → original durable SQLite task/receipt/certificate → independently read real filesystem mutation** run. The original program correctly refused a wrong approval without writing, then wrote the exact file on authorized execution, retained a task-scoped original receipt/certificate in SQLite reopened **after the process exited**, and returned a verified-success status. The actual native request/response IDs and cryptographic digests of serialized wire bytes were captured.

**The preregistered *full five-edge chain is NOT established***: the evaluated MELRA route is an **agent-independent MCP server** invoked by an evaluator-owned native client. The original agent's model-generated `tool_call_id` is absent; the original MELRA task ID is an internally generated UUID, **not** the original JSON-RPC request ID or a model's call ID. Original SQLite task receipts contain `startedAt` and `endedAt` and an original task ID but **not an original per-native-request start + end record with a persisted model-call↔native-request ID crosswalk**. It would be scientifically wrong to stitch those two identity namespaces by test-owned call order. The correct strong verdict remains **`LINK_INCOMPLETE`** and a population estimate of full-chain conformance is **UNMEASURED**. The test nevertheless **does establish a real usable lower-tier original native→original durable task outcome→independent file effect execution path**, which was absent in the B43 evidence.

## 1. Prospective preregistration, immutable source and cohort

Preregistration [PREREGISTRATION.md](./PREREGISTRATION.md) committed at **`22f32ed6b31fd100ca2b1ddd5a0951951279d49a`** before viewing the four selected upstream implementations. Exact immutable org/repo/commit and Git blob IDs [SEALED_COHORT.json](./SEALED_COHORT.json) committed at **`d7db9a17a89d6f176b786b95d8b24fb03a5e15eb`** before inspecting original file contents. No source-owner replacements after results. Original source implementation hashes were checked within each actual GitHub Action before running. The four upstream organizations were not original-source participants in B34–B43. All original owner test work was performed in B44 qualification branch, not public main.

### Frozen full-chain W/A/S/T/E criteria

1. **W original wire:** actual native `tools/call` request and reply with matching JSON-RPC IDs scoped to an original connection.
2. **A original agent identity:** actual model/agent tool-call ID, plus **original source-provided** mapping to native connection/request ID. Evaluator-generated call order/tool names or an evaluator's inserted ID are not original evidence.
3. **S original durable per-native-call start:** original persistent start event with native↔agent source identity link, reread independently.
4. **T original durable per-native-call terminal:** exactly one originally persisted matching terminal for an independently settled run, reread after process exit.
5. **E independent real effect:** original tool actually mutated a disposable resource, verified by an independent reader with exact before/after state; for a denied write, resource proved unmodified.

To call the full chain `FULL_CHAIN_VERIFIED`, every edge must be proved in the **same original invocation**, not five separately passing tests. Original task-scoped receipts with `startedAt/endedAt` are useful but insufficient for S/T until their original crosswalk to W and A exists. Effect confirmation must not be copied from the action's response.

## 2. Four source-disjoint independent owners, original first-party runtime results

| Frozen original owner | Exact upstream original commit | Original test suite and actual result | Scope and full-chain qualification |
|---|---|---:|---|
| **P1 XAGI-Lab/melra** | `ab59ffa134decd9613a378c7bd8a0e8d495c7e89` | **25/25 real governed HTTP/independent effect tests + 15/15 original SQLite storage tests = 40/40 PASS** | Real effect/independent verification and durable task records, but no external original agent model ID in evaluated server |
| **P2 heggria/taskflow** | `f4e29406b78a1e16c9b69a50f62096fb6e4ae74c` | **86/86 original persisted terminal/effect/native MCP cancellation/control tests PASS** | Native JSON-RPC request ID at transport; durable Taskflow `runId` generated separately; no observed per-wire native-to-model ID crosswalk |
| **P3 edgar4/yada** | `4066bb21fd3f1dd358d1d82166755671cd8e2b50` | **57/57 original MCP durable write, HTTP, authorization, reconnect tests PASS** | Strong application-level write `operationId` with `_meta` and separate reconcile receipt; original SDK native request ID or model-call ID to operation mapping NOT independently recorded in same first-party executed run |
| **P4 haibaoseal/sentinel-mcp** | `1692d38a20221da7d62fb6268a3a0097ebb1f523` | **137/137 original agent, stdio/HTTP MCP gateway, hash audit chain and local effect tests PASS** | Real model-proposed `call.id`, but original `AgentLoop._invoke` constructs firewall `ToolRequest` without original model `call.id`; firewall returns a distinct internal tool-call ID, and MCP SDK `ClientSession.call_tool` does not persist native request ID in original audit. Separate original tests cannot supply one cross-ID chain |

**Original selected owner tests: 320 passed, 0 failed**, across four original organizations (not an FPR estimate). Tests were carefully chosen from the original upstream project, not a claim about every repository test. Author runs:
- [MELRA owner run #43666801968](https://github.com/risu-research/risu-probe/actions/runs/43666801968) — original `pnpm build`, original server verified-effect tests 25 passed, original SQLite 15 passed. Logs SHA-256 `bb0c08a0e2a01f0fb127743a0d192e7fae75fa2ec37e2787d7162d029d1b134b`, `8282dbf90829251bbd5262abbac4e062874bb862a0ebbcfa93978c3f322a79b3`.
- [Taskflow owner run #43666832524](https://github.com/risu-research/risu-probe/actions/runs/43666832524) — original Node/pnpm build, owner 86 passed, log SHA-256 `f90ff27a3229abe58954155cad0f11388e2bc71af99888563d10d788a79bf90b`.
- [Yada owner run #43666767778](https://github.com/risu-research/risu-probe/actions/runs/43666767778) — original Vitest 6 files 57 passed, log SHA-256 `9241dd7b6a61dc2feefdb22d43e7e1a846819d476684b59162018e7ebfe520d7`.
- [Sentinel owner run #43666738466](https://github.com/risu-research/risu-probe/actions/runs/43666738466) — original Python `pytest` 5 selected suites, 137 passed, log SHA-256 `ab7b68e76015ab42f817ca92df488737696f2a1ceb2bb047d481e6ee647d214e`.

The original owner code offers four useful *different* pieces: Yada preserves application `operationId` through MCP metadata and reconcile; Sentinel has original provider `call.id` but loses the join before firewall; Taskflow has original native transport `requestId` and durable `runId` but no original bijective crosswalk shown; MELRA has independent actual-effect verification and original SQLite receipt but not an original external agent call ID. Their different properties are **not four parts of one execution**, and joining fields across different companies would be fabrication.

## 3. P1 original real native JSON-RPC → original persisted task/receipts → independently verified file

[**Source-preserving actual native evidence run #43667423952**](https://github.com/risu-research/risu-probe/actions/runs/43667423952), original compiled MELRA Node MCP CLI under an isolated temporary directory. Exact original source pinned at `ab59ffa134decd9613a378c7bd8a0e8d495c7e89` and `packages/server/src/mcp-server.ts` blob `17e3d6e7f0b63eb8395c4b5a9553dce3505d1a21`. The evaluator is an external **real native stdio JSON-RPC client**, not a fake MELRA server or reimplemented action dispatcher. Actual on-wire stdin/out newline-delimited UTF-8 message byte sequences were hashed before redacting ephemeral approval phrases in archived readable JSON.

The same workflow also ran **two further original author e2e tests**, testing original real native MCP approval+verified file and original stop/restart durable workflow, **2 passed, 14 explicitly filtered (not run)**. These two additional selected author tests are separate from the 320 earlier owner subset; 322 selected owner test passes if counted including this separate follow-up.

### Exact one-execution native message graph

| Original serialized MCP `tools/call` ID | Original target tool | Actual original native result | Independent real state |
|---|---|---|---|
| `b44-plan-101` | `melra_plan` | Original task `awaiting_approval`, original internal taskId and approval challenge | File absent |
| `b44-denied-102` | `melra_execute` with wrong approval phrase | **Native `isError:true`** | File still absent |
| `b44-execute-103` | `melra_execute` with exact original approval | Original status `verified_success`, original task receipt | Original MCP server **actually writes** the file |
| `b44-receipt-104` | `melra_receipt` | Original saved one receipt, certificate `VERIFIED_SUCCESS` | Original SQLite later reopened independently |
| `b44-status-105` | `melra_task_status` | Original task `verified_success` | Original task DB status checked after original process exit |

Actual effect: isolated disposable `b44-effect.txt` written with fixed content; independent separate Python file read confirms **exact byte equality** and **SHA-256 `5dfb18d66bc68dacedf3d62ef83d612bc763068619d6637d1c95cd8574cc45e2`**. No external production API or filesystem path was touched. A denied attempt left the file absent.

After MELRA original process **terminated cleanly**, a fresh separate Python SQLite read-only connection opened original `melra.sqlite`. Original task row **1**, original receipt row **1**, original certificate row **1**, all for exactly the same original **taskId**. The original persisted receipt schema includes `startedAt` and `endedAt`. The stored task status was `verified_success`, original receipt ID matched native API result, original certificate result was `VERIFIED_SUCCESS`. This proves a meaningful **original task-scoped persisted execution receipt**, not a native-wire-request-scoped start/terminal.

**Witness JSON SHA-256 `98e2fc70617a5fa620cdebab88c3fe3c65729afa8bee65c8357cadb09ed07baa`**. Witness contains actual native ID-labelled request/reply frames with SHA-256 of raw bytes, original receipt/certificate IDs and digests, original SQLite schema and individual row hashes, effect SHA, and exact provenance and limitations. Ephemeral approval phrase redacted in human-readable copy, raw frame hash retained.

### Why a full chain is still unproven

The original external program MELRA is an **agent-independent executor**. In this path it has no original model/agent `tool_call_id`; native JSON-RPC `id` originates from evaluator-controlled client. MELRA originally mints independent taskId and receiptId; original stored task/receipt does not carry the client's original native request ID or an original external model call ID. Original `receipt.startedAt/endedAt` is task-scoped and does not prove *one distinct terminal per native JSON-RPC call*. This is a source-evidence capability boundary, not a real application's false-success bug. One cannot combine `b44-execute-103` and original MELRA taskId by test-local call order into an original permanent ID join.

Actual original evidence under the prereg rubric: `W=true, A=false, S=false, T=false, E=true` **for per-native-call strong proof**, and **original task-level durable receipt=true**. `FULL_CHAIN_VERIFIED` original eligible organizations in this 4-source exploratory test: **0 eligible; full-chain conformance rate UNMEASURED**. It is not honest to report “0/4 correct,” “100% fail” or an FPR.

## 4. Independent evaluator score and unchanged pre-B44 research checker

[**Independent score run #43667744634**](https://github.com/risu-research/risu-probe/actions/runs/43667744634) loaded the *actual generated original-byte-frame/SQL/file witness* from #43667423952. A separate research evaluator `benchmarks/p6b44/runners/score_original_native_effect.py` checked actual W request/reply IDs, five observed native tool names, native error status for rejected approval, independently read file digest, post-exit original SQLite task/receipt/certificate row counts/hashes, and original task receipt's `startedAt` and `endedAt` schema. Result: **`LINK_INCOMPLETE`** because original model/native-ID crosswalk and original per-native-call start/end is absent, despite true native and real effect. **6 post-exposure synthetic negative tests** for missing durable row, missing effect, false success after denial, fake source model ID, counterfeit complete link, wrong file digest all passed. These were post-exposure evaluator checks, **not six independent original organizations or additional holdout positives**.

The previous research-only original B43 bridge was checked out from exact source commit `9dd37df63614416979052b30f3def8bac6f573e6`, frozen Git blob `3c20076a39ebf3529f600b59c3b38930d3d17d41`, **unmodified**, and supplied the actual original native `b44-execute-103` request/response without fabricated original connection/model/journal IDs. It returned `INCOMPLETE: CONNECTION_ID_NOT_RECOVERABLE`, correctly refusing to identify a complete original persistent chain. This is a high-value negative calibration: even when a real effect and original durable receipt exist, an independent verifier must not invent the missing cross-layer identity bond.

Strict independent score JSON SHA-256 **`1042ac0ca958ec13b49de7ebea91078ad4e1e47cc096239a06d01173a249485e`**. The frozen B43 incomplete output JSON SHA-256 **`e9635e1744ea88f833dc1dda74d4d0a685b88e15a0125f426fba6734cfd47887`**. A first [evaluation harness run #43667675115](https://github.com/risu-research/risu-probe/actions/runs/43667675115) failed at an evaluator-only assertion requiring an explicit `isError:false`: normal MCP results legally omit the optional flag. The evaluator script was corrected to `get('isError', false)` and the **rerun succeeded** (#43667744634); no external source or scoring contract was changed. This setup failure is preserved rather than hidden.

## 5. A genuinely small next method, based on what failed to link

The scientific opportunity is an **original-source-issued execution crosswalk and effect receipt**, distinct from a generic schema checker. The minimal robust record should be generated at the trusted original invocation boundary and reference:

- `agent_tool_call_id` from the real original model/agent, before dispatch.
- `native_connection_id` and original native `tools/call` request ID from original client/transport.
- `operation_id` and `attempt_id` minted and durably recorded by the original action/agent, distinguish logical retry from unique attempt and exact original effects.
- An append-only original `START` event before crossing the write boundary and exactly one originally persisted terminal event referencing it, with explicit success/error/cancelled/unknown and acknowledged post-join state.
- Independent original read of the resource state, with immutable digest/receipt stored under the same operation id; importantly original proof of actual effect rather than adapter status.
- Original authorization owner/principal, source SHA/version and proof of the boundary from which each field is emitted.

Do not derive original `agent_tool_call_id` from a tool name, tool inputs, timestamps, trace ordering, or MELRA's task ID. Do not count an original task receipt as a per-native-JSONRPC terminal. For retries after lost responses, reconcile by operation ID before replaying irreversible writes. For external receipt assurance, distinguish self-hashed source from an independently verified effect or independent anchor.

**Suggested B45 criterion:** preregister an entirely new, non-overlapping original third-party client/agent that *actually retains the model call ID*, original MCP native JSONRPC ID, original operation ID, and original durable start/end records; then join it to a real effect verified independently, using original source event records, without a test-only reconstructed mapping. Alternatively, explicitly design and release a separate **instrumentation layer** for the original missing seam and evaluate that layer on a different B45 held-out original agent. The latter is an **instrumented bridge** claim, not a claim that unmodified external upstreams originally provided the missing fields. Prefer one narrow definitive correctness criterion over broad “agent reliability” generalities.

## 6. Summary by proof level and release decision

- Original owner source organizations: **four** (all selected and executed).
- Original author selected test assertions: **320/320**, plus **2/2** additional MELRA native e2e tests in a separate run; no user services used.
- Original source organizations with a **single actual raw native MCP→original persistent task/receipt→independent real file effect** executable witness: **one (MELRA)**.
- Original native tool requests in that live joined source execution: **five**; one rejected approval is explicitly `isError:true`, no unauthorized file effect; one approved write has exact independent file effect.
- Original durable MELRA task/receipt/certificate per same task: **one each**, reopened postprocess, not per native request.
- Original source **full five-edge** verifiable native↔model↔original start/end↔effect chain: **0 eligible original organizations**; full strong-link quality and FPR **UNMEASURED**.
- Independent B44 scorer: correct `LINK_INCOMPLETE`, six synthetic negative tests, and independent frozen B43 bridge correct `INCOMPLETE`.
- No evidence the original upstream write used a live external production provider, no effects beyond temporary files, no model release vulnerability claims.
- **No modifications to public product `main`, frozen B38 or PyPI; keep this B44 qualification work as reproducible research evidence.**

[Machine-readable evidence index](./EVIDENCE_INDEX.json) tracks exact original SHA, original source blobs, per-run GitHub URLs and downloaded artifact SHA-256. Full recovery archive includes original author logs and original native/source evidence.
