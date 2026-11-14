# P6-B42 Final Original-Source Audit: Native Error Status and Settled Completion Events

**Date:** 2026-11-14  
**Research branch:** `qualification/p6b42-disjoint-native-status-and-completion-20261114`  
**Result:** Both selected original external MCP client organizations proved eligible and preserved explicit in-band error status over real serialized JSON-RPC; the frozen B38 checker produced **0 false-alarm organizations among 2 eligible organizations**. Independently, the preregistered *new* completion obligation verified one actual original external application's missing terminal `tool_result` before an upstream repair and the restored terminal event after the official repair. The secondary independent original owner trace implementation was executed but deliberately excluded from the completion-event denominator: its type does **not** record separate, per-call matched start/end events.

## 1. Prospective design and unmodified product

The [preregistration](./PREREGISTRATION.md), Git commit `706c2cbc545bd630dcf13c49ec0329db32dc89eb`, and [sealed source/contract cohort](./SEALED_COHORT.json), commit `1c838683289633ace51618e45c8f07f1325530e5`, were committed **before opening the selected upstream implementations/tests**. Selection used public repository / merged PR metadata, file names and immutable Git blob IDs. None of the selected B42 organizations was a re-used B34–B41 sample. No post-results substitution.

Public RISU Probe `main` stays `8d622b792b4ae58b7157fd81ee5f95d6febcfd53` (version `0.9.23.dev0`). Frozen B38 source `research/b38_native_contract_auditor.py`, commit `425d3d8272c4e725064010ed8fbf5b8217080cab` and Git blob `67bbb607d277dda3a1ead60a2ccd9ba807afd7ae`, was **never edited**. Original upstream code was checked out at its sealed SHA and original implementation blobs checked before overlaying evaluator-only test/relay files.

### Two research tracks, **never combined into one accuracy score**

- **Track A, existing frozen B38:** original client `tools/call` native request/response ID matched with *separately observed* original consumer in-band error status. Organization-level normal-client false-alarm result, independently selected N1 and N2.
- **Track B, novel research-only `C42-COMPLETE-1`:** original `tool_call` event, proven settled original function, joined run, immutable post-join event log snapshot and **exactly one matched `tool_result` terminal event**. Distinguishes omission, wrong-parent and duplicate from INCOMPLETE pending/unavailable evidence. No B38 sensitivity claim, no public product feature.

## 2. Track A, source-disjoint original MCP client native-wire validation

| Selected independent original client | Actual original native tool calls | Original returned status | Frozen B38 result | Eligible organization |
|---|---|---|---|---|
| **modelcontextprotocol/go-sdk** (official MCP Go SDK) | 2 real newline JSON-RPC over `net.Pipe` + original `IOTransport` and server | `CallToolResult.IsError` explicit true/false | Both `OBSERVED_CONTRACT_PRESERVED` | Yes |
| **PrefectHQ/fastmcp** | 2 real stdio JSON-RPC through byte-preserving local relay + original `PythonStdioTransport` and FastMCP server | Original `Client.call_tool(...,raise_on_error=False).is_error` explicit true/false | Both `OBSERVED_CONTRACT_PRESERVED` | Yes |

### N1 — Official Go MCP SDK

- Frozen original: `modelcontextprotocol/go-sdk` commit `0fa5e8407aa3fda65166e4207156c03d084bfd44`, `mcp/client.go` blob `7894dd0eee3e18bed7137ed88c9b5016ccc90a74`.
- Original author `TestInMemory_E2E_DiscoverSuccess` passed.
- Original `Client.Connect`, `ClientSession.CallTool`, `IOTransport`, and `Server` executed. Two evaluator-wrapped byte streams captured actual native JSON-RPC on client and server sides, separately from the actual returned `CallToolResult.IsError`. Exact tool and response request ID were paired, not synthesized.
- Normal `b42_success` and `b42_denied` with genuine in-band `result.isError=true` each preserved original client status. Frozen B38: 2/2 status contracts preserved.
- **Preserved unsuccessful harness attempt:** first execution [run #43640162371](https://github.com/risu-research/risu-probe/actions/runs/43640162371) failed because an evaluator-defined tool omitted the *original SDK-required* input JSON schema. Corrected the **test-only harness**, adding schema `{"type":"object"}`, without modifying upstream source or sample. The [final execution #43640340345](https://github.com/risu-research/risu-probe/actions/runs/43640340345) passed both original client and B38 checker.

Raw native observations SHA-256 `c9ba97fffaddf4020b86f28808dea5a342ee8008ed2859cbe4d70c196a2e48b4`; original B38 score SHA-256 `57b457666bbc0553847625bc07ddb20b63e7670b5622c5d2bafaae8ba1655c35`. Tier **ORIGINAL_CLIENT_NATIVE_JSONRPC_WITH_ORIGINAL_SERVER**; *not a deployed third-party agent app*.

### N2 — PrefectHQ FastMCP

- Frozen original: `PrefectHQ/fastmcp` commit `a8745d61e650467756bb28b4157822dbfbdfa34f`; source `fastmcp_slim/fastmcp/client/client.py` blob `99cfd750f5a3f76f5fbb3c917850ac4e27345b43`.
- Original `Client`, original `PythonStdioTransport`, and original FastMCP server executed. Evaluator-owned transparent relay forwarded all bytes unchanged and stored actual client-sent request and server-sent response lines **before forwarding**. The independent downstream status was the real original `Client.call_tool(...,raise_on_error=False)` return field `.is_error`, not the raw wire reused as a fabricated observation.
- Normal `b42_success` and native tool execution failure `b42_denied`, which raises inside server and becomes **in-band** `result.isError=true` with normal JSON-RPC `result` object (not HTTP 500 or a JSON-RPC `error`). Both status checks preserved. [Final native execution #43640340345](https://github.com/risu-research/risu-probe/actions/runs/43640340345) passed.
- Original maintainer first-party selected client test **initially could not load** because evaluation dependencies lacked `opentelemetry.sdk` in `tests/conftest.py`. This setup failure is **not** an upstream failed test. A **separate follow-up Actions job** installed missing test dependencies, without modifying original code, and [run #43640727471](https://github.com/risu-research/risu-probe/actions/runs/43640727471) passed **3 original maintainer client tests** with 56 deselected and one deprecation warning.

Original native witness SHA-256 `8fc4ce1fae3652f561020108dacf9dadc1c07d3ee5bdc76092a6ed9422509698`; captured raw newline wire log SHA-256 `56eeba685c153480e9e240a59a4611faa9b92713cb03ed35151718ad9f5c22ae`; frozen B38 score SHA-256 `c25ee207f6abc9718cb5303ed702854a88bf4bcf826be1f8a0561b7bacf8aba4`. Tier **ORIGINAL_CLIENT_NATIVE_JSONRPC_WITH_ORIGINAL_SERVER** (local test peer), *not original independently deployed application*. Neither dependency-recovery job nor extra author test increases denominator.

### Track A denominator and limitations

- Preselected external normal-client organizations: **2**; eligible real original native status observations: **2/2** organizations.
- Each organization had genuine success plus real in-band `isError:true`: **4/4 tool calls** status contracts preserved; each organization's result counted **once**.
- Frozen B38 false-alarm organizations: **0/2**, descriptive Wilson 95% confidence interval **[0, 0.65762]**. The upper bound is too broad to assert a reliably low false-positive rate.
- **Population FPR NOT ESTIMATED.** Sample is tiny, purposive, from SDK code + local test peers, not independent random deployments. The SDK implementations are independent organizations, but share the public MCP specification and neither is a whole external agent.

## 3. Track B, original immutable completion log (separate research property)

### Frozen `C42-COMPLETE-1` rule

An externally recorded tool start **must** have exactly one matching result in the original immutable journal **only if** the original tool attempt is independently proven settled, the enclosing original function has actually returned/raised, the operation is joined, and the journal snapshot follows that join. Matching requires original `tool_use_id` and the correct original `tool_call` event primary key as the result's parent. Pending work, absent journal or ambiguous identity is **INCOMPLETE**, not omission. Duplicate, wrong-parent and true omissions have separate findings.

The standalone new evaluator `benchmarks/p6b42/runners/completion_obligation.py` passed **eight positive/negative self-controls** including pending, orphan and duplicated terminal events. The new `C42` policy is a **research-only addition**, not a modification to B38 or the public CLI. This property tests recorded completion fidelity, **not whether the external tool's side effect was actually completed**.

### C1 — Original Personal-Assistant official before/after

- Official [PR #37](https://github.com/matthewfae/Personal-Assistant/pull/37), selected by official merged PR metadata. Frozen before `241b1cb722af4efed82afd308c1232163517e429`; official after `d164e21ceee1596d23ab2a61146457c558005ec9`.
- Original `bot/agent.py` pre/post blobs `cae2390364ca5955bfa3f12afdc2cc760b2bfbd4` and `f6d789ce4da435286e93a6ea1dc56530cedaccee`. **Actual original `agent.run_loop`, `write_event`, original SQLite `get_db/init_db` and original immutable DB trigger were executed** with six separate original fresh databases.
- Test-only local scripted model issued one tool call and then a deterministic end/reﬂection; fake MCP peer supplied success, in-band failure, or raised transport error. Original model API and actual native MCP network were **not** used, so this is **ORIGINAL_AGENT_JOURNAL_SETTLED_WITH_SCRIPTED_MODEL_AND_MCP**, not an end-to-end live agent deployment.

| Original tool outcome (one original tool ID per case) | Original pre-fix journal | Official post-fix journal |
|---|---|---|
| Successful tool result | 1 start, 1 matched terminal — preserved | 1 start, 1 matched terminal — preserved |
| In-band failure content (scripted return) | 1 start, 1 matched terminal — preserved | 1 start, 1 matched terminal — preserved |
| Exception raised by original MCP call interface | **1 original start, 0 terminal — `OMITTED_TERMINAL_EVENT`** | **1 start, 1 terminal — preserved** |

The original pre-fix function actually raised after leaving the committed `tool_call` row with no matching `tool_result`, and we proved the operation settled **before** the real DB snapshot. The repaired original writes one error `tool_result`. Because all three original outcomes were checked both before and after, the check did not pass merely by labeling every missing event a bug.

[Original before/after SQLite journal run #43639787592](https://github.com/risu-research/risu-probe/actions/runs/43639787592) **SUCCESS**. Before/after original journal JSON SHA-256 `e794856314592208f5698af986a6c77975207a0ee91af040af0e960527ac6b13` / `55d960514c6dbb93d72f32b47d10574fe5ae96e46b672d08779f32a0c95c9a10`. Independent C42 scores `1acf089eed939908ef34cafdc8eea93e073a91d0f0a0f8202646ed3659db2261` / `e6a5750c31c3e635f0e02bf63ff12dba0e268af4429886bbf749d81f43e8642b`.

This is **one independently authored original repair reproduced and one matched missing-completion case detected**, not a measured general true-positive rate or evidence B38 detects this class.

### C2 — TGPSKI Leather as an external scope/negative-eligibility control

- Different external organization. Frozen original [PR #51](https://github.com/TGPSKI/leather/pull/51), post `c2d4da6d5022b42be5ff9818dd0f6d8900314769`. This PR repairs MCP tool error semantics/deduplication and adds **opt-in** tool trace persistence; the preregistration explicitly warns that this is *not necessarily* a missing `tool_result` event fix.
- Ran **five original maintainer tests** on original external code: one `TestMCPClient_CallToolError`; four `ToolTrace` tests covering normal, failed, duplicate replay, and the documented `persist_runs_detail:none` default. All passed. Independently reflected actual original `model.ToolTrace` fields and confirmed it exposes **a single aggregated end-of-run tool record**, but *no stable tool-call ID, no separately recorded start and no separately recorded matched terminal event*. [Original external run #43640413237](https://github.com/risu-research/risu-probe/actions/runs/43640413237) **SUCCESS**.
- Therefore Leather is **C42-COMPLETE-1 INELIGIBLE**, **not** counted as an extra success, omission, or second owner repair. Its `persist_runs_detail:none` default intentionally disables the aggregate tool trace, so trace absence under that configuration is no evidence of a completion-event bug. No actual C2 original pre/post tests were conducted; only the original official post source.
- Reflected original type JSON SHA-256 `ebe48c0f2ed595b9d4b8c673a8bbce8b36b54f2d9ad26b8f4b2fbb566ccba875`.

## 4. Final denominators and reproducibility

| Independently preregistered question | Actual eligible evidence | Verified result | Unsupported extrapolation |
|---|---|---|---|
| Existing frozen B38 on original normal MCP clients | **2 independent original client organizations / 4 real calls** | **0/2 false-alarm organizations** | No low-FPR ecosystem guarantee |
| New original settled completion-event obligation | **1 original before/after repaired owner, 3 paired cases** | **1 pre-fix omitted terminal event; 0 in repaired post** | No generic sensitivity or deployment reliability |
| Secondary Leather external aggregate trace | One original post source, **5 upstream owner tests**, original type audit | Source and tests pass; **not eligible** for C42 per-call events | No completion-rate denominator increment |

The full machine-readable [Evidence Index](./EVIDENCE_INDEX.json) records Git commits/blobs, SHA-256 digests, failed setup attempts, exact Actions runs, source execution tiers and original client/agent boundaries.

## 5. Research decision: B43

**Keep B38 and the public product frozen.** B42 achieved B41's missing admissible comparison by obtaining two distinct original status-bearing clients (rather than a silent return API). More importantly, it supplied a genuinely separate independent completion contract with a verified original repair.

The next meaningful work is **not** adding more source-specific special cases to B38 and presenting them as general detection. For B43, prospectively seal **new original external agent applications** that record both (i) matched native in-band `isError` and (ii) their own durable per-call start/end receipt IDs, with a bounded joined snapshot. Use a source-disjoint original missing-result pre/post positive and source-disjoint normal controls, including pending, cancellation, retries and result-logging disabled by design. Seek real original model/agent/tool execution before claiming deployed fidelity, and separately test that matched completion records describe actual authorized effects. Newly exposed B42 sources are now development evidence, never an unexamined B43 holdout.

No user action is required. No change to public `main`, product, or released package is authorized or made.
