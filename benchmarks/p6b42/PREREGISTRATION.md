# P6-B42 — prospectively sealed native-client status and independent completion-omission evaluation

**Freeze point:** this registration is committed **before opening any selected original implementation/test file contents**. Eligibility screening used only repo/PR metadata, file paths, blobs, and public SDK documentation. Freeze commits and all Git hashes are repeated in `SEALED_COHORT.json`. No substituting a case after implementation/test inspection.

## Unmodified primary checker and public product

- RISU Probe public `main` remains `8d622b792b4ae58b7157fd81ee5f95d6febcfd53`, release `0.9.23.dev0`.
- B38 original unchanged: `research/b38_native_contract_auditor.py` at commit `425d3d8272c4e725064010ed8fbf5b8217080cab`, original source Git blob `67bbb607d277dda3a1ead60a2ccd9ba807afd7ae`.
- B34–B41 original organizations/sources **excluded as B42 new samples**, including Mark3labs, Metoro, Agentmetry, LangChainJS, Mastra, OpenAI Agents JS, Vercel; frozen B38 unchanged throughout.
- B42 has **TWO independent research tracks**, separately measured, separately denominated, no cross-track success inflation.

## Track A — original externally authored clients with explicit returned in-band MCP status

Preregistered normal N1: `modelcontextprotocol/go-sdk` commit `0fa5e8407aa3fda65166e4207156c03d084bfd44`, original `mcp/client.go` blob `7894dd0eee3e18bed7137ed88c9b5016ccc90a74`, author test `mcp/client_test.go` blob `12bf52e7726f3a66eb8da431862d31b91f16fb76`. Distinct organization from B41 Mark3labs; despite SDK-level shared protocol and possible shared specification, the actual Go original consumer implementation is separate.

Preregistered normal N2: `PrefectHQ/fastmcp` commit `a8745d61e650467756bb28b4157822dbfbdfa34f`, original `fastmcp_slim/fastmcp/client/client.py` blob `99cfd750f5a3f76f5fbb3c917850ac4e27345b43`, author tests `tests/client/client/test_client.py` blob `846d03bf4271c069f1d8a356573cf8729c3da4aa`. Distinct org from N1 and prior rounds.

Predeclared contract cases per normal organization, against **actual original client source and native `tools/call` JSON-RPC**:
- ordinary text success, `result.content` list and `isError:false` or omitted;
- returned in-band tool refusal `result.isError:true` (explicit boolean), *not* HTTP 500, thrown JSON-RPC error, or exceptions-as-messages;
- where supported, `structuredContent` with declared content may be additionally run, but is **not automatically a third independent organization** and must not inflate status FPR;
- compare original native request ID and original JSON-RPC response bytes separately from original consumer-returned `IsError` / `is_error`; `error==nil` is not equivalent to explicitly reported application success (B41 correction).
- Contract `{status:true,text:'none',structured:'none',media:'none'}` for primary FPR. Separate exact text/structured contracts permitted only when declared independently of results. B38 `INCOMPLETE` and `NOT_SCORED` never count as no false alarm.

**Normal-client denominator** is the number of selected original independent client organizations (**planned 2**) whose original native `tools/call` request/response IDs are matched **and** an original client `isError` status is explicitly observable. `m` may be 0,1,2; false alarm `k` means frozen B38 labels independently verified normal consumer under preregistered contract as `DISCREPANCY`. Report **k/m by organization**, number of calls separately, Wilson 95% bounds descriptive only, **no population FPR generalization**. Both original clients may be tested with first-party local peers rather than independent production servers; label provenance. Record any unsupported output/transport condition without silent substitution.

## Track B — independent original event-completion obligation, NOT a B38 status check

Preregistered positive C1: `matthewfae/Personal-Assistant` original merged [PR #37](https://github.com/matthewfae/Personal-Assistant/pull/37) (2026-10-12). Original pre `241b1cb722af4efed82afd308c1232163517e429`; official post `d164e21ceee1596d23ab2a61146457c558005ec9`. `bot/agent.py` pre blob `cae2390364ca5955bfa3f12afdc2cc760b2bfbd4` / post `f6d789ce4da435286e93a6ea1dc56530cedaccee`. `bot/mcp_client.py` pre blob `2e807771cc0b391bef5b08a5e82ac349d76217e9` / post `d6d0ae4ffb0d24befbec7a5a0cda5e7cf0897d62`. PR maintainer claims tool call exceptions left `tool_call` with no matching `tool_result`, and post original shared helper writes terminal result for every completed attempt. We will verify rather than assume.

**Completion property `C42-COMPLETE-1`, frozen now:** On a bounded, synchronously *settled* original tool execution with an originally recorded `tool_call` event and a stable call identifier, the independently observed final journal/sink must contain **exactly one matched `tool_result` terminal event**, for all three predeclared outcomes: success, MCP `isError:true` and raised original client error. Match original tool use/call ID where source provides it, not adjacency alone. Check no unmatched terminal event, no duplicates, no false completion when an operation never started. **Silence while pending is INCOMPLETE**, not missing result. A finished operation is proved by a returned original awaited function or a recorded run stop/join, not an arbitrary wall-clock sleep. Missing result on settled call is `OMITTED_TERMINAL_EVENT` only with independently observed start, settled evidence and an observable end-of-run/snapshot boundary. For before/after positive, execute **original pre and original official post code**, identical test-only controlled MCP stub and synthetic API/model where possible; no modifying original source. Original maintainer tests preferred; test-only overlay original author post regression on pre permitted but annotated. If no accessible original persistent sink / event IDs or execution blocked, report source-confirmed but `INCOMPLETE`, not a claimed detector hit.

**Track-B checker is distinct from B38**: implement *only after freezing this property* a separate opt-in research scorer that reads observed original immutable event sequence, explicit `started` + `settled` evidence, and matched call ID. It does not claim to be part of public RISU Probe, and its positive might be trivial under an ideal original event log; no generic algorithm superiority claim. Before official post correction: sought `OMITTED_TERMINAL_EVENT`, after `PRESERVED`. All three success/error/exception controls included; if the pre bug is not reproducible on the official snapshot, report not reproduced.

Preregistered secondary external C2: `TGPSKI/leather` original [PR #51](https://github.com/TGPSKI/leather/pull/51), pre `a9cffc50a0425d2217e566f988612b25d1efb6d7`, official post `c2d4da6d5022b42be5ff9818dd0f6d8900314769`. Source `internal/mcp/client.go` pre `44fbcc28cc243e1172f0995e0d8b342c4e345323` post `20deb3c09cd507b4a182f74f71dc314c4bcd3ee0`; `internal/runner/runner.go` pre `b31ace0033779c126306295a9a24683210a19c93` post `4bceeb4ec382c2daf95bfcb3f071eba000603b93`; new author test `internal/runner/tooltrace_test.go` blob `c194da6a186a4e360eeb8527fbed50514429a60e`. This PR concerns repaired MCP error, dedupe and **opt-in tool trace persistence**, so **do not assume** it is a missing tool_result bug. It is secondary external replication/control of what a true terminal run record can/cannot substantiate. Eligible for the C42-COMPLETE-1 denominator only if it originally records independently matched per-call starts, per-call terminal events and settled evidence; otherwise classify as context/other repair only, no cross-counting. If executability proves difficult, preserve failure.

For completion separate denominators:
- **Positive confirmed-repair owners** (planned 1 C1), matched pre/post execution;
- **Independent original source organizations that demonstrably implement C42-COMPLETE-1** (target C1, possibly C2 if eligible), explicitly report m. Track-A orgs are not completion orgs.
- Distinguish `OWNER_REPAIR_REPRODUCED` from detection by new general property and from owner authored tests. Neither automatically implies future performance on new held-out organizations.

## Execution process, controls, and honest limitations

1. Commit `PREREGISTRATION.md` then immutable `SEALED_COHORT.json` **before opening source code or running any selected tests**.
2. All runs pin exact Git SHA and source Git blob, verify after checkout, and record exact code path. Use original code with separate **test-only** adapters. No source changes to selected original implementation. Do not present a copied wire flag as original observation.
3. Record independent native request/response and original client application return. For completion, original event journal and explicit settled evidence, exact per-call ID and bounded end.
4. Preserve failing jobs, source contents barriers, unsupported policy and wrong assumptions. No cherry-picked replacement sources. Use explicit result tiers `ORIGINAL_CLIENT_NATIVE_JSONRPC`, `ORIGINAL_AGENT_JOURNAL_SETTLED`, `ORIGINAL_OWNER_TEST_ONLY`, `ORIGINAL_LIBRARY_NO_EVENT_PROOF`, `NOT_EXECUTED`.
5. Exclude any unrecorded test from FPR and completion denominators. After B42 original exposure, all cases are **development data**, not new blind B43. Public `main` stays frozen.
6. Success is **not** guaranteed: normal 2/2 eligible and one true original pre/post missing-completion repair would be strong; partial evidence is preserved with honest `UNMEASURED` / `INCOMPLETE` where required.
