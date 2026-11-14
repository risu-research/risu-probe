# P6-B41 Final Audit — Original external MCP clients, native status, and missing-outcome discipline

**Date:** 2026-11-14  
**Verdict:** Executed selected original client code for both preregistered normal organizations and the selected original positive-repair proxy. The single eligible normal organization had zero observed B38 false alarms, but that is **0/1 organization**, not a meaningful ecosystem FPR bound. An older original client dropped the ability to observe the tool-error flag, and the original pre-fix proxy emitted no explicit terminal success outcome. The public product stays unchanged.

## 1. Preregistration and source provenance

Before inspecting selected code, B41 preregistered three *source-disjoint* organizations and the original Git blob IDs.

- [Preregistration](./PREREGISTRATION.md): Git commit `4e48e69616c0f3bf259f8d958a7ce7e9682892f2`.
- [Sealed cohort](./SEALED_COHORT.json): Git commit `41643a236785ae8871b1fdb458500a3b280ef404`.
- Frozen public RISU Probe `main`: `8d622b792b4ae58b7157fd81ee5f95d6febcfd53` (original `0.9.23.dev0`). Product, CLI, dependency API, and PyPI unchanged.
- Frozen, **unaltered** source-independent B38 status/channel auditor: `research/b38_native_contract_auditor.py` at Git commit `425d3d8272c4e725064010ed8fbf5b8217080cab`, Git blob `67bbb607d277dda3a1ead60a2ccd9ba807afd7ae`.
- Evaluators checked out original Git commit and source blob before adding **test-only** independent witness files. All test peers use synthetic data and local processes/loopback.

The B41 *primary* sample comprises two normal-client organizations (N1 Mark3labs, N2 Metoro) and one independently authored known repaired positive (P1 Agentmetry). No replacements were made based on outcomes. All GitHub Actions and full raw evidence hashes are in [EVIDENCE_INDEX.json](./EVIDENCE_INDEX.json).

### Primary evidence table

| Selected original | Original code executed | Actual native wire and original consumer observation | Frozen B38 outcome | Independent normal FPR denominator |
|---|---|---|---|---|
| **N1 Mark3labs MCP-Go** | Yes, original client + original InProcessTransport and client-server JSON-RPC | Three matched tool calls: success text, in-band `isError:true`, structured + text | Three `OBSERVED_CONTRACT_PRESERVED`, no warnings (status contract) | **1 eligible org** |
| **N2 Metoro MCP-Go** | Yes, original client and original HTTP transport, local controlled HTTP server | Two matched `tools/call` responses: success and `isError:true`. Original `ToolResponse` holds only `Content`; status not exposed | `NOT_SCORED`; scope-ineligible under preregistered native returned-status policy | **0 eligible org** |
| **P1 Agentmetry** | Yes, original pre/post relay consumer `_relay_stdout` and author-owned regression tests | For `result.isError:true`, before emits **no** terminal failure event; after emits `tool_failed` and `outcome:error` | Before **INCOMPLETE** (no explicit successful terminal observation); after preserved | Positive cohort; never in normal denominator |

All [original upstream maintainer test preflights passed](https://github.com/risu-research/risu-probe/actions/runs/43635518842) (three independent jobs), and [native witness plus frozen auditor passed](https://github.com/risu-research/risu-probe/actions/runs/43635950974) (three independent jobs). The success status of this workflow is **not** a claim that all subjects were rated as “clean”: its verifiers explicitly require incomplete/ineligible classifications where appropriate.

## 2. N1 Mark3labs: actual native client, status fidelity

- Original source: `mark3labs/mcp-go` commit `a21ffc6877f1741603dc36246f309d6cf6c6ed05`, `client/client.go` blob `9f1a4a692507e1c4854cf03f5fb9064351ad6da8`.
- The **original author test** `TestInProcessMCPClient` passed all nine selected subtests.
- Independent evaluator used the **unchanged** external client's `NewClient`, `Initialize`, and `CallTool` methods over original `InProcessTransport.SendRequest`, which serializes and parses JSON-RPC through the original server. A test-only transport wrapper separately captured the native request/response pair.
- The actual downstream observation came from original `CallToolResult.IsError`, *not* copying `response.result.isError`. Three native calls matched exact native request IDs and method names:
  - `b41_success`: successful text
  - `b41_denied`: native tool result with `isError=true`; original client returned `IsError=true`
  - `b41_structured`: ordinary tool result with structured content and text

The unmodified B38 checker marked **3/3 status observations `OBSERVED_CONTRACT_PRESERVED`**, with **zero false-alarm findings**. The three outcomes are **one** original client organization, not three independent organizations.

[Original native-client/unchanged-B38 job](https://github.com/risu-research/risu-probe/actions/runs/43635950974). Original JSON SHA-256 `86667f1e03d402d403bcc50cb19a1dd699bc2d896599e371e15e9f15d33d89`; score JSON SHA-256 `9547715833107f64ef363bab895be08ffca7c93d8a4e732a7a51cf8972cfa506`.

**Proof tier:** externally authored original client library with native JSON-RPC and local evaluator-controlled original SDK server; *not* an independent external agent application in production.

## 3. N2 Metoro: real original client, no returned in-band error status

- Original: `metoro-io/mcp-golang` commit `e5d629c5cd43e3470dcd3bf4cbc675a90bfcf513`; `client.go` Git blob `a0e3536b9cd2a3081b65fa2c97e2b5f6eede86ac`.
- Original maintainer `TestReadResource` (HTTP original client) passed.
- Test-only controlled HTTP server sent real JSON-RPC `tools/call` replies for `b41_ok` and `b41_denied`. The second reply **contained `isError:true` on the native wire**. Original `NewClient`, original `HTTPClientTransport` and `CallTool` executed. IDs and content were traced separately.
- The original `ToolResponse` type exposes `Content` and no `IsError` field. Original `CallTool` returned parsed text and a **nil Go error**, including for the tool error case. The return value itself gives a caller no explicit way to distinguish the two tool statuses.
- **This is a concrete source-verified and runtime-observed API limitation.** It matters to anyone building audit or policy logic on that original client. However a Go `nil` *transport error* does not by itself prove an application positively reported success. MCP in-band tool errors may legitimately return without a thrown exception. The predeclared B38 status observation therefore remains absent.

B38 `NOT_SCORED`; **N2 is ineligible rather than clean or a counted false positive**. The new insight is a client-boundary observability gap: even a correct native sender status does not ensure a downstream API exposes the status required for independent policy verification.

Original JSON SHA-256 `b38ccb0a578b0e06ab7c3303cde2425974c93838bc044d377023c5f8bbec22da`; eligibility JSON `39cabaa726ffb8aefe176811eca04a2de267d39b0cfa63fab2e05fe22d2008eb`. Proof tier: independently authored original client + HTTP transport to local synthetic peer.

## 4. P1 Agentmetry: repaired missing failure event, but no observed pre-fix success

Original [PR #427](https://github.com/blitzcrieg1/agentmetry/pull/427) fixed a clear bug: a JSON-RPC `tools/call` result with boolean `isError:true` previously left the audit trail with only `tool_called`; the repaired proxy adds `tool_failed` with `outcome:error`.

- Original pre commit `773a5bc6e35f467b21967aff17e5737f2a1f8bc5`, original proxy blob `5654e78bb930a3aa25ac86573cbdecd53d918ea4`.
- Official repaired commit `ad2de9e44b37738879b7efb2ab862583b53ddd9e`, proxy blob `f6ce68be377a43891947653e670944474b9e5822`.
- **Original author's original regression suite: 17/17 passed after repair.** Applying the unchanged author's new selected test to the original pre-fix source produced one **expected failure** (`assert None is not None`), with 16 deselected. This is a genuine red/green original source repair, not a simulated copy of the fix.
- Independently, we executed both original versions' `_relay_stdout` with five native tool response shapes each, including true, false, missing, string `"true"` and numeric `1`; the original parser consumed the JSON-RPC message and emitted its own audit event.
- Original before true-error response: **no** `tool_failed` terminal event.
- Original after true-error response: **`tool_failed` / `outcome:error`**. No private tool-result text is leaked to audit event.
- All other false/missing/nonboolean flags intentionally produce no failure event under the author's explicit strict-boolean policy.

The frozen B38 checker **must not** call the before condition `APPLICATION_ERROR_AS_SUCCESS`: `tool_called` means the request started, not that the original consumer explicitly observed and reported successful completion. **Missing terminal evidence is INCOMPLETE**. The after branch provides a positive original error observation and is preserved.

This is both a meaningful independently authored repair and an important boundary of B38's *positive-evidence* conformance criterion. Future monitoring could define a separate **completion-obligation timeout or audit-state machine**, but that would be a new predeclared property to evaluate on B42, not a retroactive B41 positive.

Before/after native JSON SHA-256 `57991f5cf596adf3e01d4d04fa03603bd6f51369487af16ff470796d9228c813` / `4dda6d79174ceb054ab0e3be3abbc72a1ad2c4a26a07c35b098f1afeb6aa82ab`. B38 score `d80d5b728ba5934086afa3ebc8e5b1b4337fbe17f69a572f2799547b4591bfd7`.

## 5. Original normal-client FPR calculation (organization-level)

Preselected independent normal-client organizations: **2** (`N1`, `N2`).

- Actual original client code and native wire executed: **2/2**.
- Original clients with explicit original observed in-band error status eligible for this frozen checker: **1/2**.
- False-alarm organizations in the eligible sample: **0/1**.
- Descriptive Wilson 95% interval for 0/1: **[0, 0.793457]**.
- **Population false-positive rate: NOT ESTIMATED.** One eligible organization provides no useful assurance of low ecosystem FPR, and success + error scenarios inside the same organization are not independent draws.
- Positives: **1 official owner fix reproduced**, **0 independently counted new B38 generic detector hits**, because original before lacks an explicit successful terminal observation.

Never report `0/2`, `0/3`, `3/3 organizations`, “B38 detects all repairs,” or “low FPR proven.”

## 6. Separate, explicitly POST-EXPOSURE development exercise

Having already seen N1 behavior, we used the **same original client version** to assess whether future original-client tests can demand stronger preservation than status only. This was placed in a distinct workflow and **excluded from the independent holdout**.

[Mark3labs exact channel exploratory original-client workflow](https://github.com/risu-research/risu-probe/actions/runs/43636230662): two original client tool calls executed with an unmodified original B38 checker:

- `b41_structured_exact`: checked **status + text + structuredContent**, all preserved;
- `b41_media_exact`: checked **status + text + inline image-media digest**, all preserved.

The consumer's original `StructuredContent` and typed `ImageContent.Data` were separately observed, not copied from the native wire. Both tests passed. Score SHA-256 `f123443d42933828c5e087f5d25b1da108b77805131de15fdc2cc3649f7242e5`. **No increment** to normal-client denominator, because the original project had already been exposed.

## 7. Research decision and B42 direction

**Keep the public product unchanged.** B41 improved over B40 by producing the first *qualified* external normal native-client status sample for this line of testing, but its small eligible denominator does not justify a public low-FPR claim or sweeping detector expansion.

The valuable result is the three-way separation exposed by concrete, original external projects:

1. **Explicit correctness**: Mark3labs exposes native in-band status and the frozen checker verifies it.
2. **Unobservable status**: Metoro receives an in-band error on native wire but has no original return field that communicates that status; the checker must decline to score.
3. **Missing terminal outcome**: Agentmetry pre-fix emits no failure-completion event; the checker must not infer a successful completion from silence.

For **B42**, select another *new* source-disjoint group based on API-level executable ability to return `IsError` or an equivalent explicit tool-result status and an independently observable actual outcome. Do **not** select two normal clients that expose no status. To test missing audit events, predeclare a separate event-completion property and a bounded observation window, with normal request-only cases and independently authored status-as-success positive controls. Keep the exact B38 checker fixed until a new held-out set can support a change. A stronger follow-up should consider actual external consumer applications in addition to SDKs and report those layers separately.

All B41 cases are now **exposed development material**. They must not re-enter B42 as supposedly fresh holdout cases. No external collaboration required, and no user action is needed for the completed B41 branch.
