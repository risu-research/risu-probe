# B37 post-first-look | Original upstream MCP client and runtime error semantics

**Result: an independently maintained project's ORIGINAL MCP client source was run at exact pre- and post-fix commits against the same controlled real JSON-RPC stdio server on Ubuntu, Windows and macOS. The original defect was reproduced, with error-to-success conversion in the buggy version and correct error propagation in the official repair. An independent-of-source STATIC analysis of the same bug had missed it (B37 sealed first look 0/7).**

## Strong, scoped evidence

- External upstream: [KitAgent official merged PR #14](https://github.com/zed123214/kitagent/pull/14).
- Exact before source: `zed123214/kitagent@33afd476312db30561f998c1d1dbb46fed9b835c`, original Git blob `a9e849ee577c1c415fca93b75104e32e72ce9adb`, `src/agent_runtime/core/mcp/client.py`.
- Exact after source: `zed123214/kitagent@ddbcca26231bbaef937b8a8823fc982a52f5c1c8`, original Git blob `e06486e1769a21278e7506933fd3f57ce8088302`.
- Git full commit IDs, original Git tree object IDs and raw original `git cat-file blob` bytes are checked before **executing the real third-party module**. Its code imports only Python standard-library modules. The rest of the third-party repository is never imported/executed.
- Server: a controlled first-party Python stdio producer implements real JSON-RPC 2.0 initialize, initialized-notification, tools/list and tools/call (MCP protocol 2024-11-05). No third-party original server, network endpoint, database, account or external credentials were involved.
- [Original upstream native stdio 3-OS run 43513309234](https://github.com/risu-research/risu-probe/actions/runs/43513309234), all 3 operating systems PASS.
- [Generic read-only wire-to-consumer evidence checker run 43513916615](https://github.com/risu-research/risu-probe/actions/runs/43513916615): **11** adversarial and normal tests plus full original upstream before/after replay **PASS** on Ubuntu, Windows and macOS. Each operating system's run artifact includes the *original native request/response JSONL*, original committed Git source metadata (but not the third-party source), the directly observed client outcomes, and an independent verifier classification.

## Observed status and behavior

| Controlled request | MCP original JSON-RPC message | Real original KitAgent pre-fix | Real original KitAgent post-fix |
|---|---|---|---|
| Normal tool call | `isError=false` + text | Returns text successfully | Returns same text successfully |
| Application failure with explanation | `isError=true` + `VALIDATION_FAILED` details | **Returns error text as successful tool result** | **Raises `McpToolError` with original details** |
| Application failure with empty explanation | `isError=true` + empty content | **Returns empty string as successful tool result** | **Raises `McpToolError` with a meaningful fallback** |
| Two text blocks | `isError=false`, two blocks | Preserves `first\nsecond` | Preserves `first\nsecond` |
| JSON-RPC error envelope | `error` with code `-32603` | Raises protocol error | Raises protocol error |
| Normal call after error | `isError=false` | Client still works | Client still works |

The generic checker, which **does not inspect upstream Python source**, validates that each wire request ID matches the response ID, each tool identity matches the claimed observation, the recorded original trace SHA-256 equals the raw JSONL bytes, and original error text is actually propagated or explicitly misclassified as success. It refuses false evidence where identities differ, JSON-RPC envelopes are malformed, a consumer output is invented, a trace is altered, or an `isError` field is not boolean. It distinguishes application-level errors from JSON-RPC errors, and avoids declaring complete content-channel preservation merely because the error status was preserved.

**Verifier result on each OS:** pre-fix 2 application errors as success, post-fix 0; post-fix 2 correctly propagated application errors; both pre/post 3 normal-success controls and 1 correctly preserved JSON-RPC error. No synthetic before/after values were substituted for the actual executed original KitAgent code.

## What is established, and what is not

This is a genuine original third-party **client** execution under controlled conditions, with a first-party synthetic MCP **server**. It is an experimental reproduction of an already fixed externally reported bug. It does **not** claim:
- independent remote original server execution;
- novel undisclosed vulnerability discovery;
- a software supply-chain/TEE proof of how the external third-party build was deployed;
- that Git SHA alone authenticates human approval;
- that passing 11 synthetic tests estimates a real-world false-positive rate;
- cross-language source static coverage beyond Python.

The evidence is collected by RISU's CI; cryptographic hashes preserve internal integrity but do not confer external human attestation. Different OS JSONL formatting can yield different SHA-256 without changing semantic classifications.

## Product and research lesson

The **first-look B37 source detector was 0/7**, while the new generic runtime witness correctly separated original error status from consumer handling on an **actual external, independently authored client**. This is the strongest positive B37 finding. A promising product design is an **opt-in protocol-to-consumer contract verifier** that takes native MCP wire evidence plus independently recorded consumer observation and reports exactly the channel/type/status discrepancy it can prove, with source analysis used only for later localization.

Further work requires more external upstream original clients from distinct authors, independently defined normal policies, untouched future **B38** holdout before any generalized detection algorithm changes, and careful design of provenance of consumer-observed outcomes. Do not infer overall recall or merge the experimental verifier into public `risu-probe/main` yet.

**Preservation:** this documentation and actual original replay tests are in the B37 native-original research branch. The sealed first-look [B37 report](https://github.com/risu-research/risu-probe/blob/qualification/p6b37-sealed-external-20261113/benchmarks/p6b37/RESULTS_AND_NEXT_DECISION.md) and its 0/7 source verdict remain immutable.
