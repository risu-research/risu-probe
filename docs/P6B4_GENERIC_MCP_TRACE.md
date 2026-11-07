# P6-B4 | Generic saved MCP JSON-RPC semantic verification

**Status:** public-only experimental product qualification. Previous P6-B2 independent static detection 0/2 remains unchanged; P6-B3 exact fixed-SDK replay checks remain available. P6-B4 adds a generic, offline **capture observation** verifier with no pre-coded issue IDs, no product-code execution, and no online MCP connectivity.

## Installation and first use

```sh
python -m pip install .
risu-probe verify-mcp-trace ./captured-mcp.jsonl --protocol-version 2025-11-25 --format json
risu-probe check . --mcp-trace ./captured-mcp.jsonl --mcp-protocol-version 2025-11-25 --format json
```

The CLI supports JSON, text and SARIF. Existing files are never overwritten; `--fail-on-observed` returns 1 on observed recorded mismatches, and `--strict-incomplete` returns 2 if the semantic check is incomplete. **Neither means a live server was authenticated.** `--fail-on-confirmed` remains separate for P6-B3 pinned verified public CI replay. A record of a tool error (`isError=true`) is not automatically a schema defect.

## Supported raw format and causal checks

Supply one JSON-RPC 2.0 message per UTF-8 line. A direct line is allowed:

```json
{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}
```

An optional capture wrapper can add a session ID:

```json
{"session":"demo","direction":"client_to_server","message":{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"sample","arguments":{}}}}
```

The verifier correlates request/response IDs **within each session**, requires a complete `tools/list` before tool use, handles tool-list-change invalidation, ignores completed unrelated JSON-RPC request pairs and separately reports malformed/incomplete conversations. It does not infer missing captures from an untrusted filename or from tool output text. It checks only **successful complete** `tools/call` results for declared output schemas. Protocol errors and `isError=true` tool results are counted as out of scope for successful output contract checks, not as defects.

| Code | Recorded discrepancy | Conditions |
|---|---|---|
| `RMC501` | Missing structured result | Successful complete tool call with declared `outputSchema` |
| `RMC502` | Structured result does not satisfy schema | Valid supported Draft 2020-12 schema and actual `structuredContent` value |
| `RMC503` | Invalid declared output schema | Observed tool call with malformed or invalid declared schema |
| `RMC504` | Legacy schema root not object | Only when declared protocol `2025-11-25` and declared output schema lacks object root |

Incomplete catalogs, unpaired records, absent `outputSchema`, protocol-level errors, dynamic/remote refs, expensive regular-expression schema keywords and unsupported dialects yield **UNVERIFIED**, not a confident pass. The default protocol is `unknown` and a manually supplied version is an **unattested assertion**. Parser and validator limits are conservative: 4 MiB trace, at most 4096 lines, max 512 KiB per message, bounded JSON graph and schema recursion. The verifier never fetches `$ref`, connects to endpoints, imports project modules, loads plugins, or executes the recorded content.

The tool uses `jsonschema`'s Draft 2020-12 validator. It explicitly abstains on `format` assertion, dynamic refs, regex-based schema expressions, remote refs and unsupported dialects. Supported local `#/$defs/` references include recursive schemas within resource bounds. JSON Schema conformance does not cover business-logic semantics, natural-language content, authorization, destructive tool safety, source HTTP parity, or unrecorded behavior.

## Evidence and claim boundaries

`capture_status=PARSED_BOUNDED_JSONRPC` means the **record syntax** was accepted. It is not proof that the capture is complete or genuinely recorded from a running server. `semantic_verification` reflects what can be inferred from matched, untrusted messages. `origin_integrity=UNATTESTED_LOCAL_CAPTURE` applies even when an exact SHA-256 of the file is reported: a digest shows file identity, not authenticated provenance. The result intentionally avoids echoing full source payloads or structured content values.

P6-B4 has two separate protocol evidence controls. First it invokes **actual official MCP SDK 2.1.0 client/server calls in-memory** and normalizes observed SDK objects into JSON-RPC-shaped records; these are **not literal wire bytes**. Second, an official SDK 2.1.0 server is launched as a **separate, local stdio process** and an independently implemented test client writes real JSON-RPC requests and preserves the server's byte-exact JSON-RPC responses. The raw public fixture and separate audit files are saved with the CI artifacts. Both controls use only synthetic values. The negative cases in both tests are **explicitly injected mutations of the observed normal records**, not genuine upstream bugs or live-user failures. The CI uses only public packages, synthetic non-sensitive data, no third-party production endpoint, and read-only repository permissions. Heavy SDK replays are excluded from external PR jobs.

## Ideas reused, but claims scoped

- **Ruff:** stable `RMC50x` rule IDs, direct CLI, per-rule tests, SARIF, no silent change of prior `check` semantics.
- **Schemathesis:** positive and negative controlled examples, bounded replay, independent expected verdicts and explicit unverified status.
- **oasdiff / mcpdiff:** version and tool-name scoped contracts, but no claim that a raw JSON-RPC trace matches their API/OpenAPI or schema-diff capabilities.
- **MCP Inspector:** ingest its exported JSON-RPC messages when formatted into this JSONL contract; no GUI or inspector server is recreated.
- **Renovate:** reviewed, opt-in CI failure, no automatic code modification or PR creation.

## Future qualification gates

1. Extend bounded schema support and multi-page tool discovery without changing the secure abstention rule.
2. Evaluate unseen public defect/fix pairs frozen **before** introducing further detector rules. Existing two SDK benchmark defects used in designing P6-B3 are development cases, not holdout scores.
3. Keep the original P6-B2 0/2 static detection measurement untouched.
4. Add imported official Inspector/SDK capture conversion, while retaining source/transport provenance and any uncertainty.

Protocol reference: https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2025-11-25/server/tools.mdx and https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/schema/2026-07-28/schema.json .
