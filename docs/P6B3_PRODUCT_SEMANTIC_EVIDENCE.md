# P6-B3: Product-native MCP semantic verification from pinned SDK replay

This experimental `0.9.22.dev0` step makes RISU Probe itself inspect the **public P6-B2 released MCP SDK saved replay** instead of requiring a separate research auditor to interpret it.

It distinguishes three genuinely different claims:

| Stage | What it proves | What it does not prove |
|---|---|---|
| `risu-probe check .` | Python/OpenAPI source parsed and static rules ran | MCP runtime or semantic correctness |
| `risu-probe verify-mcp --old ... --fixed ...` | Saved, **known-hash** SDK 2.0.0 vs 2.1.0 runs support two concrete problem-specific contrasts | Current production server defect; external stdio wire capture |
| Future explicit active MCP checks | Would require explicit, isolated execution and real protocol recording | **Not implemented by this step** |

## Commands

```sh
risu-probe check . --format json
risu-probe verify-mcp --old tests/fixtures/sdk_old.json --fixed tests/fixtures/sdk_fixed.json --format json
risu-probe verify-mcp --old tests/fixtures/sdk_old.json --fixed tests/fixtures/sdk_fixed.json --fail-on-confirmed
risu-probe check . --mcp-sdk-old tests/fixtures/sdk_old.json --mcp-sdk-fixed tests/fixtures/sdk_fixed.json --format sarif
```

Two new rules are scoped **only to the pinned public synthetic replay**:

- `RMC401`: MCP 2025-11-25 legacy validator rejects otherwise valid boolean property sub-schemas (Python SDK [#3353](https://github.com/modelcontextprotocol/python-sdk/issues/3353)); old `mcp==2.0.0` validator rejected, fixed `mcp==2.1.0` accepted, 2026-07-28 positive control accepted in both.
- `RMC402`: recursive output type breaks legacy MCP `tools/list` and hides the catalog (Python SDK [#3337](https://github.com/modelcontextprotocol/python-sdk/issues/3337)); old failed, fixed listed `tree` and `heartbeat` and called `tree` through real official SDK **in-memory JSON-RPC**.

The serialized original CI results are in `tests/fixtures` and cryptographically pinned by known SHA-256 values in `src/risu_mcp_replay.py`, originating from [public GitHub Actions #42342027675](https://github.com/risu-research/risu-probe/actions/runs/42342027675). This proves only that the exact replay files are the ones from that recorded public CI artifact; a file hash by itself is not a digital signature proving an execution environment. The source P6-B2 runner, framework versions, original commits and public CI should be inspected independently.

**Unpinned user-authored JSON, even when apparently consistent, is `UNATTESTED_SELF_REPORTED_JSON`. It never becomes a confirmed finding or triggers `--fail-on-confirmed`.** Malformed/contradictory JSON gets exit 2. Empty/missing capture yields no fabricated results. CLI text, JSON and SARIF all express the evidence boundary.

No client source code or third-party checkout is imported or run. No HTTP requests, secrets, customer records, live MCP connections, or LLM calls occur. Ordinary public PRs use read-only GitHub token, never invoke privileged workflows.

**Important test split:** P6-B2 independent static detection was 0/2 holdout issues. P6-B3's two product-native saved-replay classifications do **not** retroactively change that score or establish independent generalization. Other unknown SDK defects remain unverified and P6-C is still separate future work.
