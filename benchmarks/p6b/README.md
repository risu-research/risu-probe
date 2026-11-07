# P6-B public upstream defect detection

The first benchmark uses **real, immutable public Git sources** and Git blob SHA-1 checks. The Git object SHA references are in [cases.json](cases.json). External source files are **never imported or executed** by RISU. The installed 0.9.20 wheel (pinned main baseline) and proposed 0.9.21 wheel scan the same original upstream source bytes.

| Public case | Ground truth | Scoring |
|---|---|---|
| FastMCP #5030, merged #5063 | Schema-bearing serialization exception silently falls back to content-only response | One *development* defect / fixed pair; new RPY204 was written with this case in mind |
| FastMCP #3717, merged #3756 | ResponseLimitingMiddleware caused a client-side output schema error | Holdout defect / merged fix pair; the fix bypasses client validation via meta, **not** a promise to keep structured output |
| LangChain #40471 | Structured error payload not retained in ToolMessage artifact | Open issue, no official merged repair. PR #41566 was closed without merge |
| MCP TypeScript SDK #2614 | Metadata cache mutation on invalid schema | Out of scope for Python-only source scanner; explicit abstention |
| Requests sessions.py | Unlabeled background source | Not a validated clean control; excluded from false-positive denominator |

**Detection:** a finding counts only if its rule ID targets the known public defect and appears on the fixed original affected source. **False alarms:** the same issue-specific rule fired on an officially merged repaired version. Generic warnings cannot substitute for defect detection. Unsupported and unlabeled examples are excluded from both recall and specificity.

The *first iteration is in-sample*: FastMCP #5030 informed RPY204. Detecting that example is not independent generalization. Missed bugs are retained in the result. Static findings remain hypotheses, even when a separate public issue documents the defect. No third-party project is executed in this benchmark. No general ecosystem recall, production incident, unpublished vulnerability or hidden-data claim.

Reproduce using the read-only [public benchmark CI](../../.github/workflows/p6b-public-defect-benchmark.yml). It installs the pinned baseline and candidate wheel separately, fetches public Git objects during a trusted branch push only, checks every blob SHA, and independently recomputes scored metrics. PRs run only bounded, no-secret wheel tests.
