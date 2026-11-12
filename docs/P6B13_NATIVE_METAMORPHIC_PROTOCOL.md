# P6-B13 — Native MCP semantic-preservation discovery protocol

## Provenance and claim level

This is **new, separate qualification work** after P6-B12; the P6-B12 frozen five-server cohort and first-pass outputs are not edited. P6-B13 selects two previously unevaluated independent upstream publishers using their public documentation. The candidate set and exact immutable commits are recorded in `benchmarks/p6b13/prelocked_native_cases.json` **before running these original binaries**. Reading project docs and tool schemas is permitted; this is documentation-informed selection, not source-code-hidden discovery.

| ID | Native original | Source SHA | Local, independent oracle |
|---|---|---|---|
| FS2 | j0hanz/filesystem-mcp | ff783caf6191eb41f5a3de0e5f924dcc18f770ce | Files on disk; full vs head read; literal hit/miss, stat and listing |
| SQL2 | rusq/mcp-sqlite | 455a196ac2b2783f7a4250ba4ad6d736ddc6437b | Direct `sqlite3` query; literal vs bound SQL; Unicode and persisted mutation |

The targeted independent behaviors differ from B12's earlier 5-server cohort. All inputs live in a disposable per-job directory, files and databases use generated test-only values, and there are no calls to live sites or external MCP services. The source checkouts and dependency installs are pinned-public CI setup, and all actual MCP calls run against their unmodified compiled original native stdio servers, never SDK proxy substitutes.

## Methodology

1. Freeze the B12 core scanner `src/risu_mcp_trace.py` blob `9f017ca0344d94cf54bd0229ddb14d4f586101c8` and display fidelity `6785b2ed912d3e9a41dda956da537dc2e5f4f8e3`.
2. Pin two public upstream commits and their predeclared 13 selected tool invocations; no target selection after results are visible.
3. Build upstream originals in isolated CI, run MCP initialize / tools-list / tools-call, and capture the real process stdout byte-for-byte with SHA-256.
4. Independently judge declared test invariants against known files and local SQLite, and keep `MISMATCH_CANDIDATE`, `UNVERIFIED` and `PASS` distinct. Product warnings are reported separately.
5. A candidate requires independent replay (ideally a different MCP client), normal controls and source-level root-cause identification. Search public upstream issue and commit histories **before** calling it unknown or previously unreported. Do not open external issues or submit patches without reviewing the exact claim.

Every failure remains in the selected cohort denominator. CI success only means runnable and audited evidence, not that RISU discovered an unknown bug. The initial result will be recorded only after reviewing the actual CI result and artifacts.

## Reproduction

Run the `RISU P6-B13 locked native cross-publisher metamorphic discovery` Actions workflow on the isolated `qualification/p6b13-metamorphic-native-20261112` branch. It preserves captures and verdicts as separate named artifacts `risu-b13-frozen-original-FS2` and `risu-b13-frozen-original-SQL2`.

No release, PR, main merge, upstream report or default-branch change is authorized by this qualification experiment.