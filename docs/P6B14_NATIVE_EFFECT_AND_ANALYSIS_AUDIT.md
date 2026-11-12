# P6-B14 | Native MCP effect witnesses and independent failure adjudication

Status: **source-first experiment and postfreeze reproduction complete** (2026-11-12).
Branch: `qualification/p6b14-native-effect-witness-20261112`.
The default `main` branch and earlier frozen P6-B7 through P6-B13 measurements remain unchanged.

## What changed in the evaluation

B12 and B13 showed that an analyzer can have zero findings even when external semantic
contracts deserve scrutiny. B14 preregisters two separate external original stdio
servers, preserves their original JSON-RPC bytes, and measures committed SQLite
logical state before and after each tool invocation. A reported success string alone
is insufficient to infer whether state changed.

The source selection was documentation-informed **and source-inspected**.
Consequently this is a prospective, frozen **source-informed** experiment, *not*
an untouched blind survey. The source/manifest was committed before execution:
`benchmarks/p6b14/prelocked_native_effect_cohort.json`,
commit `69e6fbcc9b321fc30f10429fed5c106f4b30fec6`.

### Locked denominator and original source

| Cohort | Original upstream | Frozen source | Original calls |
| --- | --- | --- | ---: |
| SP | [spences10/mcp-sqlite-tools](https://github.com/spences10/mcp-sqlite-tools) | `a6a6f196b315b11e17929aeeb274821f5a0e6ed0` | 6 |
| ME | [mekanixms/sqlite-mcp-server](https://github.com/mekanixms/sqlite-mcp-server) | `05191e95d1ca74f7c26312ae071f5fab42c19601` | 6 |

All calls use synthetic SQLite rows in an isolated, disposable CI workspace.
The 12 calls, independent per-call database oracle, output checks and source
commit pins are recorded before observing the final outcome.

## Frozen source-first result

Original successful first-pass GitHub run:
https://github.com/risu-research/risu-probe/actions/runs/43283214546

1. SP: **four independent oracle checks passed**, zero unverified. When its
   `execute_read_query` was asked to issue a data-changing statement, it
   returned an MCP tool execution error (`isError: true`) and committed SQLite
   state was unchanged. Limit/offset and a bound Unicode argument also passed.
2. ME: **three independent oracles passed and one failed**, zero unverified.
   The README calls `query` read-only. A predeclared `UPDATE` sent to
   `query` changed committed SQLite row 1 from `RISU_B14_ONE` to
   `RISU_B14_WRONG_PATH`, while MCP returned `isError: false` and stated
   one row was affected. A separately predeclared `update_data` operation
   correctly changed a different row, serving as a successful write control.
3. A **separate, unexpected failure appeared within the predeclared**
   `analyze_table` call. The upstream server returned the text
   `Error analyzing table: Object of type int64 is not JSON serializable`
   while setting `isError: false`. This symptom was *observed* in the
   first-pass transcript, but its root-cause-specific test was developed
   **afterward** and cannot be counted as a preregistered detector success.
4. The previously frozen RISU core analyzer returned **zero findings**
   for both source runs. The ME mismatches were discovered by the separate
   independent SQLite state oracle and review of the actual MCP result. These
   must not be attributed to RISU's automatic detection capability.

## Postfreeze confirmation and independent positive controls

Native upstream server, same frozen source, clean pinned SDK v1.30.0 and
pandas v2.2.3, executed independently under Python 3.11 and Python 3.12:
https://github.com/risu-research/risu-probe/actions/runs/43283834458

- Text-only two-row table, `analyze_table(..., "basic")`: valid statistics JSON.
- Real-valued two-row table, same tool: valid statistics JSON.
- Integer-containing two-row table, same tool, **repeated twice**:
  `int64` JSON serialization failure both times.
- In the two failing runs `isError` remained `false`, so consumers that
  trust only the MCP error flag may interpret a failed analysis as success.

This isolates the data-type boundary. The upstream function computes pandas
numeric aggregates and calls Python `json.dumps` directly on values that can
include NumPy integer scalars. A sound correction would normalize NumPy
scalar values before serialization, and communicate execution failures via
the MCP error mechanism instead of a normal string result. Proposed correction
is a hypothesis; upstream behavior after an actual fix has **not** been tested.

## Immutable cross-artifact audit

https://github.com/risu-research/risu-probe/actions/runs/43284381362

The cross-audit independently:
- Fetched **the original first-pass evidence**, rather than rerunning the
  cohort with the new inspection code.
- Verified every source SHA, all 12 tool calls, original JSON-RPC requests
  and responses, origin hash, frozen RISU results and first-pass scores.
- Independently checked the normal SP read-only control, ME changed DB
  state, ME positive writer control, and anomalous `analyze_table` response.
- Verified both postfreeze original-server reproductions and their hashes.
- Deliberately modified one byte of a copy of the original ME trace;
  the audit correctly rejected it as a hash mismatch.

The original observation and later diagnosis have **separate runs and hashes**.

## Scope and novelty boundaries

- The `query` issue is best characterized as a **documented behavior
  mismatch**. The MCP `readOnlyHint` metadata is advisory. This work has
  **not** verified that ME advertised an incorrect MCP `readOnlyHint`, and
  should not allege an MCP protocol violation on that basis.
- The `analyze_table` failure is a reproducible runtime defect for normal
  integer-containing fixtures in the frozen upstream version, plus a
  misleading success flag. It was reproduced on two Python runtimes.
- The upstream GitHub issue/PR lists and targeted issue search contained no
  matching existing report as checked 2026-11-12; that is **not proof of
  global novelty** or industrial prevalence. No upstream issue was opened.
- The upstream repository was last pushed in February 2025. It is a small,
  older codebase; the result does not establish incidence among actively
  maintained MCP infrastructure.
- This cohort is two nonrandom projects, selected after some source inspection.
  It does not support ecosystem-wide recall, sensitivity, specificity, or
  zero false-positive claims. No application/user data was touched.

## Why this matters for RISU Probe

The most consequential gap is the difference between a tool reporting
successful completion and the observed effect or usable result. It is possible
for a source-native tool to commit a state change and call it successful
despite conflicting user-facing documentation; an unrelated tool can fail
to produce its promised analysis while marking the MCP call successful.

Next: develop a **general opt-in, evidence-graded effect/result contract**
that takes actual independent state witnesses and machine-checkable result
obligations, not heuristics based only on the word "Error". Freeze the
general rule before testing against **new independent external projects**
that were not used in B14 development. Keep original stdio and source
fingerprints. Evaluate false positives with natural error prose and valid
summaries before claiming any independent discovery capability.

B14 is a qualifying research result; the current RISU detector did not
automatically detect the unexpected analysis failure.
