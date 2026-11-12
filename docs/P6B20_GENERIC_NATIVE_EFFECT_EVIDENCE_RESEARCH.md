# P6-B20 | A tool-neutral effect differential for original MCP execution

**Status:** source-frozen generic engine, signed B19 development positive, original unrelated publisher's native filesystem holdout and independent repeat all passed (2026-11-12).

**Research branch:** `qualification/p6b20-generic-effect-boundaries-20261112`  
**Frozen kernel:** `src/risu_mcp_effects.py`, Git blob SHA-1 `ab8191a3ca153ac079fcd07d128ddfcd7a06e99f`.  
**Prior B19 frozen product:** Git blob `41bb9439174c37a53481db3e025cb9601ae6040f`, unchanged.  
**Previous main:** unchanged.

## Research problem

The original verified B19 security repair established a concrete observation:
all four legitimate `git_status` tool responses were byte-equivalent after
canonical JSON normalization, while the old upstream signed package executed
an unintended program on exactly one controlled repository-local setting.
The fixed vendor-signed package suppressed that hidden side effect without
impairing the tool's successful result.

A rule hardcoded to `git_status`, `core.fsmonitor`, an advisory identifier or
the chosen release cannot test whether RISU has a reusable method. Therefore
B20 **converts the B19 evidence into a developer-only positive control**
and tests a different effect domain under the same frozen comparator
with another publisher's actual unmodified MCP server.

## Method: generic typed effect matrix

The **generic engine knows nothing about repository names, Git operations,
vulnerabilities, permitted paths, file writers or SQL tables**. The analyst
supplies a bounded four-case plan:

| | Trigger fixture | Matched normal control |
| --- | --- | --- |
| Baseline (`before`) | `before_trigger` | `before_control` |
| Candidate (`after`) | `after_trigger` | `after_control` |

For each `case`, the input includes:

1. Exact original native MCP JSON-RPC request and result bytes.
2. A complete, stable original `tools/list` snapshot captured before the call.
3. A single successful tool invocation, with argument hash and result hash.
4. A separate original observer JSON record for before/after state.
5. The observer source file's SHA-256, exact **JSON pointers** to the
   original values, and their strict typed copies in the episode record.

For sensor `s` and cell `c` define

`D(s,c) := [before_state(s,c) != after_state(s,c)]`

only when both values have the exact predeclared type and the original
witness file, case ID, raw MCP trace SHA and original call all corroborate.

Three typed sensor classes are supported:
`boolean` (existence or flag change), `digest` (sha256 or missing) and
`counter` (bounded nonnegative integer).

The analyst declares the **complete truth table before independent
evaluation**, choosing one of:

- `suppressed-in-after-with-controls-stable`: `[1,0,0,0]`
- `preserved-in-both-trigger-cases`: `[1,0,1,0]`
- `no-effect-in-any-case`: `[0,0,0,0]`
- `custom`: exact four boolean values for each of the four cells

The engine computes whether every sensor satisfies its predeclared
pattern and records all mismatches. It **does not assume that a
readOnlyHint authorizes a state policy**, that an observed change is an
illegal change, or that a successful tool response proves an absence
of additional hidden effects.

An orthogonal result property is computed:

`R := [SHA256(canonical(MCP_tool_result(c))) is identical for all four cells]`

When `R` holds and the predeclared `[1,0,0,0]` effect suppression pattern
is observed, the report records a **response-only observability gap**.
This conclusion is about the specified observed sensor and explicit
fixture scope, not every possible effect of the executable.

## Threat model and fail-closed design

The engine is offline, imports only bounded RISU parsers and standard
Python, and **never executes an external MCP target**. The CI harnesses
make isolated native calls separately.

It rejects:

- Missing, oversized, symlinked or escaping witness files.
- Changed original source witness SHA-256 or mismatched typed JSON pointers.
- Duplicate sensors, incomplete cell coverage or original evidence reuse
  across different cells.
- Missing/incomplete/stale/ambiguous `tools/list` catalogs.
- No matching native `tools/call`, multiple calls, JSON-RPC errors or
  tool-level errors.
- Mismatched original tool, arguments SHA, response SHA, request/response
  line numbers, or whole-trace SHA.
- Wrong typed values, unsupported kinds and unknown dataset roles.

**Trust boundary:** An original side-effect witness file and captured
stdio, even when internally hash-consistent, can be fabricated by an
untrusted recorder. B20 labels its observation sources
`CI_OBSERVED_NOT_REMOTELY_ATTESTED` or
`DECLARED_LOCAL_OBSERVATION`. Actual publisher origin and genuine
execution require separate, auditable processes. The B19 source-positive
already has an independently verified upstream PyPI publisher attestation;
the new filesystem holdout is a byte-corroborated original PyPI package
**without any asserted publisher cryptographic signature**.

The engine models **changes, not direction**: a `false -> true` and a
`true -> false` transition both have `D=1`. Original witness values
remain available for independent directional verification, but this
version of the generic kernel does not yet infer an effect's direction,
authorization, causal responsibility or an external program's identity.
An observed `counter` change similarly is not inherently an increase.
Those limitations are explicit future work.

## Experiment A: signed B19 upstream repair, developer positive

The original **external upstream signed and already public** B19
security fix `GHSA-6hqx-gqrx-c5r2` was carried over intact:

- Upstream: `modelcontextprotocol/servers`.
- Vulnerable signed official PyPI wheel: `mcp-server-git==2026.11.4`.
- Fixed signed official PyPI wheel: `mcp-server-git==2026.11.11`.
- Four original native `git_status` cases.
- Independent observer of a controlled benign file marker.
- Source and release proven by B19's official PEP-740 PyPI publish
  signatures, exact wheel/source-byte comparison and native stdio.

**No original server executed again or was patched for this development
control.** B20 copied the untouched original B19 raw stdout and original
side-effect witness files, then emitted JSON pointers and hashes into
the new generic observation format.

Product report:

`[before_trigger, before_control, after_trigger, after_control] = [1,0,0,0]`

- Predeclared generic effect suppression: **PASS (1/1 sensors)**
- Original MCP tool result bodies equivalent across four cells: **YES**
- Response-only observability gap: **YES**
- New upstream defects discovered: **0**

CI: https://github.com/risu-research/risu-probe/actions/runs/43321811071

This is a **known-bug development example** and is expressly excluded
from the independent evaluation denominator.

## Experiment B: separate publisher, real non-Git source

A genuinely separate original developer organization was selected after
the effect algorithm blob `ab8191a3...` was frozen:

- New publisher: `kujirahand/mcp_server-filesystem`.
- Exact original source commit:
  `1aff1e094ed317ec2c5de06591978781d660c48a`.
- Original server module Git blob:
  `f886fcbc6e61f3be8e6fd76b6e5f3ad1f8cbb7b6`.
- Published PyPI package:
  `filesystem-mcp==1.0.2`.
- Exact original wheel SHA-256:
  `94610f0b73df1d3ada4ef0353353eb93695645c7b82f71ca80ed13dc1022c235`.
- Exact source module SHA-256:
  `c754a7720d52d92eb49324649b19f58b07b20703fcc2c2c1b02ce1f20152fcc8`.

The original wheel's `filesystem_mcp/server.py` bytes were independently
matched to the pinned original GitHub source and installed virtualenv
module. The target was **never modified**. The exact tool and effect
pattern were precommitted in
`benchmarks/p6b20/FROZEN_FS_HELDOUT_PLAN.json` before the original
native external requests.

The original tool is **`write_file`**, entirely unrelated to
`git_status`, and takes a synthetic safe file path under a temp allowed
directory.

**Important:** Here the `before` and `after` matrix columns mean
**two independent replicas of the same version 1.0.2**, not a software
fix or release comparison. The claim is generalization of the effect
evidence architecture across actual tool semantics, **not a new upstream
security repair or a new bug**.

Each pair has a *trigger* fixture where a new file is written and a
*normal-control* fixture where the already-identical file contents
are written again. All four original tools succeed, and a separate
parent-process observer stores the actual before/after file bytes
outside the MCP response.

| Cell | File existence | Content SHA-256 | Byte-count |
| --- | --- | --- | --- |
| before_trigger | changed | changed | changed |
| before_control | same | same | same |
| after_trigger | changed | changed | changed |
| after_control | same | same | same |

Exact original content: `RISU B20 safe synthetic write\n`.

Expected post-file SHA-256:
`d3b04e4474fb01e8dc6e2fae80f75f79f2edc6d542acd7853440e75eb60735ae`.

**Frozen B20 generic product results:**

- **3/3 independent sensor types** matched their specified
  `preserved-in-both-trigger-cases` truth table.
- All 4 native original MCP calls succeeded.
- Original tool response bodies are **not identical** across cases,
  as randomized workspace paths differ. The engine still correctly
  recognizes the effects without relying on response equality.
- No upstream behavior defect was detected or claimed.

Primary original external run:
https://github.com/risu-research/risu-probe/actions/runs/43322280437

## Independent other-publisher rerun and audit

A **new independent GitHub runner** re-downloaded the publisher's
pinned GitHub source object, verified the original PyPI wheel code
byte-for-byte, reinstalled the exact release in a new isolated Python
virtualenv, and executed all four original `write_file` calls
again under new temp roots and native processes.

Its independent auditor
`benchmarks/p6b20/independent_non_git_effect_audit.py`
**does not import the RISU effect product**. It reparses the raw original
stdio, recomputes original server wheel/source Git object hashes and
actual stored file content bytes, compares the eight original
before/after snapshots per run, and verifies the independent 2x2 truth table.

Both independent external runs yielded identical **three-sensor
truth tables**, all matched by the original frozen B20 checker.
Synthetic postfreeze changes to the captured file bytes and the
original observer JSON were independently rejected.

Second original external run:
https://github.com/risu-research/risu-probe/actions/runs/43322884796

This is a source-informed **other-publisher normal-functionality
holdout**, not blinded independent discovery. Source selection
was intentionally tailored to a different effect family; only the
**generalized product and sensor-plan semantics were frozen** before
the original source execution.

## Cross-platform software regression

The complete installed RISU preview wheel and all historical tests,
including 32 new adversarial B20 effect tests, passed:

**381 tests on Ubuntu, 381 on Windows, 381 on macOS.**

https://github.com/risu-research/risu-probe/actions/runs/43321190922

The operational harness needed two setup corrections before successful
other-publisher evaluation. The first run had not installed the RISU
observer into the parent test harness. The second mistakenly resolved
the virtualenv's `bin/python` symlink to its host interpreter; the
unmodified external package could not load. The fixes changed only
harness environment and additional before/after byte archiving. The
frozen effect algorithm blob and original held-out plan stayed unchanged;
earlier failed run logs were preserved publicly.

## What B20 supports and what it does not

B20 supports a **tool-neutral method for connecting a native MCP call to
typed, independently recorded state transitions**, and matching a
predeclared 2x2 effect pattern under normal controls. It preserves
the actual source evidence chain, including the distinction between
in-band result and external effect, and transfers from B19's known
publisher-signed hidden program invocation to a distinct developer's
unmodified real file writer.

B20 cannot claim a new vulnerability, a population defect rate,
general source authority over side effects, remote cryptographic
attestation of a sensor, or state-causal proof in environments with
uncontrolled concurrent writers. All four holdout cases are normal
operations of a single upstream version. Three file sensors measure
**different properties of the same file**, not three independent
sources or randomly selected unrelated vendors.

**Next highest-value step:** Direction-aware typed transition contracts,
independent event/provenance collectors and a new precommitted external
fixed/defective pair from an entirely different developer. That would
test real defect detection transfer, rather than only normal effect
measurement transfer. Keep B19 permanently a development positive
and this B20 non-Git cohort an independent *functionality* control.
