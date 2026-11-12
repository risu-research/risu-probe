# P6-B15 | Explicit MCP effect witnesses and result obligations

**2026-11-12. Product qualification complete on B14 development evidence.
Independent three-publisher heldout complete and cross-audited.**

## What the new product can actually verify

`risu-probe check-mcp-observations` is an **offline, opt-in** checker added to
RISU Probe's installed preview wheel. It consumes three local files:

1. **Original recorded MCP JSON-RPC JSONL** from an external source process.
2. A **strict explicit observation contract** that names the tool, argument
   selectors and expected behavior. There is no heuristic reading of words
   such as "error", "read-only", or "success".
3. An optional **independent state witness ledger**, bound to the raw trace
   SHA-256 and exact source request/response line numbers. The ledger records
   SHA-256 of canonicalized persistent state before and after each tool call.

Two rule families are supported:

- `state-unchanged` / `state-changed`: an independent persistent-state
  snapshot disagrees with an explicitly declared obligation.
  The mismatching report ID is **RME610**.
- `json-object`: the selected successful response must use either a single
  JSON text object or declared `structuredContent`, with required typed
  JSON paths. A malformed payload or type mismatch yields **RME620**.
  An explicitly errored MCP tool call abstains from the JSON-success check.

Missing state evidence, invalid SHA, missing response, ambiguous correlation,
unsupported carrier, duplicate JSON keys, or an unmatched rule must not turn
into a false certification. The tool distinguishes **PASS**, **MISMATCH** and
**UNVERIFIED**. Reports hash tool and rule identifiers and avoid exposing
the observed values. It does not run untrusted projects, contact servers or
attest the origin or honesty of the external witness file.

### How to run

```sh
python -m pip install .
risu-probe check-mcp-observations original_stdio.jsonl \
  --contract observation_contract.json \
  --witness state_witness.json \
  --format json --out result.json
```

Use `--fail-on-observed` to return status 1 for observations, and
`--strict-incomplete` to return 2 for unmatched/incomplete evaluations.
A rule file is needed even when using JSON result checks alone.

## Freeze before independent evaluation

**Development only**: P6-B14 retained exact original source stdout from
`43283214546`, including two meaningful mismatches in the small
`mekanixms/sqlite-mcp-server` sample and the correctly protected
`spences10/mcp-sqlite-tools` read-only comparator.

The original B14 replay confirmed that B15 detects:

| Evidence | Expected product outcome |
| --- | --- |
| B14 documented read-only query unexpectedly changes committed SQLite state | RME610 |
| B14 valid statistics request returned non-JSON failure prose as normal completion | RME620 |
| B14 state-unchanged protection and correct JSON output | Two PASS controls |

Both reports and witness bindings were produced from the original B14
immutable CI artifacts. They are **development regression results**,
not heldout detections. Three OS installed-wheel development run:
https://github.com/risu-research/risu-probe/actions/runs/43288608423

The checker was frozen before fresh upstream source inspection:

- Product blob `src/risu_mcp_observations.py`:
  `4314e9bf92e2ec75c421bab25eae3b43f1424a08`
- Original trace parser blob `src/risu_mcp_trace.py`:
  `9f017ca0344d94cf54bd0229ddb14d4f586101c8`
- Freeze registration commit: `be4e18f4057384d7b0bb302098fa9a563cf984a4`
- Frozen files:
  `benchmarks/p6b15/FROZEN_DETECTOR_BEFORE_HOLDOUT.json`.

## External heldout selected after the product freeze

Three previously unused owners, selected using public metadata and READMEs;
the source commits and the **14 exact tool calls** were preregistered before
implementation source inspection in
`benchmarks/p6b15/FROZEN_UNSEEN_ORIGINAL_SERVERS.json`
(commit `dd31fc4128b83bc05607a1ccab29210e3961c296`).

| Code owner and pinned original | Operations | Product first pass |
| --- | ---: | --- |
| `panasenco/mcp-sqlite` at `c5f46391520d9c8c5283249e5513788d4de698f7` | 4 | 3 pass, 1 contract mismatch |
| `zongmin-yu/sqlite-literature-management-fastmcp-mcp-server` at `a3ceee63a34ff99de3bcfd80e0c72bf439017f4e` | 5 | 5 pass |
| `fellowgeek/mcp-memory` at `a50a87708628d0822af439015503de47c35d7acc` | 5 | 5 pass |

First-pass real source CI:
https://github.com/risu-research/risu-probe/actions/runs/43290126061

**Original source result:** all 3 real stdio servers ran, 14/14 locked calls
completed and the frozen product independently checked 14/14 explicit
comparisons with 0 incomplete. It reported 1 mismatch under the
preregistered contract.

### Independent contract-authority adjudication

The sole frozen mismatch was caused by a **wrong test contract**.
The preregistered PA `sqlite_execute` UPDATE probe expected the database to
change because the high-level README mentioned arbitrary SQL.

The **original, same-session `tools/list`** description states instead that
this tool opens the database **read-only by default**, with write access
restricted to explicitly marked canned queries. The source originally
returned a read-only database refusal, `isError: true`, and the separate
SQLite observer verified no committed change.

So RISU correctly detected disagreement with the supplied contract, but
the *contract contradicted the actual advertised tool interface*.
The comparison must be excluded from any **upstream bug** count.
This is the most important validity lesson from B15.

The ZM read-query DDL rejection also returned `isError: true` and made no
database change, an independent second normal control. Source read-only
guards, legitimate writing and deleting, successful lookup and real SQLite
storage effects all behaved consistently in their selected calls.

Final adjudicated result:

- **14/14** original calls and wire-state pairings independently audited.
- **13/13** defensible contract obligations passed.
- **1/14** predeclared contract error identified with contemporaneous catalog
  evidence and reported separately.
- **0** independently confirmed previously unreported upstream behavior bugs.
- **2** normal MCP tool-error signaling controls validated.
- **0** unverified original native source deployments.

Independent audit with one-byte trace tampering correctly refused:
https://github.com/risu-research/risu-probe/actions/runs/43291142163

## What the numbers can and cannot mean

The product demonstrated its B14 **development-set** detection and a
three-publisher real-source **heldout agreement** under independently
observed persistent state. It has no demonstrated real-world recall
on previously unreported bugs in the heldout, since no ground-truth
positive defect was found there.

The apparent single heldout alert does **not** imply one defective server,
and blindly counting it as a false positive against the server would also
ignore that the checker correctly compared the supplied, incorrect rule.
The correct separate quantities are **contract-conditional accuracy** and
**contract validity**. This distinction is central to deploying the feature.

Independent state witnesses and trace SHA checks establish **internal
consistency of supplied evidence**. They do not independently certify that
a user-supplied witness came from genuine upstream code. This qualification
adds confidence through exact Git commit provenance, CI environment and
original source transcript, not self-attestation by the checker.

All data is synthetic and local; original upstream repositories were not
modified or sent bug reports. The main branch and all earlier benchmark
branches remain unchanged.

## Next highest-value investigation

Require **evidence of contract authority** in addition to evidence of
tool behavior. For example, cryptographically bind the contract to the
contemporaneous tool catalog and separately require a reviewed declaration
of permissions. Since free-text tool descriptions are ambiguous, do not
silently infer semantics from keywords.

After that, freeze the stricter contract-authority mechanism and test on
another previously unused set of independent organizations with positive
bug-bearing before/after versions and normal matched controls.

A productive research claim will come from **independent defect detection
under grounded contracts**, not an ever-larger number of inherited fixtures.
