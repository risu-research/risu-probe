# P6-B16 | Catalog-bound authority for MCP observation contracts

**Qualification date:** 2026-11-12  
**Branch:** `qualification/p6b16-catalog-bound-authority-20261112`  
**Main and all earlier qualification branches:** unchanged.

## Question

P6-B15 correctly compared an explicitly supplied state expectation against
independent SQLite or filesystem state, but one externally selected writer
expectation was wrong. The server's actual `tools/list` already described the
tool as read-only by default. The result was a legitimate *disagreement with
the submitted test contract*, not a new upstream defect.

P6-B16 asks a narrower question: **What evidence in the same captured MCP
session actually licenses promotion of a tool observation into a claimed
contract discrepancy?**

The result is an opt-in catalog authority gate, shipped as readable RISU
preview source, with a real `risu-probe` CLI command.

## Normative source basis

The MCP 2025-11-25 server tool specification states:

- `tools/list` enumerates the tool declarations for the session and is
  paginated; `notifications/tools/list_changed` invalidates older lists.
- Tool annotations (including `readOnlyHint`) are behavioral **hints**,
  and the specification says clients **MUST** consider annotations untrusted
  unless they originate from trusted servers.
- If a tool declares `outputSchema`, the server **MUST** return structured
  results conforming to it; clients **SHOULD** validate them.
- The optional `outputSchema` is a declaration about the
  `structuredContent` object, **not a requirement that arbitrary prose in
  `content[].text` be JSON**.

Official source: https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2025-11-25/server/tools.mdx

This makes the evidence grades intentionally asymmetric:

| Rule | Actual same-session catalog evidence | B16 disposition |
| --- | --- | --- |
| `json-object` + `structured-content` | Fully retrieved catalog with a simple outputSchema that directly entails every required path/type | `CATALOG_NORMATIVE`, qualified conditional observation |
| `state-unchanged` | `readOnlyHint: true` alone | `CATALOG_ADVISORY`, **never** a qualified defect |
| `state-changed` | `readOnlyHint: true` | `CONFLICT`, quarantine caller expectation |
| `state-changed` | Annotation absent or false | `UNVERIFIED`; the hint never promises a change |
| `json-object` + `single-text-json` | Advertised outputSchema | `UNVERIFIED`; structured schema cannot govern arbitrary text carrier |
| Any | No complete catalog, stale `list_changed`, cursor chain unfinished, duplicate advertised name or wrong tool | `UNVERIFIED`, quarantine mismatch |

B16 checks only conservatively supported JSON Schema types and directly
required paths; it refuses remote references, dynamic/compound schema
constructs and ambiguous required fields. **It does not claim to implement
general JSON Schema proof or to verify a server's identity.**

## Product implementation

New source `src/risu_mcp_authority.py` is installed through
`pyproject.toml` and routed by `src/risu_p5d_cli.py`.

```sh
python -m pip install .
risu-probe qualify-mcp-observations original_stdio.jsonl \
  --contract observation_contract.json \
  --witness state_witness.json \
  --format json --out authority-report.json
```

The existing B15 `check-mcp-observations` remains available and unchanged.
The new command reuses the same strict source parser, explicit contract
syntax and independently captured state witness format.

The B16 report preserves each matched observation as a separate record
containing:

- The underlying observation outcome (`PASS`, `MISMATCH` or `UNVERIFIED`).
- The contemporaneous catalog hash, complete-catalog line and selected tool
  descriptor hash, or a precise incompleteness reason.
- The evidence grade (`CATALOG_NORMATIVE`, `CATALOG_ADVISORY`,
  `CONFLICT` or `UNVERIFIED`).
- An explicit disposition: `QUALIFIED_MISMATCH`,
  `QUARANTINED_MISMATCH`, `QUALIFIED_PASS`, `ADVISORY_PASS`,
  `UNQUALIFIED_PASS` or `UNVERIFIED_OBSERVATION`.

**Qualified means qualified against the captured, advertised schema, not
cryptographically authenticated upstream misbehavior.** Even qualified
mismatches retain the origin label
`UNATTESTED_LOCAL_JSONRPC_CAPTURE_AND_LOCAL_WITNESSES`.
No subprocess, import of target code, schema network access, or leaking
values occurs in the checker.

`--fail-on-qualified` is an opt-in exit 1 gate for qualified mismatches;
`--strict-incomplete` returns 2 for incomplete authority or observations.

### Frozen source identity

Freeze committed **before** touching new external sources:

- `src/risu_mcp_authority.py` Git blob
  `be24472b0fea8d8e7a252a7a36158cf8873128de`.
- Unchanged B15 source
  `src/risu_mcp_observations.py` Git blob
  `4314e9bf92e2ec75c421bab25eae3b43f1424a08`.
- Unchanged generic MCP trace parser Git blob
  `9f017ca0344d94cf54bd0229ddb14d4f586101c8`.
- Frozen specification:
  `benchmarks/p6b16/FROZEN_AUTHORITY_BEFORE_NEW_SOURCES.json`.

All later CI checks assert the product-source blob hashes.

## Three-owner B15 development-control replay

Existing B15 originals and their source-native evidence were downloaded from
the **original successful firstpass** (43290126061), never fabricated:

https://github.com/risu-research/risu-probe/actions/runs/43294477328

- 3 external owners and all 14 source-native calls were correlated.
- The one B15 caller-contract mismatch on `panasenco/mcp-sqlite` was
  **quarantined**, not promoted to an upstream bug.
- B15 original outcomes remain visible and unchanged.
- These sources were already known during B16 development; **they are
  development-set evidence**, not independent positive defects.

## New independent-source interoperability cohort

The frozen classifier was then applied to **two previously unused upstream
owners**, selected after limited public source inspection. Selection was
source-informed, so this is **not blind bug discovery**.

Precommitted cohort:
`benchmarks/p6b16/FROZEN_NEW_ORIGINAL_SERVERS.json`,
commit `2441a0c706a36ab1247371cf1651c3217712eca0`.

| Upstream | Exact source commit | Real native stdio calls |
| --- | --- | ---: |
| `AI-Shell-Team/aish` features fixture | `c9ad99acac291dd3a7b38162b6159bf5b01a1ed9` | 5 |
| `MarvinRomson/master-mcp` search server | `75dc67c58e6468cdd81a6e5c3cb0a2f1521af93d` | 2 |

Both original subprocesses completed. The original `aish` fixture
advertised a valid structured-output schema, returned genuine structured
responses and sent `notifications/tools/list_changed` following a
real tool invocation.

**Original first-pass results:**

- Two structured output checks had `CATALOG_NORMATIVE` support and passed.
- One read-only annotation produced a `CATALOG_ADVISORY` pass.
- One structured call, made after `list_changed` and before refreshing
  `tools/list`, was **not promoted** under the stale catalog.
- The refresh produced a new complete-catalog SHA and renewed qualification.
- The independent search server yielded two correct state observations
  without unsupported authoritative claims.
- **Seven original calls**, **zero real-source mismatches**, **zero reported new
  upstream bugs**.

Real native source CI:
https://github.com/risu-research/risu-probe/actions/runs/43295550845

The `aish` source is explicitly a **fixture server maintained by an
independent development organization**. This is valuable interoperability
evidence, not proof of industrial prevalence.

## Frozen-rule postfreeze sensitivity check

Only **after** the original third-party responses were saved, a separate
offline fixture mutator changed the type of precisely one field in one
original MCP tool response per case:

1. Before catalog invalidation, a changed `count` integer was classified
   as `QUALIFIED_MISMATCH`.
2. After `list_changed`, before a new catalog, the same changed field was
   classified as `QUARANTINED_MISMATCH`.
3. After a complete catalog refresh, the changed field was again classified
   as `QUALIFIED_MISMATCH`.

**These three are synthetic mutations, not real upstream defects.**
Independent audit verified that each mutation altered precisely one declared
result field and preserved all other original wire messages. It also
verified original seven-call source records, SHA-256, catalog timing,
normal controls and normal source behavior. Deliberately tampered original
bytes with unchanged witness hashes were rejected.

Independent audit:
https://github.com/risu-research/risu-probe/actions/runs/43296125914

## Research contribution and limitations

B16 separates three questions that simpler static checks collapse:

1. **What happened?** The raw tool response or independent persisted state
   is bound to one exact JSON-RPC invocation.
2. **What did the server actually advertise at that time?** The relevant
   version of the complete, in-band catalog is bound to the request.
3. **What is the assertion's authority?** Machine-readable outputSchema
   supports a narrow normative result obligation; read-only hints and
   caller-supplied human-language promises do not.

Result: the prior incorrect caller-contract alert is still auditable but no
longer promoted, and legitimate in-band structured output obligations can be
checked in an independently captured original server process.

**Boundaries:** Catalog SHA is an integrity tie *within user-supplied bytes*,
not proof of server identity or external code revision. There is no
cryptographic origin attestation, no independent third-party trusted policy
review, and no demonstrated discovery of a previously unseen real-world
positive bug. Sampling two source-informed owners cannot estimate population
recall or false-positive rate. A deliberate typed mismatch in a modified
capture proves a narrow unit capability, not an externally discovered bug.

## Highest-value next step: B17

Make contract authority *independently reviewable* beyond the supplied
transcript: signed or separately fetched, pinned publisher documentation,
tool-version provenance, explicit source-controlled policy, and caller
authorization for risk-bearing side effects. Avoid automatic semantic
assumptions from free text, untrusted annotations or the mere absence of a
permission check.

Then evaluate a genuine before-fix / after-fix bug in **another publisher
not inspected during B16**. Freeze the rule before looking at the heldout
first-pass output; include both fixed normal controls and real source-state
witnesses. The scientific target is actual new defect-finding ability,
not a larger inventory of synthetic failures.
