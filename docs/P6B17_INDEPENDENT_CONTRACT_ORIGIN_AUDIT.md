# P6-B17 | Independent origin of an MCP tool contract

**Status:** Product and external source-origin qualification complete, 2026-11-12.  
**Research branch:** `qualification/p6b17-independent-source-provenance-20261112`  
**Base:** P6-B16 at `b5a50263f401d06e4260268ed897ac24ab7a700f`. The existing main branch and prior qualifications are unchanged.

## Research question

A tool's live `tools/list` is part of the same endpoint's claim. If the
server is faulty, the same server can advertise the wrong schema. P6-B16
correctly withheld unqualified authority from caller-made rules and
untrusted `readOnlyHint`, but still trusted an in-band `outputSchema`
as the contract's normative source.

P6-B17 seeks an **independently retrieved upstream source** for that contract
and binds four pieces of evidence:

1. A publisher's full pinned Git commit and a selected file's Git blob ID.
2. A concrete tool's *literal* `outputSchema` AST declaration within that Git
   blob, extracted **without executing/importing the upstream source**.
3. The same-session `tools/list` declaration actually captured *before*
   the original MCP request, with catalog freshness and pagination enforced
   by B16.
4. The exact original `tools/call` JSON-RPC request/response and
   contract's resulting structured value.

A mismatch between the source and live catalog becomes
`QUARANTINED_SOURCE_CONFLICT`. A missing or stale catalog is not promoted.
Behavioral hints and unreviewed source prose cannot qualify side-effect
permissions just because they appear in source code.

## Product: `verify-mcp-origin`

```sh
risu-probe verify-mcp-origin original_stdio.jsonl \
  --contract observation_contract.json \
  --source-checkout ./exact-publisher-git-checkout \
  --source-manifest source_manifest.json \
  --format json --out origin-report.json
```

The offline checker verifies:

- Full 40-character `HEAD` commit equals the user-declared pin.
- `HEAD:path` blob equals the pinned blob in the declaration.
- The Git object is an actual blob and matches canonical Git blob SHA-1,
  computed from the original Git object bytes.
- Independent SHA-256 of those exact original source bytes.
- The worktree is identical to the Git blob, allowing only Git for Windows
  CRLF text-checkout conversion to the canonical LF source.
- A **uniquely selected static** `types.Tool(name="...", outputSchema={...})`
  declaration is parseable using `ast.literal_eval`; dynamic schemas,
  duplicates and missing literal names remain unverified.
- Its complete schema matches the actual tool declaration in the source
  transcript's contemporaneous, complete catalog.
- B16 already qualified the chosen rule against that catalog before the
  result is promoted.

There is **no Git checkout command, remote fetch or target executable invocation
inside the B17 checker**. A caller supplies an already available local checkout;
the checker uses bounded Git object inspection commands and offline Python
AST parsing. Git itself is invoked only for Git object introspection.

The report separates the original B16 `observed` and authority grade from
B17 `source_level` and final disposition:

- `SOURCE_CORROBORATED_PASS`
- `SOURCE_CORROBORATED_MISMATCH`
- `QUARANTINED_SOURCE_CONFLICT`
- `NOT_PROMOTED`

**Critical trust boundary:** A user-provided Git checkout can be fabricated,
even when it is internally consistent. Therefore, a mere local Git hash is
not independent publisher authentication. The accompanying CI experiments
verify the publisher's remote GitHub organization, pinned commit and tree
separately. No captured stdio JSONL file can cryptographically prove that
the process producing it was actually built from the pinned Git source.

## Frozen product before new external source evaluation

- B17 `src/risu_mcp_origin.py` blob:
  `75180de2dbd78165d2e970ee15e99df14804e7f1`.
- B16 catalog authority source remains:
  `be24472b0fea8d8e7a252a7a36158cf8873128de`.
- B15 result checker remains:
  `4314e9bf92e2ec75c421bab25eae3b43f1424a08`.
- New evaluator:
  `benchmarks/p6b17/FROZEN_UPSTREAM_ORIGIN_COHORT.json`.
- Selected publisher origin pin:
  `benchmarks/p6b17/GCP_PINNED_SOURCE_MANIFEST.json`.

The new owner and the two exact synthetic requests were fixed before the
source-native server ran. Its selection was **source-informed**: some public
implementation source was examined to choose an independently verifiable
literal output schema. Thus no untouched, blind defect-discovery claim is made.

## Independent source-original evaluation (new owner)

Publisher: [GoogleCloudPlatform/mcp-python-sdk-grpc-poc](https://github.com/GoogleCloudPlatform/mcp-python-sdk-grpc-poc)

| Evidence component | Independently checked value |
| --- | --- |
| Source revision | `cedc20fdc8fdf22fc8b411a3947ae03c71cbc926` |
| Publisher file | `examples/servers/structured_output_lowlevel.py` |
| Git blob SHA-1 | `7f102ff8b5e09b6df64b6b9c0fd913ac25f709f5` |
| In-band tool | `get_weather` |
| Preselected original calls | 2 |
| Source-corroborated correct outputs | **2/2** |
| Source-corroborated original mismatches | **0** |

Original CI:
https://github.com/risu-research/risu-probe/actions/runs/43300343923

The CI independently fetched the publisher's source with Git at the exact
commit and then queried **GitHub's remote Git tree API** to confirm that the
selected file path refers to the same Git blob. Its local SHA-256 and the blob
content ID were separately checked. The *original server source* was then
executed over native MCP stdio in an isolated temp directory under a pinned
MCP SDK version and only two synthetic city requests.

Both original calls returned successful `structuredContent` whose required
field types matched the source-pinned `outputSchema`, and the original
`tools/list` advertised the same schema.

Additional **independent** CI:
https://github.com/risu-research/risu-probe/actions/runs/43300940842

It reacquired the Git repository, independently verified source identity and
rechecked the originally captured wire without importing RISU's origin
classifier. GitHub's REST API returned `commit.verification.verified=true`
and `reason=valid` for the selected commit. GitHub also identified the
repository owner as an `Organization`. This supports the provenance of the
**published source commit**; it does not authenticate the identity of the
original MCP process from a transcript alone. The commit signature was
verified by GitHub, not independently reverified against a separately
trusted publisher key by RISU.

### Fault-injection controls

All of these **postfreeze synthetic mutations** are stored separately from the
untouched first-pass server output:

| Intervention | Frozen B17 result |
| --- | --- |
| Change original upstream source worktree bytes | **Rejected** |
| Supply forged local source Git blob pin | **Rejected** |
| Supply forged remote GitHub tree evidence to independent auditor | **Rejected** |
| Alter the same-session catalog's schema while leaving source unchanged | **2 source conflicts quarantined** |
| Make one normally returned `humidity` integer a string | **1 source-corroborated synthetic mismatch**, other original check still passed |

Thus the actual original upstream had **zero confirmed defects**; inserted
faults demonstrate the validator's source-provenance discrimination.

## Prior-source controls (development, not fresh discoveries)

Previously recorded external original source traces from B16 were replayed
against independently refetched pinned Git objects for:

- `AI-Shell-Team/aish`: commit
  `c9ad99acac291dd3a7b38162b6159bf5b01a1ed9`,
  source blob `91d8470deee0df4ec58c4543f2c36d4e7ff470de`.
  **Two** catalog-normative structured output checks were source-corroborated;
  the stale catalog and advisory-only contract observations remained
  **not promoted**.
- `MarvinRomson/master-mcp`: commit
  `75dc67c58e6468cdd81a6e5c3cb0a2f1521af93d`,
  source blob `b9e746df29655533102ed729d2de6bd3f7862d42`.
  Two read-only effect observations remained **not promoted** without an
  authoritative source-backed side-effect obligation.

Source replay:
https://github.com/risu-research/risu-probe/actions/runs/43301252255

The tool executions for these two owners originate from B16 and were already
known when B17 was designed; they count as **regression/development controls**.

## Regression and scope

Full installed preview wheel, with all earlier tests and new attack cases:
**310 tests each on Ubuntu, Windows and macOS**, all passed.

https://github.com/risu-research/risu-probe/actions/runs/43299820956

Windows Git checkout CRLF conversion was tested and recorded separately:
Git blob bytes are always canonical; worktree normalization cannot hide
arbitrary content edits.

This B17 implementation targets captured classic MCP
`2025-11-25`-style JSON-RPC with `initialize`, session scoping and
`tools/list`. The newer MCP `2026-07-28` stateless protocol has different
discovery and provenance requirements and is outside this evaluation.

### What this supports

This gives an evidence chain grounded in **independent publisher-hosted
version-control content**, rather than relying on a server's self-description
or an unconstrained user-created test contract. For the narrow static
`outputSchema` subset, source, active catalog and original results were
independently verified. A catalog mismatch can be quarantined without
erasing the observed result, and the original source remains auditable.

### What this does not prove

- That the running executable was itself securely built, deployed or
  remotely attested from that exact source commit.
- That a publisher's signed source code implements the advertised contract
  correctly for all inputs.
- Authorization to perform an external side effect; explicit source
  annotations and textual descriptions are still not sufficient permission.
- General JSON Schema implication, dynamic schemas or conditional tool
  declarations beyond this narrowly supported static subset.
- An ecosystem-level defect rate, zero false positives or blind discovery
  recall. One new source-informed vendor and two earlier development controls
  cannot support those claims.
- A previously unreported real upstream bug. The new original source **passed**.

## Next highest-value step

B18 should test **independently authenticated deployment/build provenance** or
the closest verifiable substitute, then lock a genuine real before-fix /
after-fix external defect pair *before inspecting outputs*. Keep structured
output obligations and side-effect permissions separate. A trusted publisher
artifact or signed provenance record could substantiate the source-to-binary
mapping; otherwise the claim must remain bounded at source-corroborated
contract consistency.
