# P6-B18 | Which executable actually answered the MCP call?

**Qualified original external build and execution:** 2026-11-12  
**Branch:** `qualification/p6b18-executed-binary-provenance-20261112`  
**Primary firstpass:** [43304077747](https://github.com/risu-research/risu-probe/actions/runs/43304077747)  
**Independent rerun and negative controls:** [43305633121](https://github.com/risu-research/risu-probe/actions/runs/43305633121)  
**Whole installed wheel regression:** [43304723059](https://github.com/risu-research/risu-probe/actions/runs/43304723059)

## Why this matters

B15 compared externally supplied expectations with genuine native MCP
responses and independent committed-state witnesses. B16 required evidence
that an in-band catalog actually justified the selected obligation. B17
corroborated the catalog against a source file from an exact Git commit,
with a remote publisher tree check.

The remaining gap was fundamental. A valid signed source revision and a
matching `tools/list` are evidence of source consistency, but **which program
was actually executing when the native MCP responses appeared?**

B18 extends the chain into a compiled executable, independently rebuilt
artifact, signed build record and **live process image**.

## Original external target and preregistration

This evaluation uses the public
[modelcontextprotocol/go-sdk](https://github.com/modelcontextprotocol/go-sdk)
source at the immutable commit:

`328036ea2090c83f28c41a42ee4c9e5ec7393a4f`

The original unmodified executable is the SDK's Go toolschema server
`./examples/server/toolschemas`. This is a **source-informed external
example server**, selected after code inspection, and cannot be presented as
a blind bug-finding cohort.

Source file Git blobs:

| Original upstream file | Pinned Git blob SHA-1 |
| --- | --- |
| `examples/server/toolschemas/main.go` | `0a2cfbd214798cd094fbe63162e78e7cc5bcab33` |
| `go.mod` | `3287a95780c8160bdbb4554fb2f509ca369197a4` |
| `go.sum` | `c13454aad50d66edfca523be20fd9c230ff100c7` |

The exact source revision, three source object IDs, toolchain, deterministic
build flags, selected four tool calls, signer's repository and claim limits
were written to
`benchmarks/p6b18/FROZEN_SOURCE_BUILD_RUNTIME.json` **before original
build and execution**.

## Implementation

Installed opt-in CLI:

```sh
risu-probe verify-mcp-runtime original_stdio.jsonl \
  --source-checkout ./original-go-sdk \
  --frozen-cohort benchmarks/p6b18/FROZEN_SOURCE_BUILD_RUNTIME.json \
  --source-manifest benchmarks/p6b18/SOURCE_GIT_OBJECT_MANIFEST.json \
  --binary ./mcp-toolschemas \
  --builder-a ./A/builder.json \
  --builder-b ./B/builder.json \
  --runtime-witness ./runtime_witness.json \
  --attestation-result ./attestation_verified.json \
  --format json --out runtime_provenance.json
```

Product: `src/risu_mcp_runtime_origin.py`.

The **offline command** checks internal consistency of the supplied data.
It does not execute a user-supplied binary, contact the network, mint a
signature, or independently validate Sigstore cryptography. Explicit external
verification is executed by the dedicated CI workflow using GitHub CLI
`gh attestation verify` with an expected signer workflow and repository.

The product requires all the following:

1. Exact Git HEAD commit, original `HEAD:path` Git blob objects, source bytes,
   Git blob object hash and SHA-256, via the B17 offline source inspector.
2. Two separately recorded original Go builds with identical toolchain,
   source-object list, flags, executable length and binary SHA-256.
3. Separately produced `gh attestation verify` result for the same binary
   digest and the expected signer identity.
4. Matching executable SHA-256 at launch and completion, measured from
   `/proc/<pid>/exe`, with a stable process executable inode/device,
   executable path and original process argv.
5. Original trace SHA-256 bound to the runtime witness.
6. Four pinned native JSON-RPC tool calls, each correlated with a complete
   contemporaneous in-band `tools/list` catalog and a concrete response.
7. No missing or undeclared additional tool calls.

It reports carefully that a passed chain is **CI source-to-executable
corroboration**, not verification of a third-party publisher's deployed
release.

## Genuine two-builder source build, real execution and signer proof

Build source: official upstream Go SDK commit above.

Build toolchain: `go version go1.25.0 linux/amd64`.
Both isolated GitHub-hosted runners independently built the unchanged
external Go code using:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOTOOLCHAIN=local \
go build -trimpath -buildvcs=false -mod=readonly \
  '-ldflags=-buildid=' -o mcp-toolschemas ./examples/server/toolschemas
```

Both produced the **exact same binary bytes**, SHA-256:

`c11061e35013c28f273e92ed44ff8f76eb21f8d547a76c93c7b2840c8cc5ef8f`

The builder-A output was signed using the current GitHub
`actions/attest@v4` Sigstore-backed build-provenance action. The signature
was uploaded to the public Sigstore Rekor transparency log. A separate CI
job used `gh attestation verify` to check the same digest and require
`risu-research/risu-probe/.github/workflows/p6b18-source-build-runtime.yml`
as signer.

An independent source checkout on the runtime runner reverified all three
Git objects against the original public GitHub repository's remote
commit tree.

**Important source attribution:** The actual Sigstore attestation signer is
the **RISU GitHub Actions qualification workflow**. Its signed SLSA statement
records RISU's workflow and commit, *not a release issued and signed by the
modelcontextprotocol organization*. The external source revision is
corroborated through the frozen CI workflow, independently fetched source
tree and build records. The signed provenance is not a cryptographic
attestation by the upstream author that they approved or deployed this
particular executable.

## Actual original live process and MCP wire

The original compiled binary was launched directly as a native process,
without shell redirection or modifying its source. The runner measured
`/proc/PID/exe` **while it was alive**, both before initialization and
after all selected tool responses. The executable file's on-disk SHA-256,
actual process `cmdline`, process executable inode and the live-process
image SHA-256 were also recorded.

**All observed hashes matched the signed binary SHA-256 at both endpoints.**

Four predeclared original tool requests were completed:

| Original tool call | Original response |
| --- | --- |
| `simple greeting`, `name=RISU` | structured `{"greeting":"Hi RISU"}` |
| `manual greeting`, `name=B18` | structured `{"greeting":"Hi B18"}` |
| `manual greeting`, input exceeding source maxLength | tool refusal with `isError: true` |
| `unvalidated greeting`, `user=B18` | original text `Hi B18` |

This normal/negative original control is especially useful because it shows
that an original server can intentionally reject invalid input while its
executable provenance remains valid. Such a tool-level refusal is **not** a
build-integrity failure.

Original runtime firstpass had no missing MCP requests, missing tool catalog
or failed hash check.

## Independent second executable process

A **different CI run** downloaded both original builder artifacts, reacquired
the frozen upstream source and ran `gh attestation verify` again against
builder B's byte-identical artifact. Then it directly executed the original
builder-B executable under a **new PID** and measured its live
`/proc/PID/exe` and disk SHA-256 again, before and after four repeated
native MCP calls.

A second independent Python auditor,
`benchmarks/p6b18/independent_source_runtime_audit.py`, uses **no RISU
product imports**. It verified the original publisher source Git objects,
both builders, Sigstore statement signer and subject digest, original
process witness, exact input/output semantics for all four tool calls,
and the second executable's source-native outputs.

The two original processes returned equivalent responses for all four
selected requests.

Second CI:
https://github.com/risu-research/risu-probe/actions/runs/43305633121

## Negative tests

The complete installed RISU wheel passed **331 unit and regression tests
per OS** on Linux, Windows and macOS:

https://github.com/risu-research/risu-probe/actions/runs/43304723059

Separately, an independent CI audit applied 16 deliberately altered
**synthetic** evidence records to the frozen source/build/runtime product.
All 16 were rejected, including wrong source objects, modified source
worktree, altered binary bytes, inconsistent builder identity/toolchain,
wrong signer and attestation subject, changed executable process image,
altered inode identity and modified native stdout.

All synthetic faults remained separate from the two genuine original
source process runs and **none were counted as an upstream defect**.

## Scientific claims: precise boundary

**Supported finding:** Within a trusted, publicly auditable GitHub Actions
qualification environment, the exact original external source commit,
two byte-identical independent builds, a Sigstore-signed build subject,
live executed ELF image, original native MCP transcript and selected
tool semantics can be linked in a reproducible evidence chain.

**Distinct limitations:**

- GitHub Actions signed provenance is generated by RISU, not the upstream
  publisher. This is a signed **qualification build**, not an upstream
  official release or signed external deployment.
- The offline verifier's JSON evidence and process witness can be fabricated
  by an adversary. They are made materially stronger here through separate
  GitHub CI measurement, attestation verification and independent rerun.
- A compiler, dependency, GitHub runner or build-time supply-chain
  compromise is outside the threat model. A reproducible output can
  reproducibly contain a malicious change.
- Even a genuinely verified binary's selected tool responses can still be
  defective. Source provenance answers **what ran**, not **whether it was
  correct**.
- No real upstream novel defect was detected in this source-informed external
  example: **zero** previously unknown external bugs. Population precision
  and recall are not estimable from this cohort.
- Go MCP transport and process identity were verified on Linux procfs;
  cross-platform tests verify the **offline product checker**, not Windows
  or macOS live process measurement.
- This does not implement full modern MCP protocol discovery or a publisher
  authorization/side-effect policy proof.

## Next research milestone

For a stronger, independent ecosystem result, obtain an upstream project
with **publisher-signed release artifacts and source-linked provenance**,
not solely a RISU-signed qualification build. Independently verify release
digest, build materials and real process identity and compare a previously
unknown genuine before/after defect pair with matched unaffected controls.
This would test a new and more valuable dimension: **detecting actual
upstream behavioral failure from authenticated source and execution
evidence**, rather than only proving the provenance chain itself.
