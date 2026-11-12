# P6-B19 | An authenticated MCP repair whose responses never changed

**Qualification date:** 2026-11-12  
**Research branch:** `qualification/p6b19-upstream-signed-wheel-real-repair-20261112`  
**Public historical defect:** [GHSA-6hqx-gqrx-c5r2](https://github.com/modelcontextprotocol/servers/security/advisories/GHSA-6hqx-gqrx-c5r2), published 2026-11-11.  
**Outcome:** Genuine known upstream security bug reproduced on its original vendor-published wheel, fixed on its original separately publisher-attested wheel, independently reexecuted. **No claim of a previously undisclosed issue.**

## 1. The research question

Previous RISU stages B15–B18 separately verified MCP result/state
obligations, catalog and Git source origin, and a RISU-signed independent
qualification build plus live executable image. These did not yet evaluate
**two versions of a real upstream vendor-published, signed distribution that
changed actual defective behavior**.

P6-B19 asks: Can an offline checker connect a cryptographically verified
upstream *published* package, actual source code, native MCP response and
independently observed state effect, to correctly distinguish a known
security regression from its verified remediation?

The most significant result was stronger than anticipated:

> Every one of the four original `git_status` tool results had the **exact
> same canonical JSON content**. Only the vulnerable release, when the
> inspected repository supplied `core.fsmonitor`, executed an additional
> program. Read-only MCP response comparison alone has no observable signal
> for this selected defect.

The canonical SHA-256 of the tool result body in **all four originally
executed cases** is

`427e379e413fcb703d516e1458ab2e6acc851e561027fba4ab21cf100717b60b`.

That same result equivalence and the asymmetric effect were reproduced in
a separate runner using newly installed official wheels.

## 2. Upstream source and signed releases

Repository: `modelcontextprotocol/servers`, the official reference
implementation publishers, source path `src/git`.

| Upstream exact released artifact | Before (defective) | After (fixed) |
| --- | --- | --- |
| PyPI package | `mcp-server-git==2026.11.4` | `mcp-server-git==2026.11.11` |
| Original signed wheel SHA-256 | `0cdaa8f446554d020f8ffa0e44ef45b89df4ed4deaeb961b4305d8a2852b4e0e` | `2197a56393bba71f152c6dae55a4ad9107987b9fb9c596b87bbb85a4e0dacf90` |
| Publisher Git commit in Sigstore X.509 certificate | `36380287ed3b15d115b55f546617d723072b1296` | `e1dc4b18dbb948921da37f3d4224a628730b43b0` |
| Original Git `server.py` blob SHA-1 | `ca69538746a24f70e3e1c8602d5fcd2d1bb933f0` | `cd1d874ece4e44ea95b23d9dd933a0a74176187f` |
| Installed and upstream `server.py` SHA-256 | `2304871e38ddd95ed807f628cc68b0e0cdd8ec2e82401110211ea8ea647715a5` | `64cca3830b52f935dc254f13cca0ad4a8c0d0b024b0c6d0ec1f327966aa3ace2` |
| Publisher workflow | `modelcontextprotocol/servers/.github/workflows/release.yml` | same |

This is the first RISU controlled pair in this line of work for which
**the distribution is directly signed by the upstream developer's
GitHub Actions publish workflow**, independently of RISU's CI.

Verification was more than relying on the badge displayed by PyPI:

1. PyPI original JSON API was queried for each exact distribution file,
   exact SHA-256 and canonical `files.pythonhosted.org` URL.
2. The actual untouched wheel bytes were downloaded and independently
   hashed.
3. The PEP 740 PyPI Integrity API returned the original signed publish
   provenance bundles and original source publisher declaration.
4. `pypi-attestations==0.0.31` ran
   `verify pypi --repository https://github.com/modelcontextprotocol/servers`
   on the **exact canonical wheel URL**; both original signatures were
   cryptographically validated successfully. The same procedure succeeded
   in the independent second GitHub-hosted runner.
5. The independent auditor decoded the issuer certificate SAN and Sigstore
   `1.3.6.1.4.1.57264.1.3` Git source revision extension, confirming the
   exact corresponding commits, including the upstream Git tag-specific
   publisher workflow identities (`v2.3.0` and `v2.4.0`).
6. `mcp_server_git/server.py` within each actual wheel was byte-identical
   to the original GitHub API source blob at the independently pinned
   commit. The installed module in the corresponding isolated venv had
   that same SHA-256.

**Precise signature claim:** These are bona fide **upstream PyPI Publish
Attestations**, authenticated for both released wheels. A signed *publish*
attestation alone does not guarantee a hermetic/reproducible SLSA
source-to-build chain. The source bytes were **separately** corroborated
against their Git origin.

Official PyPI evidence:

- https://pypi.org/project/mcp-server-git/2026.11.4/
- https://pypi.org/project/mcp-server-git/2026.11.11/

PyPI attestation verification documentation:
https://docs.pypi.org/attestations/consuming-attestations/

## 3. Frozen test and operational controls

Before executing either external original package, commit
`71b3702b120f1ad25da8ad857a5050c19efc07ff` locked the
detector source identity, exact original wheels and both cohorts.

- Frozen detector: `src/risu_mcp_signed_repair.py`, Git blob
  `41bb9439174c37a53481db3e025cb9601ae6040f`.
- Frozen case list:
  `benchmarks/p6b19/FROZEN_PUBLISHER_WHEELS_REAL_GIT_REPAIR.json`.
- Frozen detector protocol:
  `benchmarks/p6b19/FROZEN_DETECTOR_BEFORE_NATIVE_EVAL.json`.

The real source defect and fix were documented by the upstream published
GHSA on November 11. Our positive case was **preselected from that public
record**. Every distinct normal case has the same inputs except the
presence or absence of one repository-local Git setting.

All tests use Python 3.11 on GitHub-hosted Ubuntu, the original
2025-11-25 MCP stdio handshake, GitPython 3.1.60 and MCP Python SDK 2.3.0
plus identical separately installed dependency lists. Each version lives
in its own fresh venv.

The synthetic repository contains only a small README and a
`safe-monitor.sh` file. The configured probe sets
`core.fsmonitor` to execute that **harmless local marker-writing script**.
The marker is stored under the same temporary test root, outside the Git
repository. Nothing reads private files, collects credentials, sends data
over the network or interacts with a real target. The subprocess receives
a minimal scrubbed environment with no CI token or user secrets.

**Operational safeguards** include writing the Git setting as the **last
Git configuration command**, never running any Git status in the harness
after configuration, checking the marker is absent immediately before the
actual MCP tool call, and counting its exact known benign bytes after
the response. Each case uses an independently created temporary repo
and new original server process.

## 4. Actual four-case native before/after original result

| Signed version | Original MCP `git_status` | Repository-local `core.fsmonitor` | Successful tool response | Benign external program executed |
| --- | --- | --- | --- | --- |
| 2026.11.4 | YES | configured | YES | **YES, 1 invocation** |
| 2026.11.4 | YES | absent | YES | NO |
| 2026.11.11 | YES | configured | YES | **NO** |
| 2026.11.11 | YES | absent | YES | NO |

All four `tools/call` requests were preceded by the original
`initialize` negotiation and `tools/list` catalog declaration. Raw
JSON-RPC stdout and a separate external side-effect witness were
preserved in original byte form. In all four cases:

- The actual original MCP process identified itself as `mcp-git` at
  the correct installed release version.
- The original `git_status` tool reported **normal success** and the same
  repository status body.
- The external marker did **not exist before** the tool call.
- Exactly one benign marker invocation was recorded only on the
  pre-fix **configured** case.
- Neither release generated the marker on the normal repository.

The source investigation aligns with this independent behavior: the
fixed upstream code hardens the repository's effective Git
configuration before running the relevant Git operations. The
old original server did not have that protection.

First successful frozen detector and original source CI:
https://github.com/risu-research/risu-probe/actions/runs/43316866530

The checker returned
`REPRODUCED_KNOWN_UPSTREAM_SECURITY_REPAIR`, with two publisher-signed
wheels, four correlated native calls, both normal controls passing,
the original configured marker visible and the repaired configured
marker absent.

A previous harness run recorded all four real original outcomes before
failing in the **evaluation file layout adapter**. This was fixed only
by copying the unchanged official evidence alongside the original
wire, without touching the frozen detector or case definitions.
Earlier attempted CI records were retained, not silently excluded.

## 5. Independent source-free evaluator and second original execution

Independent source:
`benchmarks/p6b19/independent_publisher_hidden_effect_audit.py`

It **does not import the B19 detector**. The independent implementation
checks official wheel digests, original Git source object digests,
upstream PyPI publisher certificates and signed commit extensions, the
four native JSON-RPC requests and responses, and marker file witness
identity. It also recomputes the tool-result SHA256.

On an independent fresh GitHub runner, the official PyPI signatures were
cryptographically reverified, both original wheels were freshly
installed in isolated virtual environments, and both versions were
**executed again** against newly created benign synthetic repos, yielding
another four actual native MCP calls.

Both independent executions produced the same four-way effect pattern,
and **all eight actual original tool response bodies were identical**
under canonical JSON across both runs.

The second auditor also rejected (on purpose) a synthetic forged marker
witness and a modified previously publisher-signed wheel. The expected
negative-control exceptions were not counted as source defects.

Independent replay and X.509 publisher audit:
https://github.com/risu-research/risu-probe/actions/runs/43317961883

## 6. Offline user-facing tool

```sh
risu-probe compare-signed-mcp-repair \
  --evidence-root ./original-signed-wheel-and-native-captures \
  --freeze benchmarks/p6b19/FROZEN_PUBLISHER_WHEELS_REAL_GIT_REPAIR.json \
  --format json --out repair_verdict.json
```

The command is an opt-in offline comparator, **specific to the selected
four-case signed wheel/effect witness schema**. It does not execute
external code or collect signed provenance itself. It verifies the
supplied actual wheel digest, preverified published identity, original
source module SHA-256, exact original MCP request/response correlation,
and independent external effect witness. The actual Sigstore certificate
verification is performed separately by the official PyPI CLI in CI.

Findings cannot be promoted when a wheel digest, source bytes,
publisher origin or normal status/effect controls disagree. It is a
research-grade **conditional evidence comparator**, not a general
automatic scanner for arbitrary Git configuration exploits or novel
vulnerabilities.

The 18 new synthetic offline controls include forged signing identity,
wrong source digest, modified wheel, tampered original trace, altered
effect witness, missing original response, simulated tool errors and
contaminated normal controls. These are synthetic and separately named.

Complete installed RISU wheel, with all historical functionality:
**349 tests each on Ubuntu, Windows and macOS**.
https://github.com/risu-research/risu-probe/actions/runs/43315902509

## 7. Why this is research-relevant

The B19 paired design isolates the bug mechanism from three possible
misreadings:

1. **A normal-looking response is not proof of a read-only action.**
   In this dataset an unchanged canonical MCP tool result concealed
   the executable side effect.
2. **A claimed fix is not confirmed by an absent side effect alone.**
   The post-fix tool must still complete successfully; matched normal
   controls catch a server that simply fails to perform the operation.
3. **A valid package name/commit is not proof of which original code ran.**
   Signed upstream PyPI publication, wheel bytes, Git source bytes,
   installed module bytes, live original MCP server metadata and
   runtime effect witnesses are distinct evidence links.

This is a reproducible known-bug positive control for future independent
RISU rules, not an announcement of a newly discovered vulnerability,
population bug-detection precision, broad automated exploit discovery or
end-to-end proof of trusted deployment.

## 8. Next step

Use the B19 result as a development positive and **freeze a general
source-and-effect decision rule** for a previously unused external
publisher's signed pre/fix pair, preferably using a different protocol
and independent ground-truth defect with matched unaffected controls.
Retain exact signed publisher identity; provenance and behavior must
be evaluated separately, and original wire/state artifacts must be
sufficient for another team to reproduce the decision.
