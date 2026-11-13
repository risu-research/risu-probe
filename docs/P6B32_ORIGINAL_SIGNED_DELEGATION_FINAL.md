# RISU P6-B32 | Original signed source and delegated signer evidence closure

**Final 2026-11-13. Five out of six fixed original publisher assets cryptographically verified using Sigstore/GitHub's actual trust root; one original availability negative retained. Two newly heldout independent publishers passed the frozen B32 algorithm without source-policy relaxation. Product selectively shipped to `main` as 0.9.22.dev0.**

## Motivation and existing verification standards

SLSA/in-toto provenance can attest to artifact integrity, build source and responsible signer. GitHub CLI already implements cryptographic Sigstore verification, certificate identity and signer-repo / signer-workflow policy checks. B32 therefore **does not claim to invent signatures or outperform native gh on its own intended provenance question**.

The practical implementation gap in RISU Probe 0.9.21 was that its B31 adapter required source and signer in the same GitHub repository, as well as an exact signed subject filename. Real original software release attestations demonstrate two legitimate variations:

1. **Delegated signer:** `UpCloudLtd/upcloud-cli` owns the signed software artifact, while the actual trusted certificate SAN refers to `UpCloudLtd/workflows/.github/workflows/build-provenance.yaml@refs/heads/main`. Its signed SLSA source is the separate caller `UpCloudLtd/upcloud-cli/.github/workflows/publish.yml@refs/tags/v3.37.0`. The original X509 certificate has independent `sourceRepositoryDigest` and `buildSignerDigest`.
2. **Canonical subject name:** the original `txn2/kubefwd` signed SLSA subject is named `./kubefwd_Linux_x86_64.tar.gz` even though the release asset is downloaded as `kubefwd_Linux_x86_64.tar.gz`. The exact binary SHA-256 matches. The dot-slash alias is permitted, while arbitrary directory changes or traversal remain rejected.

Original GitHub CLI confirmed that **`--cert-identity` and `--signer-repo` are mutually exclusive**. B32 uses one exact `--cert-identity` URI, which already binds signer repository, workflow filename and signer Git ref. The original verifier simultaneously enforces the source repository, source Git ref and signed predicate type.

See official CLI flags: https://cli.github.com/manual/gh_attestation_verify

## Locked first independent software publisher cohort (H1-H4)

Frozen before inspecting the original attestations: [original source evaluation protocol](../benchmarks/p6b32/LOCKED_ORIGINAL_PUBLISHER_HOLDOUT.md).

| Case | Original publisher and release | Original SHA-256 metadata | Native `gh` verification | RISU final result |
| --- | --- | --- | --- | --- |
| H1 | `mitre/hdf-libs` v3.5.1, hdf_3.5.1_linux_amd64.tar.gz | matched | HTTP 404, no retrievable attestation | **UNVERIFIED**, certificate refused |
| H2 | `txn2/kubefwd` v1.25.17, kubefwd_Linux_x86_64.tar.gz | matched | PASS | VERIFIED with safe `./` subject normalization |
| H3 | `UpCloudLtd/upcloud-cli` v3.37.0, upcloud-cli_3.37.0_linux_x86_64.tar.gz | matched | PASS under explicit UpCloudLtd/workflows signer | VERIFIED with distinct caller/signing workflow and explicit delegation |
| H4 | `axonops/audit` v0.2.5, audit_0.2.5_linux_amd64.tar.gz | matched | PASS | VERIFIED with original source `refs/heads/main` |

Original first-look GitHub CI: https://github.com/risu-research/risu-probe/actions/runs/43450828852

Final original product, negative controls and all platform regressions: https://github.com/risu-research/risu-probe/actions/runs/43452832725

The MITRE HDF 404 was **not** interpreted as falsified provenance, and no alternate artifact was substituted. Its release bytes did match published GitHub release digest; the missing original cryptographic attestation makes that particular stronger claim unverified at observation time.

## Two completely new publisher holdouts (H5-H6)

The B32 verifier code and hostile-control tests were committed at SHA `a3ab9b0faaa377a2d2ce3fba4e4ee7d2c92caea0` before querying the original signed statements of either H5 or H6. Original GitHub release asset SHA-256, named publisher, release and expected signer workflow/ref were frozen separately:

[sealed H5/H6 original protocol](../benchmarks/p6b32/SEALED_NEVER_SEEN_PUBLISHER_HOLDOUT_H5_H6.md)

- **H5**: `klodr/gmail-mcp` v3.0.0, original `index.js`, digest `682301b9d0aaf51fbdbd05a1abea28387f1f4d06bfb9a0490a47e6421960cc4e`. Exact certificate SAN `https://github.com/klodr/gmail-mcp/.github/workflows/release.yml@refs/tags/v3.0.0`. Native GitHub verifier PASS, unchanged B32 PASS.
- **H6**: `libredb/libredb-studio` 1.3.0, original signed CycloneDX `libredb-studio-1.3.0.cdx.json` SHA-256 `7baef425849d7e54252bdf7bddb552f8fb27de39f0069e88c3af7efbcd4e87e8`. Exact certificate SAN `https://github.com/libredb/libredb-studio/.github/workflows/release-artifacts.yml@refs/tags/1.3.0`. Native verifier PASS, unchanged B32 PASS. This proves signed SBOM provenance, not the factual completeness of every SBOM entry.

**Frozen independent original H5/H6 evaluation CI:** https://github.com/risu-research/risu-probe/actions/runs/43453821659

No source code or rule updates were made after viewing the H5/H6 signed results. This is a genuine second-stage cross-publisher test but a **small, nonrandom sample**, not a statistically representative population.

## What the implemented product actually checks

Implemented module: `src/risu_delegated_signer.py`, in GitHub `main` as of version 0.9.22.dev0.

- Original release asset exact caller-pinned SHA-256, streamed from disk; no executing downloaded code.
- Exact expected producing source repository, expected Git ref and original X509 certificate identity (signer GitHub repository + workflow path + signer's Git ref).
- Delegation permitted only if the invoking user explicitly allows the **specific signed signer identity** via `--allow-delegated`; an arbitrary signed repository is never accepted.
- Official real `gh attestation verify` cryptographic verification against GitHub's attestation API and Sigstore trust root, with exact source `--repo`, signer `--cert-identity`, source `--source-ref` and SLSA predicate.
- Strictly parsed original verified output: signed in-toto Statement v1, exact subject bytes SHA-256 and original safe relative filename (optionally one leading `./`), trusted verified certificate's `sourceRepositoryURI`, `sourceRepositoryRef`, `sourceRepositoryDigest`, `buildSignerURI` and verified timestamp(s).
- Signed SLSA producer workflow source metadata consistent with verified original certificate. The predicate itself is supplied by the build workflow and must not be treated as third-party factual truth.
- Signed artifact provenance may be VERIFIED; independently controlled resource owner consent, one-time write permission and observed remote effect are always **UNVERIFIED** without separate original action-specific evidence.

The verifier **does not grant any repository, database, S3 or MCP write credential**; it performs read-only attestation verification. It emits no API token, no binary and no arbitrary secrets. The signed source verifier is a reusable product feature and is deliberately independent from B25-B30 experimental resource writers.

## Adversarial and compatibility evaluation

Original B32 research CI https://github.com/risu-research/risu-probe/actions/runs/43452832725 passed 26 dedicated tests including independent actual original signature checks and source mutation. Adversarial controls:

- Alter one original release byte and recompute the expected local digest; **real GitHub/Sigstore attestation verification refuses**.
- Substitute a genuine signed but other publisher's repo/source/signer; the original verifier refuses.
- Remove explicit permission for the valid delegated UpCloud workflow: RISU refuses before calling cryptography.
- Falsify sourceRepositoryURI, sourceRef, signer SAN, producer workflow source, signed subject name or digest in captured original verification results: strict local policy refuses. These pure data mutation tests are not themselves cryptographic signature verification.
- Reject `../` or deeper path aliases rather than broadly normalizing signed artifact names.
- Refuse unsigned JSON marked `verified`, no official verifier executable, invalid repo paths, conflicting JSON duplicate keys, and true original HDF attestation unavailability.

Three operating system installed-wheel regression: Ubuntu, Windows, macOS each **81/81 PASS**.

## Stable main release, selective promotion

Main was deliberately updated because B32 extends a real user-facing B31 product feature. Instead of merging the experimental qualification branch, a new branch was created from stable `main` and only six files promoted.

- Stable PR: https://github.com/risu-research/risu-probe/pull/2
- Main squash commit: `a1b4afdb7a4d8ee3a9f4c543924b6428aba7e137`
- Stable version `0.9.22.dev0`.
- User-facing docs: https://github.com/risu-research/risu-probe/blob/main/docs/DELEGATED_SIGNED_PROVENANCE.md
- Two commands remain available: the original B31 `verify-signed-release-provenance`, and the B32 `verify-delegated-signed-provenance`.
- Main PR premerge test: https://github.com/risu-research/risu-probe/actions/runs/43454766698 ; **4/4 successful CI jobs**.
- Postmerge main test: https://github.com/risu-research/risu-probe/actions/runs/43455008883

Main PR checked 81 installed tests per platform and a separate five-original-release live signature verification job, including H5/H6. Research-specific B25-B30 attack/test harness and privileged permission fixtures remain outside stable main.

## Measured scope and next research direction

Six frozen original release assets from six independent software repositories: **5 real signed release provenance verifications passed, 1 original attestation unverified**. The two truly previously unseen publishers in H5/H6 passed the same fixed policy with zero observed false rejections; this does not prove a universal or statistically calibrated zero false positive rate.

The actual gap addressed is **RISU B31 same-repository signer assumptions**, plus safe `./` subject binding. GitHub CLI and in-toto standards already support signers and subject provenance. This is a valuable small **product coverage and evidence-precision improvement**, not invention of signature cryptography or demonstration of superiority over GitHub's native verifier.

A new external action/effect *authorization* claim would still require independent evidence linking a specific owner's consent, exact action request and observed resource change within the SAME operation. A valid build signature alone never substitutes for it.

Best next nonhuman study: freeze an actual new cohort of independently signed build and runtime evidence from tools whose source scope can be compared with exact GitHub post-approval artifact/commit effects; introduce time- and owner-scoped proof obligation checks rather than relying on the source attestation alone. Compare to a properly configured existing in-toto/SLSA policy as a separate baseline with equivalent capabilities.

No independent external human or email participation was required or performed.
