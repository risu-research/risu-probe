# B32 locked external original signed-provenance benchmark (2026-11-13)

Frozen before the first original B32 verification run. This experiment develops one general signed source/delegated signer authorization boundary, then evaluates previously unused external publishers. **None** of the projects below was part of B31's two development/holdout publishers (`cli/cli`, `sigstore/fulcio`). Original GitHub release metadata SHA-256 digests, repository, version, asset and asserted signer family are pinned below. An original negative or unverified status is retained, never replaced with a different release.

| Label | Original publisher | Release | Exact original release asset | Official GitHub release asset SHA-256 | Signed-source family |
|---|---|---|---|---|---|
| H1 | `mitre/hdf-libs` | `v3.5.1` | `hdf_3.5.1_linux_amd64.tar.gz` | `482bc0e3a92a508d141e9285eba9985965c0d6bc67e922903359d70e06c3ae7a` | Same-repo release workflow |
| H2 | `txn2/kubefwd` | `v1.25.17` | `kubefwd_Linux_x86_64.tar.gz` | `f9a2986f26d219713429477511f5f570df12c811e0f79d42b244569746e8eba1` | Same-repo release workflow |
| H3 | `UpCloudLtd/upcloud-cli` | `v3.37.0` | `upcloud-cli_3.37.0_linux_x86_64.tar.gz` | `ce2d381bdf49ce74a74582f390490542c49957079d7e606303e1426138b7e3d6` | **Delegated reusable signing workflow** operated in `UpCloudLtd/workflows` |
| H4 | `axonops/audit` | `v0.2.5` | `audit_0.2.5_linux_amd64.tar.gz` | `e0b075569683a2614656f7923271b8b302dd167950bb3480f0021f2bf12c3f2a` | Same-repo release workflow, also separate signed checksum bundle |

## Primary research goal

Distinguish **a repository whose artifact is signed** (`source repository`) from **the repository/workflow whose certificate signed the attestation** (`signer repository`), including a legitimate delegated reusable signing workflow. Older B31's single-repository workflow requirement is a declared **product coverage limitation**. Prespecify the policy allowing delegation only when:
- upstream GitHub/Sigstore signature verification succeeds using the actual original artifact bytes and exact repository and signer expectations, with no JSON-only signature shortcut;
- the signed subject name and digest match the original original-release asset;
- the `SLSA provenance` predicate identifies the exact producing source repository (or else explicitly leave source identity unverified; don't silently substitute the signer repository);
- a delegated signer must be explicitly allowed by the caller's trust policy; arbitrary valid signing repositories are never acceptable;
- an unrelated approval/execution target is never authorized by a signed build artifact, regardless of how legitimate the signature or delegation.

## Baseline and fair comparison

**Native gh / Sigstore**: cryptographically determines whether each artifact has signed origin under explicit identity expectations. It is a baseline for *artifact provenance*, not a competing authorization verifier. Preserve the actual native outcome and original success/failure. The RISU layer may give `VERIFIED` for provenance but must give `UNVERIFIED` for owner authorization and exact remote-effect privileges in absence of a separate same-resource chain. It is **invalid** to portray a native gh success as a failure to detect an unauthorized resource write; gh makes no such claim.

**B31 existing RISU**: requires the signer workflow inside the same repository as the source. Prespecified H3 is a legitimate heldout case which may require a separately trusted delegate signer; do not relax the original B31 branch silently to count it as pass.

**B32 source–signer boundary**: unambiguously bind exact byte SHA, signed subject digest, producer repository, signer repository and trusted signer workflow, without claiming that a verified build signer is the independent resource owner.

## Frozen negative controls

N1: one-bit edit after original bytes downloaded. Official `gh attestation verify` must reject regardless of attacker choosing a new local SHA.
N2: replace expected signing repository with another valid publisher; original official verifier must reject.
N3: present `mitre/hdf-libs` signed proof as if it were the `txn2/kubefwd` release under another valid subject label; refuse due to original digest / repository mismatch.
N4: present the valid signed `UpCloudLtd/workflows` delegated certificate without explicitly authorizing the delegation; refuse, **not** accept any signed issuer.
N5: conflate original build signature from H1/H2/H3/H4 with permission to write B25's unrelated GitHub file or B28's unrelated PostgreSQL resource; keep owner consent `UNVERIFIED`.
N6: tamper with returned unsigned `verificationResult.statement.predicate`; only the official verifier's *new* output is accepted as a cryptographically verified source. A user-provided JSON with `verified=true` is not proof.
N7: alter caller expected source ref, signer workflow, asset digest or target repo; original verifier and strict policy must refuse.

## Pass/failure rules and interpretation

- Every H1–H4 must be reported with its exact original outcome and rejection/uncertainty reason; never replace a negative with a new project.
- Do not execute or upload the downloaded binaries. Persist digest and nonsecret verification results only.
- Compare legitimate same-repo signing and delegated signing. This is the distinct **technical** B32 novelty over B31; broad universal superiority is NOT claimed.
- Complete an actual original heldout evaluation before considering selective stable main integration. Merge only stable functions after original heldout results, installed wheel and three-OS full regressions pass.
- This preliminary cohort of four is **small and convenience-selected using official public release documentation**. Tests derived from its findings are no longer independent future holdout.
- No external human or collaborator approval is used or required.

References:
- https://cli.github.com/manual/gh_attestation_verify
- https://docs.github.com/en/actions/concepts/security/artifact-attestations
- https://github.com/mitre/hdf-libs/blob/main/site/docs/guides/verifying-releases.md
- https://github.com/txn2/kubefwd/releases/tag/v1.25.17
- https://github.com/UpCloudLtd/upcloud-cli/blob/main/docs/index.md
- https://github.com/axonops/audit/blob/main/docs/releasing.md
