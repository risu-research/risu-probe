# Original signed releases with explicitly delegated workflows (RISU Probe 0.9.22.dev0)

This extends the existing [signed release provenance verifier](SIGNED_RELEASE_PROVENANCE.md) to support an important real GitHub Actions pattern: **the artifact-producing repository and the Sigstore certificate signer workflow repository can be different**.

RISU delegates actual X.509 signature, Sigstore trusted-root and timestamp verification to the installed **official GitHub CLI** (`gh attestation verify`). It then checks the verified certificate, exact expected signer workflow identity, original source repository/ref/commit and signed subject bytes. It refuses arbitrary signers and unrelated owner-authority claims.

## Command

```sh
risu-probe verify-delegated-signed-provenance \
  --asset ./upcloud-cli_3.37.0_linux_x86_64.tar.gz \
  --source-repo UpCloudLtd/upcloud-cli \
  --signer-identity 'https://github.com/UpCloudLtd/workflows/.github/workflows/build-provenance.yaml@refs/heads/main' \
  --source-ref refs/tags/v3.37.0 \
  --sha256 ce2d381bdf49ce74a74582f390490542c49957079d7e606303e1426138b7e3d6 \
  --allow-delegated \
  --out ./upcloud-original-provenance.json
```

Before running, download the unexecuted original artifact from its publisher's official GitHub Release. The SHA-256, expected source repository/ref and certificate signer identity are **caller-controlled policy expectations**: obtain them from trusted release/workflow metadata, not from a possibly malicious attestation itself. No downloaded binary is executed by RISU.

`--allow-delegated` is required only when the signer workflow belongs to a different GitHub repository. It means the **user explicitly permits that exact signer for this signed software artifact**. It is never authority for that signer or software to write someone else's files, databases, or cloud resources.

In the signed output, `source_repository` identifies the producing project, while `signer_repository` and `signer_certificate_identity` identify the entity/workflow that actually signed. These are checked separately. The certificate's signed source commit and verified source ref are also included for reproducibility.

## Actual external publisher evidence

Six frozen published release attestations were assessed, across six software publishers not used by the initial B31 study:

| Published original sample | Observation |
| --- | --- |
| MITRE HDF v3.5.1 `hdf_3.5.1_linux_amd64.tar.gz` | GitHub release SHA-256 matches, attestation API returned HTTP 404; **UNVERIFIED**, never certified |
| txn2/kubefwd v1.25.17 Linux x86-64 archive | **VERIFIED**; signed original subject name includes a single safe `./` prefix |
| UpCloud CLI v3.37.0 Linux x86-64 archive | **VERIFIED**; source repo `UpCloudLtd/upcloud-cli`, signer repo `UpCloudLtd/workflows`; exact reusable signer identity permitted |
| axonops/audit v0.2.5 Linux amd64 archive | **VERIFIED**; original signer source is `refs/heads/main`, not the release tag |
| klodr/gmail-mcp v3.0.0 `index.js` | **VERIFIED** by unchanged B32 policy on newly heldout original publisher |
| libredb/libredb-studio 1.3.0 CycloneDX SBOM | **VERIFIED** by unchanged B32 policy on newly heldout original publisher; signed SBOM provenance, not correctness of SBOM contents |

The first four projects were used during rule development. The last two were locked after the B32 source had been implemented and before inspecting those releases' signed attestations. All six project identities, release assets and expected SHA-256 digests were fixed; the MITRE failure was retained, not replaced.

Independent original proof runs:

- First four published originals: https://github.com/risu-research/risu-probe/actions/runs/43452832725
- Sealed two new publisher tests: https://github.com/risu-research/risu-probe/actions/runs/43453821659

## Security and scope

- Fails closed if the expected file SHA-256 differs, the cryptographic verifier is unavailable or fails, the certificate signer differs, the original source/ref differs or the signed subject does not match the original bytes.
- The CLI explicitly binds the certificate SAN including signer workflow and signing ref via `--cert-identity`. GitHub CLI **does not accept `--cert-identity` and `--signer-repo` in the same invocation**. Since the exact URI already includes repository, workflow and ref, that single flag is the more precise policy.
- The same original content may legitimately be signed as `./file.tar.gz`; the checker recognizes exactly this single prefix but rejects arbitrary directory traversal or automatic renaming.
- A valid attestation proves that an artifact was signed with a particular identity under Sigstore's verification model. It does not prove the source code is safe, the entire predicate objectively truthful, a different owner authorized an action, or any exact resource change actually occurred.
- No GitHub token is persisted in the result. GitHub CLI and the local environment remain trusted dependencies; a hostile local executable or compromised builder is outside this narrow evaluation.
- The tool's `claim_states` explicitly labels independent owner consent, unrelated remote effects and one-time resource permission as **UNVERIFIED**, even after original signature verification.

The original GitHub CLI product command `verify-signed-release-provenance` remains available and unchanged.

## Reference

- <https://cli.github.com/manual/gh_attestation_verify>
- <https://docs.github.com/en/actions/concepts/security/artifact-attestations>
- <https://github.com/UpCloudLtd/upcloud-cli/blob/main/docs/index.md>
