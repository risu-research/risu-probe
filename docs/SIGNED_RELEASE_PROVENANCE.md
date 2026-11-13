# Verified signed-release provenance (RISU Probe preview)

RISU Probe can now verify a downloaded release file using **GitHub's official Sigstore-backed cryptographic attestation verifier**, including the expected signing workflow and source ref, before issuing a narrowly scoped provenance report.

This feature is source provenance verification. It **does not certify** that a separately owned GitHub file, database row, or S3 object was authorized for modification by its owner.

## Requirements

- Install RISU Probe and the official GitHub CLI `gh` with its attestation verification command.
- Access to GitHub attestation lookup and Sigstore trust-root verification.
- The release asset file on disk and an externally verified expected SHA-256, repository, signer workflow, and source ref.
- Set `GH_TOKEN` to a GitHub token with appropriate read access when needed.

Do not execute a downloaded binary simply to test its provenance.

## Verified external examples

The original independent publisher samples, frozen in B31, are:

- Development sample: [GitHub CLI v2.62.0](https://github.com/cli/cli/releases/tag/v2.62.0), file `gh_2.62.0_linux_amd64.tar.gz`, SHA-256 `41c8b0698ad3003cb5c44bde672a1ffd5f818595abd80162fbf8cc999418446a`, signer workflow `cli/cli/.github/workflows/deployment.yml`, source ref `refs/heads/trunk`.
- Independently produced holdout: [Sigstore Fulcio v1.10.0](https://github.com/sigstore/fulcio/releases/tag/v1.10.0), file `fulcio-linux-amd64`, SHA-256 `92092b98fbb78ec24585982f970367a734ac8ab035fde42df05ef9b0c48cb07d`, signer workflow `sigstore/fulcio/.github/workflows/release.yml`, source ref `refs/tags/v1.10.0`.

Example command after downloading the original asset:

```shell
risu-probe verify-signed-release-provenance \
  --asset ./gh_2.62.0_linux_amd64.tar.gz \
  --repo cli/cli \
  --asset-name gh_2.62.0_linux_amd64.tar.gz \
  --signer-workflow cli/cli/.github/workflows/deployment.yml \
  --source-ref refs/heads/trunk \
  --sha256 41c8b0698ad3003cb5c44bde672a1ffd5f818595abd80162fbf8cc999418446a \
  --out ./signed-source-verdict.json
```

## Verified report scope

The verification must complete successfully in the official CLI, with the expected signing identity, SLSA provenance predicate, matching signed artifact digest and trusted timestamp. RISU records only a concise provenance report, not a downloaded asset or private token.

The JSON reports `VERIFIED` for the actual signed artifact bytes, verified source repository and SLSA statement. It reports `UNVERIFIED` for any unrelated owner's exact authorization, one-use permission or independently audited resource effect. These claims require a separately verified same-operation evidence chain.

The verifier refuses an altered artifact, mismatched signer, wrong repository, wrong signed subject, absent official verification engine or ambiguous signed output. A raw JSON file containing `"verified": true` is never treated as a signature. The current verifier is designed for GitHub-hosted release attestations and does not purport to verify arbitrary in-toto formats or OCI attestations.

## Original qualification evidence and limitations

The development and independent holdout both completed original GitHub/Sigstore cryptographic checks. Native cryptography itself rejected a byte-altered release; signer substitution and unrelated owner consent inference were also refused. See the B31 qualification CI record: https://github.com/risu-research/risu-probe/actions/runs/43447495402

This relies on GitHub CLI and its Sigstore trust-root implementation. GitHub's documentation warns that the signer workflow may control portions of the SLSA predicate; cryptographic identity is not equivalent to application-specific owner consent. A release's signed source ref may be the repository's deployment branch rather than the release tag itself, as with GitHub CLI v2.62.0. It is checked against the expected actual signer workflow and source ref, not guessed from release naming.
