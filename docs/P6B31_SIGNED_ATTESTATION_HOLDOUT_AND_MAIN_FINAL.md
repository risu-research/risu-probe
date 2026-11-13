# RISU Probe P6-B31 | Original Sigstore-signed independent publisher holdout and stable main promotion

**Completed 2026-11-13. Original cryptographic verification and independent publisher holdout PASS. Main selectively merged through PR #1 at commit 32e4f3b66c690338395c277dabe92cede61eef54.**

## Development versus independent evaluation

The B31 sources were preregistered in [LOCKED_ORIGINAL_SIGNED_ATTESTATION_EVAL.md](../benchmarks/p6b31/LOCKED_ORIGINAL_SIGNED_ATTESTATION_EVAL.md) before the original cryptographic study.

| | Original independent publisher 1: development | Original publisher 2: holdout |
| --- | --- | --- |
| Repository | cli/cli | sigstore/fulcio |
| Release tag | v2.62.0 | v1.10.0 |
| Original asset | gh_2.62.0_linux_amd64.tar.gz | fulcio-linux-amd64 |
| Published actual SHA-256 | 41c8b0698ad3003cb5c44bde672a1ffd5f818595abd80162fbf8cc999418446a | 92092b98fbb78ec24585982f970367a734ac8ab035fde42df05ef9b0c48cb07d |
| Exact signer workflow | cli/cli/.github/workflows/deployment.yml | sigstore/fulcio/.github/workflows/release.yml |
| Exact source ref | refs/heads/trunk | refs/tags/v1.10.0 |
| Original Sigstore / gh attestation check | PASS | PASS |
| B31 signed source provenance result | VERIFIED | VERIFIED |
| Authorization of unrelated B25 / B28 resource changes | UNVERIFIED / REFUSED as authority | UNVERIFIED / REFUSED as authority |

Original independent source discovery, signed statement subject digests and source workflows: https://github.com/risu-research/risu-probe/actions/runs/43446087643

Qualified experimental product and original holdout: https://github.com/risu-research/risu-probe/actions/runs/43447495402

Original nonsecret two-signature verified verdicts: https://github.com/risu-research/risu-probe/actions/runs/43447495402/artifacts/14048197458

No downloaded third-party release binary was executed, and neither publisher was contacted for assistance.

## Real cryptographic checks and adversarial evaluation

The code calls the **official GitHub CLI Sigstore trust-root verifier**, not a home-made JSON signature check. The gh invocation binds:
- actual on-disk original asset bytes and SHA-256;
- exact GitHub owner/repository, not an organization-wide match;
- exact original certificate signer workflow;
- exact original Git source ref;
- original SLSA v1 provenance predicate and verified certificate/timestamps.

The B31 Python layer additionally verifies the returned in-toto v1 subject, signed name/digest, source repository and workflow metadata. It returns short and nonsecret machine-readable results.

Adversarial tests include:
1. Mutate actual original GitHub CLI archive byte and confirm that the official **cryptographic engine itself rejects** the altered artifact (even if an attacker proposes a new expected digest).
2. Try to verify a properly signed GitHub CLI artifact as if it had been issued by Sigstore Fulcio, and observe refusal.
3. Require an explicit trusted GitHub CLI executable; missing CLI and failed signature subprocess both fail closed.
4. Reject ambiguous verification JSON with duplicate keys, malformed repo path, nonfinite data, altered subject digest, wrong SLSA repository/workflow metadata.
5. Check that valid original release signatures do NOT automatically prove external owner consent, one-time execution, or a changed B25 GitHub/B28 PostgreSQL resource.

All B31 development and independent holdout original checks and the signed-release adversarial test suite passed in the qualified Linux run; installed Ubuntu/Windows/macOS full regressions each passed 609/609.

## Stable main integration actually performed

The user explicitly authorized changing main when beneficial. We therefore took a **selective promotion**, not an indiscriminate merge of many earlier research phases.

- Main initial version: 0.9.20.dev0, source main commit 8d660aa11aa4a046b419c1e543dfc49e7a6fb837.
- Main-derived integration branch: integration/b31-verified-sigstore-main-20261113.
- Main PR: https://github.com/risu-research/risu-probe/pull/1
- Actual successful squash merge commit: 32e4f3b66c690338395c277dabe92cede61eef54.
- Version after merge: **0.9.21.dev0**.
- Added stable product CLI: risu-probe verify-signed-release-provenance.
- Main source module: src/risu_signed_release_verifier.py.
- Docs: docs/SIGNED_RELEASE_PROVENANCE.md.
- Tests: tests/test_p6b31_signed_source_provenance.py.
- CI: .github/workflows/b31-signed-release-provenance-product.yml.
- Maintained existing first-use version test by comparing installed package metadata with the declared version in pyproject.toml, replacing hard-coded 0.9.20.dev0.
- Only seven main files changed. No B25-B30 experimental enforcement harness or permissions were merged.

PR CI at latest original pull request head https://github.com/risu-research/risu-probe/actions/runs/43448557110 passed Ubuntu, Windows and macOS installed-wheel suite (70/70 per OS), as well as original two-publisher Sigstore verification with 14 B31 tests.

Merge-time main CI: https://github.com/risu-research/risu-probe/actions/runs/43448830541

## Important interpretation and future research

The GitHub verifier confirms an attestation's trusted signature/certificate, original signed subject digest and declared SLSA source. These are actual independently published original software supply-chain attestations.

**The signer workflow can control parts of the predicate.** A verified signature does not prove every sentence of the predicate is objectively true, that all upstream source files were harmless, or that the signer owns any unrelated resource. This is exactly the trust boundary the new B31 product preserves.

B31 is a narrow original-publisher evaluation of two real signed releases, one used during development and one frozen independent holdout. It is not broad statistical evidence of superior false-positive performance or novel cryptography. It reused a mature GitHub/Sigstore implementation deliberately; signature correctness comes from that verifier and its trust roots.

Next non-human path: collect a larger previously unseen cohort of signed release/build/workflow attestations from additional independent projects, including deliberately plausible but invalid cross-action claim joins. Freeze cohort and rules before evaluation. Require baseline comparable to existing in-toto/SLSA policy verification, rather than calling a simplistic OR union state-of-the-art.

No external human approval was obtained or invented; no user's email was sent; no new credential/owner permissions were requested.
