# RISU Probe P6-B25.1 | Actual human-reviewed one-file GitHub effect

**Status: VERIFIED POSITIVE (2026-11-13 UTC).** Human approval, a constrained trusted writer, the remote one-file modification, and independent read-only audit all completed. This result belongs to the B25 experimental branch, not main.

## Immutable points of reference

- GitHub execution: https://github.com/risu-research/risu-verify/actions/runs/43355918665
- Execution trigger (risu-verify): `e9409d8ef4a6a71a3a93705909fe5c777d014bbc`
- Actual remote modification: https://github.com/risu-research/risu-verify/commit/26ac7506d27a76290a7a1eb945ef0f9ea6059e09
- Trusted RISU Probe source revision: `669be8b14cb314acf6ba49353fa198c2415a056b`
- Trusted writer Git blob: `4a0e31affd2ecb27edc17d0b10e64bb40d4d0f45`
- Independent audit code Git blob: `e877f70b53fb8980f6864674da937bcb271a5589`
- Full regression: https://github.com/risu-research/risu-probe/actions/runs/43355766926
- Initial negative (failure) run: https://github.com/risu-research/risu-verify/actions/runs/43354699656
- First failure: actual GitHub Contents API line-folded Base64 rejected by old strict decoder; no resource modification in that run.
- Final fix: normalize only CR and LF, require valid canonical Base64 and identical resource cryptographic digests; add positive and negative regression for folded GitHub responses. Strict transport test on Python 3.14 + 542 tests per OS on Ubuntu, Windows, macOS passed.

## Actual GitHub B25.1 outcome

1. The named human `moon10021017` approved `risu-b25-human-owner-approval` for exact run `43355918665` (attempt 1). Review was verified using GitHub's run-specific deployment approvals API. The source proposal itself remained `UNAPPROVED_UNTIL_GITHUB_ENVIRONMENT_REVIEW_EVENT`.
2. A separate untrusted, `contents:read` job attempted direct GitHub Contents PUT and got HTTP 403, with no unauthorized file created.
3. The privileged job verified source provenance with `gh attestation verify` and exact Git source blob checks. The trusted writer verified actual review, then issued one GitHub Contents PUT to the already-existing approved fixture.
4. Actual commit `26ac7506d27a76290a7a1eb945ef0f9ea6059e09` changed **only** `benchmarks/p6b25/owner_only_resource.txt` on `qualification/p6b25-real-review-credential-isolation-20261112`. The only text change was:
   - before: `state=AWAITING_GITHUB_ENVIRONMENT_REVIEW`
   - after: `state=GITHUB_HUMAN_APPROVED_BROKER_WRITE`
5. The independently pinned read-only auditor re-queried GitHub's approval history, immutable before/after blobs and actual commit diff and reported PASS.

### Exact effects and credentials

| Measurement | Observed value |
| --- | --- |
| GitHub run ID | `43355918665` |
| Specific human review | `approved`, reviewer `moon10021017` |
| Review source | GitHub Actions run-specific deployment approvals |
| Writer age at review check | 96 seconds from run creation |
| Trusted writer writes | 1 |
| Changed files in actual commit | 1 |
| Before Git blob | `c84690efad2ac44fa96605a4d1b7c34efbff52de` |
| After Git blob | `806f70a8733e3bb3ac68119166d65d9ae433ae9d` |
| Before SHA-256 | `fe8092741095803fd70cf7c62e516fa752ba296ed8688fc15bb320db5cc64b18` |
| After SHA-256 | `1f3d9970b42d3a8b5ebc163c5678328a6b4aacc9a223f3a7119aa28456717bdb` |
| Separate untrusted job direct PUT | HTTP 403 |
| Separate POSIX child UID | 65534 |
| Child received GitHub token | false |
| Child could read privileged parent /proc environment | false |
| Child anonymous PUT | HTTP 401 |
| External independent third-party resource owner | NOT TESTED |
| New upstream external MCP defect discovered | 0 |

## Original evidence artifacts (GitHub-run immutable artifact IDs)

- Owner proposal and OIDC attestations: https://github.com/risu-research/risu-verify/actions/runs/43355918665/artifacts/14006286280
- Independent read-only remote audit: https://github.com/risu-research/risu-verify/actions/runs/43355918665/artifacts/14005962891
- Real HTTP 403 negative control: https://github.com/risu-research/risu-verify/actions/runs/43355918665/artifacts/14006086728
- Separate original owner proposal: https://github.com/risu-research/risu-verify/actions/runs/43355918665/artifacts/14005772556

The original artifact bytes were downloaded and independently cross-compared against both the repo's live remote commit and the GitHub source files. The owner-proposal artifact's bytes match the proposal within the privileged-writer artifact. All supplied resource SHA-256 and Git blob checks pass.

## Interpretation and precise trust boundary

This is a **positive platform-enforced human approval and observed effect** experiment using the owner's own GitHub organization and isolated fixture. The owner reviewed a specific run, GitHub withheld the privileged job until the review, the fixed writer performed one GitHub PUT, and a separate read-only auditor confirmed the Git effect. The negative control also verified that the untrusted job's token could not create another file.

**Limits to retain in any paper or claim:**

- The authorized human and organization owner are the same account for this test, with `prevent_self_review=false`. Independent approval by a second human or independent third-party resource owner has **not** been established.
- The job-scoped `GITHUB_TOKEN` has repository-level `contents:write` permission. It has **no cryptographic or native file-path scope**. The exact-one-file guarantee depends on the frozen, trusted writer and isolated job. An attacker controlling the privileged job code or runner could use the token outside the intended path.
- The nonprivileged child was tested under a different POSIX UID with absent token and denied parent environment read. This tests the stated isolation boundary, not a general sandbox for malicious privileged code.
- This experiment does not claim an upstream vulnerability in a real third-party MCP server. It is controlled integration evidence for the RISU Probe enforcement design.
- An offline artifact consistency verifier is not itself fresh proof of GitHub's platform state or a replacement for `gh attestation verify`; the GitHub jobs performed the platform and provenance checks.

## Next meaningful research test

B26 should concentrate on truly independent **credential issuer and resource owner enforcement** beyond a repo-scoped token, with a second approval principal and a downstream resource that rejects out-of-scope writes even if the trusted writer or agent is bypassed. Evaluate denial before execution and an independently observed effect after execution. Keep the B25.1 positive case frozen as a development benchmark; pre-register B26 positive/negative and previously unseen evaluation cases.
