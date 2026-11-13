# RISU Probe P6-B30.2 | Claim-specific proof of authorized resource effects

**2026-11-13 UTC. Final status: original live GitHub effect closure PASS; four original subjects evaluated without cross-action consent transfer; VERIFIED / REFUTED / UNVERIFIED evidence states implemented. No external human cooperation required.**

Research branch: qualification/p6b30-claim-effect-closure-20261113. Both RISU main branches remain unchanged.

## Research question and relation to existing tools

When a workflow contains several individually valid approvals, credentials, command results and audit records, which of them support the exact resource-change claim? A valid approval for one execution must not transfer to another action or resource, and a permitted object path need not imply permission to write arbitrary values or repeat an effect.

in-toto already verifies digested step materials and products. SLSA/Sigstore already address build provenance, signatures and trusted identities. B30 deliberately **reuses the idea of source identity and digest binding** instead of reinventing these systems. Its narrow focus is a machine-checkable *owner authorization / resource effect proof-obligation join*, distinguishing positive witnesses, actual counterexamples, and evidence not available.

References:
- https://github.com/in-toto/attestation/blob/main/spec/predicates/link.md
- https://github.com/in-toto/attestation-verifier
- https://github.com/sigstore/docs/blob/main/content/en/policy-controller/overview.md

## Real original B25 approval-to-Git-effect closure

The B30 verifier fetched live original GitHub REST data for:
- Native run risu-research/risu-verify #43355918665; repository ID 1350184511, attempt 1.
- Approved-run source SHA e9409d8ef4a6a71a3a93705909fe5c777d014bbc.
- Original human review of environment risu-b25-human-owner-approval, GitHub account ID 208310835.
- The proposed exact operation at benchmarks/p6b25/OWNER_PROPOSED_REQUEST.json from that **immutable source SHA**.
- Actual effect commit 26ac7506d27a76290a7a1eb945ef0f9ea6059e09.
- Sole effect commit parent = the original reviewed source SHA, exact Git history relationship.
- Exactly one actual modified GitHub file: benchmarks/p6b25/owner_only_resource.txt.
- Before Git blob c84690efad2ac44fa96605a4d1b7c34efbff52de; content SHA-256 fe8092741095803fd70cf7c62e516fa752ba296ed8688fc15bb320db5cc64b18.
- After Git blob 806f70a8733e3bb3ac68119166d65d9ae433ae9d; content SHA-256 1f3d9970b42d3a8b5ebc163c5678328a6b4aacc9a223f3a7119aa28456717bdb.

B30 independently reconstructs Git blob SHA-1 from decoded byte content (accepting only GitHub's canonical folded Base64) and compares actual SHA-256, Git diff file count, precise requested path, original source/run, environment and reviewer. It refuses wrong sources, different Git parents, an added second file, different preimage, different postimage, wrong run attempt, wrong reviewer, or a post-run change in environment settings.

**Positive original lower-tier result:** PLATFORM_REVIEW_AND_EXACT_GIT_EFFECT_CLOSED.

This is a confirmed platform-review-and-immutable-Git-effect link, **not** proof that the approval caused the commit or that a separately controlled human owner authorized it. The B25 actor and reviewer are the same GitHub account. The original GITHUB_TOKEN is repository-scoped, not file-scoped.

Live original CI and source-to-effect artifact:
- https://github.com/risu-research/risu-probe/actions/runs/43439862506
- https://github.com/risu-research/risu-probe/actions/runs/43439862506/artifacts/14045507314

Installed CLI:

    risu-probe verify-mcp-effect-closure \
      --repo risu-research/risu-verify \
      --run-id 43355918665 \
      --environment risu-b25-human-owner-approval \
      --proposal-path benchmarks/p6b25/OWNER_PROPOSED_REQUEST.json \
      --effect-commit 26ac7506d27a76290a7a1eb945ef0f9ea6059e09 \
      --out effect-closure.json

## Four-original-subject evidence join

A separate, installed RISU checker imports previously verified immutable GitHub Actions artifacts:
- B30 B25 original live Git effect certificate from run #43439862506.
- B29 original same-account-review negative result from #43436411185.
- B27 native PostgreSQL and SeaweedFS independent original source comparison from #43365668801.
- B28 original OpenBao/PostgreSQL issuer and effect certificate from #43378448871.

These concern FOUR DIFFERENT operation subjects:
1. B25 exact GitHub Contents file and run.
2. B27 PostgreSQL row in database risu_b27_external.
3. B27 SeaweedFS object in S3 bucket risu-b27-external.
4. B28 PostgreSQL row and dynamic native issuer lease in database risu_b28_external.

The checker evaluates eight obligations separately: actual independent owner approval, issuer scope, exact resource, exact bytes, original-state direction, effect repetition, native revocation, independent resource audit. It never inherits a successful claim from one resource into another.

Evidence semantics:
- VERIFIED means the admitted source-specific original evidence supports this exact property.
- REFUTED means a direct original counterexample contradicts the claimed property.
- UNVERIFIED means this evidence set has not established the property. It must not be called a security failure.

Original SeaweedFS allows a different-content PUT and repeated PUT on the exact previously allowed object, so this configured policy's exact-content and one-effect claims are REFUTED. Its original object scope and native revocation are VERIFIED. Independent real-human owner consent is UNVERIFIED, not refuted.

### Result summary

| Original subject | Verified obligations | Refuted original properties | Unverified obligations |
| --- | --- | --- | --- |
| B25 actual GitHub file | 3 of 8 | none in imported sources | 5, including separate owner approval and B30-imported independent resource audit |
| B27 PostgreSQL RLS | 6 of 8 | none | separate owner approval and native issuer/owner binding |
| B27 SeaweedFS 4.53 | 3 of 8 | exact desired bytes; replay prevention | 3, including separate owner approval, issuer scope and old-state direction |
| B28 OpenBao 2.7.2 / PostgreSQL | 7 of 8 | none | independent real-human owner approval |

An earlier separate B25 independent audit exists; the narrow B30 matrix calls that particular proof UNVERIFIED **only because the B25 original audit artifact is not included in the four imported certificates**. It does not claim the audit never happened.

**Four-subject result:** FOUR_INDEPENDENT_ORIGINAL_CLAIM_SUBJECTS_NEVER_FALSE_JOINED. None of the four subjects satisfies all eight requirements.

For diagnosis, B28 has the fewest missing obligations and its exact unresolved one is the independent real resource-owner approval. This explains status, but further human involvement is not necessary for the next proposed technical improvements.

A deliberately incorrect comparator that takes ANY prior native approval and OR-combines ALL permissions and effects across the four separate subjects produces a false positive. This is a trivial invalid baseline constructed to make the failure mode concrete, not a measured superiority claim against Sigstore, in-toto, GitHub or another production verifier.

Original 4-source CI and stored matrix:
- https://github.com/risu-research/risu-probe/actions/runs/43441533953
- https://github.com/risu-research/risu-probe/actions/runs/43440849203/artifacts/14045168687

Installed command:

    risu-probe compare-mcp-claim-sufficiency \
      --b30 original_b25_effect_closure.json \
      --b29 b25-original-github-self-review.json \
      --b27 independent_capability_matrix.json \
      --b28 .b28-record-certificate.json \
      --out claim-sufficiency.json

## Evaluation and reproducibility

Both B30 commands are installed in the wheel on the research branch. New modules:
- src/risu_mcp_effect_closure.py
- src/risu_mcp_claim_sufficiency.py
- CLI src/risu_p5d_cli.py and package pyproject.toml
- tests/test_p6b30_effect_closure.py
- tests/test_p6b30_claim_sufficiency.py
- .github/workflows/p6b30-original-github-effect-closure.yml
- .github/workflows/p6b30-cross-backend-claim-closure.yml

Adversarial checks perturb original approval identities, revised resource bytes, source/commit parent, run ID, imported B29 account separation, SeaweedFS S3 property labels, B28 lease/revocation and owner assertions. The original GitHub instance remained read-only and the user-controlled production resources remained unchanged.

Full, installed three-operating-system CI:
https://github.com/risu-research/risu-probe/actions/runs/43441570914

## Interpretation and next meaningful task WITHOUT external human

B30 demonstrates a concrete, portable claim-specific verifier with originally observed provenance links and actual counterexamples, not a new general signature protocol or first-ever authority graph. The current four evidence sources are a small **development set** selected while designing the verifier. Their comparison is an offline aggregation of earlier verified original records, not fresh executions of every backend. Neither the complete bundle nor an unsigned copied witness is cryptographically certified as a single independently controlled owner instruction. A hostile CI root or service operator remains outside this trust model.

The best next non-human test is to integrate an existing signed in-toto/Sigstore attestation verification library and trust root, then PRE-FREEZE a new unseen evaluation cohort with independently produced signed artifact provenance plus runtime effects. Measure how often valid signed artifacts can be misjoined into unauthorized operation claims, verified false positives and correct refusals, without weakening GitHub or external backend authorization conditions. Prioritize technical reproducibility and genuinely unseen data over a synthetic independent human account.

The B30 branch is a development qualification branch, not a released stable RISU Probe version.
