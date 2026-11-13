# RISU Probe P6-B29 | Original GitHub human-review provenance and cross-run consent separation

**Final status: VERIFIED ORIGINAL NEGATIVE EVIDENCE + PASSING INSTALLED PRODUCT REGRESSIONS. No positive case of an independently controlled external human owner was observed.**

Date: 2026-11-13 UTC. Research branch qualification/p6b29-independent-owner-evidence-20261113. Neither risu-probe main nor risu-verify main was changed. All native GitHub API experiments were read-only.

## Core question

Earlier:
- B25 proved a genuine GitHub approval for a controlled one-file write; actual reviewer and requester were the same GitHub account.
- B26 proved owner-issued resource-side enforcement in a RISU-authored service.
- B27 proved claim-specific differences between original PostgreSQL RLS and original SeaweedFS S3 IAM.
- B28 proved original OpenBao-issued dynamic PostgreSQL credentials, one-time credential delivery, exact state change, lease revocation, separate Linux user and an independent resource catalog audit.

B29 asks whether an actual **independent resource owner** authorized the **exact resulting effect**. The new checker treats a valid platform approval, a distinct account, owner/operator control, intent binding, and observed remote effect as separate evidence obligations. It rejects attempts to infer the entire chain from one successful prior step.

## Two real original GitHub negative cases, both verified from fresh GitHub API

[Final original CI #43436411185](https://github.com/risu-research/risu-probe/actions/runs/43436411185).

[Immutable GitHub original refusal evidence artifact #14043563167](https://github.com/risu-research/risu-probe/actions/runs/43436411185/artifacts/14043563167).

### A. B25 valid approval is not independent approval

Original source repository: risu-research/risu-verify, repository ID 1350184511. Run #43355918665. Run attempt 1. Head commit e9409d8ef4a6a71a3a93705909fe5c777d014bbc.

The native original GitHub run succeeded and recorded an approved review for environment risu-b25-human-owner-approval. Original GitHub user ID for run actor, triggering actor and actual approver was the same (208310835). The original environment has native required reviewers but prevent_self_review=false. can_admins_bypass=false, and deployment branch policy is configured. The environment config was last updated before the original run started.

Actual B29 refusal codes:
- GITHUB_NATIVE_PREVENT_SELF_REVIEW_DISABLED
- SELF_APPROVAL_OR_NONINDEPENDENT_PLATFORM_PRINCIPAL

The B25 result remains a valid *platform human approval and observed GitHub write* case. It cannot be described as an approval by a separate owner or even a different GitHub account.

### B. B25 approval must not authorize B28 effect retrospectively

Try to attach the same B25 approved review to the successful OpenBao-to-PostgreSQL B28 run from **another repository** (risu-research/risu-probe, repository ID 1448998079, run #43377450878, source commit 3b756905f30f5c988da1c4c2ee15e7aed3bc0d08).

The original two runs were independently successful in their own narrower studies. They were different repository IDs, different run IDs and different commit SHAs. No legitimate provenance edge makes the B25 review an approval for B28's PostgreSQL row mutation.

Actual additional B29 refusal code:
- CROSS_REPOSITORY_RUN_OR_REVISION_APPROVAL_STITCHING

This is a real-world negative against **evidence laundering via legitimate but unrelated success records**. It is not a newly discovered GitHub vulnerability.

## B29 reusable code and actual native source

Source module: src/risu_mcp_independent_owner_evidence.py
Installed CLI routing: src/risu_p5d_cli.py
Package registration: pyproject.toml
Native code: GitHub read-only REST API for run, exact run approvals, environment, and claimed effect run. GitHub API permission during CI is contents:read and actions:read; no GitHub file, approval, environment, deployment or permission mutations occurred.

Command:

    risu-probe verify-mcp-independent-owner --repo OWNER/REPOSITORY \
      --run-id ORIGINAL_GITHUB_RUN_ID --environment ENVIRONMENT_NAME \
      --effect-repo OWNER/TARGET_REPOSITORY \
      --effect-run-id CLAIMED_EFFECT_RUN_ID \
      --out b29-origin-evidence.json

A refused proof returns process exit code 2 and emits a redacted machine-readable list of unmet obligations. It never outputs or stores a GitHub API token.

Hard requirements:
1. Exact original run identity, repo ID, run ID, attempt and immutable commit.
2. Exact native environment with required user reviewer(s).
3. Native prevent-self-review enabled, no administrator bypass, deployment branch restriction.
4. Current native environment protection last updated no later than original run start. Post-hoc edits or unproven timing are refused, and retries with unbound approval attempts are refused.
5. Exact original approved event from a permitted reviewer with a distinct numeric GitHub ID from **both** run actor and triggering actor.
6. Exact same repository ID, run ID, attempt, head SHA and successful execution in the claimed effect provenance.
7. Separate human ownership and actual content-effect evidence must be obtained independently. The GitHub reviewer result alone never certifies them.

The verifier additionally avoids self-declaring a synthetic fixture as real GitHub proof: artificial examples can pass *structural* checks but cannot be represented as live original API validation. This distinction is preserved in both output status and supported claims.

## Reproducible regression evidence

Three original GitHub Actions runner operating systems, installed actual RISU Probe wheel:

| Environment | B29 dedicated synthetic adversarial tests | Full RISU installed-source regression |
| --- | ---: | ---: |
| Ubuntu | 30/30 PASS | 592/592 PASS |
| Windows | 30/30 PASS | 592/592 PASS |
| macOS | 30/30 PASS | 592/592 PASS |

CI #43436411185. The installed command and prior full RISU functionality were exercised.

Adversarial unit cases include self-approval despite valid reviewer, triggering-user self-review, missing/invalid required-reviewer rule, admin bypass enabled, branch protection missing, historical environment configuration changes, missing run start time, later run attempt without exact review binding, unapproved/rejected review, mismatched environment ID, reviewer not on approved user list, team-only reviewer without independent membership proof, different effect repository/run/commit/attempt, failed run, malformed account fields, malicious API paths, synthetic evidence laundering and secret-free output.

## What this proves and does not prove

**Observed and reproducible:** a valid platform review is weaker than a proven independent account review; a valid run's approval cannot be transferred to another run or repository; a collection of legitimate evidence fragments is insufficient to certify a chain without provenance links. RISU can implement a fail-closed check for these conditions using original GitHub platform records.

**Not yet observed:** a genuinely separately operated human/resource owner approving a user-specific request in their own service or repository. A distinct numeric GitHub account ID also does not itself prove two real humans or actual resource ownership. GitHub environment REST state is current, not a signed historical snapshot; the tool refuses post-run edits but cannot rule out every adversarial policy-history manipulation. GitHub successful workflow status cannot itself establish an original external resource's changed bytes.

**Scientific novelty scope:** B29 does not invent native GitHub required reviewers, OpenBao tokens or RLS. Its contribution is an operational, claim-specific anti-stitching and principal-separation criterion, with original counterexamples and a usable negative verifier. Independent positive evidence remains a separate, essential evaluation objective.

## Positive held-out requirement for B29 completion

The next legitimate positive case requires an **external person who independently controls a protected resource**, acting from their own verified account and holding issuer credentials unavailable to RISU. Their own resource must host or authorize the exact intent, protected job must require a reviewer different from the requester, self-review and admin bypass must be disabled, and their original resource audit must independently validate the same-run change. A reviewer only invited to a RISU-owned repo supplies distinct-account evidence but not independent resource ownership.

No second account, approval, external resource owner or review was invented during B29. No email was sent. Guidance for future operator participation: benchmarks/p6b29/EXTERNAL_OWNER_REPRODUCTION_KO.md.

## Reproduction references

- Frozen prior: benchmarks/p6b29/PRE_REGISTERED_HUMAN_OWNER_PROVENANCE.md
- Original machine-readable refusals: GitHub artifact #14043563167
- Source: src/risu_mcp_independent_owner_evidence.py
- Tests: tests/test_p6b29_independent_owner_evidence.py
- CI: .github/workflows/p6b29-independent-owner-readonly.yml
- Official GitHub deployed environment documentation: https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments
- Original GitHub REST approval API: https://docs.github.com/en/rest/actions/workflow-runs
