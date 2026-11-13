# RISU Probe B29 | Frozen independent-owner and authorization/effect evidence protocol

**Pre-registered before original GitHub live CI.** All B29 original GitHub requests are read-only. The two prior research controls are pinned to their exact original successful workflow runs.

## Question and proof obligations

An independently controlled resource owner must grant a specific action and the original resource service must enforce that action even if the execution gateway is bypassed. B29 separates five distinct checks:

1. GitHub native protected environment really exists, requires explicitly listed reviewer(s), has prevent_self_review=true and can_admins_bypass=false, and has constrained deployment branches.
2. Exact run-specific approval was performed by a GitHub account ID distinct from both initiating actor ID and triggering actor ID. Account display names alone are not evidence.
3. Approved run and claimed execution/effect refer to the same repository ID, exact run ID, run attempt and head commit SHA. No crossing experiments.
4. The approving account is a genuinely distinct person operating the protected resource. Different GitHub account IDs **alone** cannot establish this. Independent operator-control evidence is needed.
5. An exact owner-originated intent (object, prior value/version, desired content, expected state, expiry, use limit) is linked to an independently observed resource effect. Mere workflow success is not sufficient.

B29 currently tests #1–3. It explicitly returns false for the unproven #4–5, even for synthetically valid two-account fixtures.

## Real frozen negative case A: platform review versus independent account

GitHub repo risu-research/risu-verify, workflow run #43355918665, environment risu-b25-human-owner-approval, source SHA e9409d8ef4a6a71a3a93705909fe5c777d014bbc. A genuine GitHub approval and one-file Git effect succeeded in B25.1. But original initiating account and approval account were both the SAME numeric GitHub account, and the native environment had prevent_self_review=false. The new verifier MUST REFUSE independent reviewer proof without disputing the original authorized effect.

Original public GitHub endpoints:
- GET /repos/risu-research/risu-verify/actions/runs/43355918665
- GET /repos/risu-research/risu-verify/actions/runs/43355918665/approvals
- GET /repos/risu-research/risu-verify/environments/risu-b25-human-owner-approval

## Real frozen negative case B: approval from another research experiment

With exactly the B25 human approval, attempt to certify separate successful B28 issuer and PostgreSQL execution from repo risu-research/risu-probe, run #43377450878. The repo ID, run ID and exact head commit differ. Both successful runs must NOT be joined into a single authorization. Any verifier that accepts the pair is defective.

## Synthetic controls (not original evidence)

Construct fake structurally valid cases with actor ID 1001, review ID 1002, exact matching repository/run/attempt/head SHA, required reviewer, prevent self review, and no bypass. Passing synthetic structural checks must not establish independent humans or owner control. Mutate one dimension at a time: self review, alternate triggering actor, missing approval, nonrequired reviewer, team-only reviewer without membership evidence, branch policy missing, admin bypass enabled, run identity changed, conflicting rejection, changed head SHA, changed run attempt, failed original execution, and malformatted ID / path. Check all negatives fail closed.

## Future positive criteria

A genuine separately controlled resource owner must authorize a specific action directly under their OWN real authority. The operator must independently control access to a resource/service, refuse requests and hold credentials outside the agent. For a GitHub-owned resource, enable a native required reviewer DIFFERENT from the triggering actor, prevent self review, disable administrator bypass, and verify immutable requested intent and the same-run effect. A second account without independently demonstrated control remains only a distinct-account review.

Do not automatically create an unprotected GitHub environment that would implicitly approve deployments. A read-only preflight must verify the configured environment before any gated job can start.

## Exact interpretation

GitHub public API demonstrates original numeric account identity and the **current** environment configuration, not a court-quality identity of humans, a timeless historical snapshot of protections, or a resource owner's separate organization authority. GitHub's native run approvals API may not expose a timestamp; never invent it. A success run is not the same as independent original resource byte evidence.

The product may correctly finish B29 with valid negative original evidence and no positive independent owner proof. Preserve that status rather than fabricate a reviewer.

GitHub native docs: https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments
GitHub REST API: https://docs.github.com/en/rest/actions/workflow-runs
