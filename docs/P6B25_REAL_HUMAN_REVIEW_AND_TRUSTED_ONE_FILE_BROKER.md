# P6-B25 | A real GitHub reviewer as the activation authority, with the write credential confined to one trusted writer

Status: **implementation and negative controls verified; actual human review not performed yet.**  
Date: 2026-11-12 US Eastern / CI jobs may be UTC 2026-11-13.  
Owner repo: `risu-research/risu-verify`  
Owner research branch: `qualification/p6b25-real-review-credential-isolation-20261112`  
RISU source branch: `qualification/p6b25-real-review-credential-isolation-20261112`  
Both `main` branches unchanged.

## Trust-boundary question

B23 demonstrated a GitHub-admin-account delegated approval that was signed by GitHub OIDC/Sigstore and then executed by the official original MCP server. B24 showed a separate read-only GitHub Actions agent cannot write through either REST or the original MCP server, while an approved broker job with `contents:write` can write a real one-file resource. But the broker in B24 passed a broad repository write token to the external MCP binary and had no independent human deployment review.

B25 separates three categories of evidence:

1. **Proposed owner request (unapproved):** GitHub organization-owned `risu-verify` file `benchmarks/p6b25/OWNER_PROPOSED_REQUEST.json`, Git object `c66e2630c0c4edf15ee467fb758f601de6370ede`. The original resource is `benchmarks/p6b25/owner_only_resource.txt`, original blob `c84690efad2ac44fa96605a4d1b7c34efbff52de`. The proposal is explicitly marked `UNAPPROVED_UNTIL_GITHUB_ENVIRONMENT_REVIEW_EVENT`.
2. **Human GitHub review:** environment `risu-b25-human-owner-approval` must be configured with `Required reviewers`. The trusted job never interprets mere GitHub `push`, artifact provenance, workflow input or a local Boolean as consent. It queries `GET /repos/risu-research/risu-verify/actions/runs/{RUN_ID}/approvals` and requires an actual GitHub review `state=approved`, named account `moon10021017`, account type `User`, and exact named environment in **this run**. Rerun attempts are rejected (`run_attempt != 1`), as are absent/wrong/robot/rejected approvals. GitHub API records account approval; the API alone cannot distinguish an API-driven approval from a physical mouse click. For the user’s actual requested test, they personally use the GitHub web interface.
3. **Trusted one-file writer:** `human-reviewed-one-file-writer` is the *only* B25 job with a GitHub repository `contents:write` token, and it references the protected environment. The writer does not check out potentially untrusted branch code. Instead it downloads exactly one source module from immutable RISU commit `a81e72024167703036e93a5699f9b2a7c6a0c0ad`, and verifies its Git source blob is `d94b7c4a05db806a0aac143c12a0c10e10899a49` before loading it. The module also pins the exact original owner's Git object. It accepts no arbitrary file, URL or arbitrary agent-executed command.

The owner proposal fixes org and repo numeric IDs, exact branch and file, original Git blob and content SHA-256, exact post-state bytes, allowed commit message, a single exact GitHub Contents API PUT route and a one-time nonce. The writer checks live remote prestate, consumes the nonce using executor-private `O_CREAT|O_EXCL` and executes one hardcoded `PUT /repos/risu-research/risu-verify/contents/benchmarks/p6b25/owner_only_resource.txt`. It checks the resulting immutable Git commit changes exactly that one file and that resulting bytes match the proposal.

**Crucial reduction vs B24:** The official third-party GitHub MCP binary is not run with the privileged write credential in B25. A child agent process only runs as separate Linux UID `nobody` with an empty environment, cannot read parent environment via `/proc`, and its unauthenticated direct GitHub write attempt must be rejected. The sole credential holder is this fixed trusted writer code. The actual original MCP backend-source and official MCP write behavior remain independently established by B23/B24; B25 specifically tests a stronger authorization and credential-confinement boundary.

## Verified engineering and real GitHub negatives

- **538 installed product tests each on Ubuntu, macOS, Windows**: all PASS, including historical RISU and new B25 mocked reviewer/credential controls. <https://github.com/risu-research/risu-probe/actions/runs/43351520641>.
- Actual external separate GitHub run with `permissions: contents:read` and **no human approval history**. The original remote B25 owner file Git blob was confirmed unchanged. A real GitHub Contents PUT to a separate benign fake destination was rejected **HTTP 403**; GET confirmed unauthorized file absent. This was performed before any human authorization and did not mutate `main` or the owner fixture. <https://github.com/risu-research/risu-verify/actions/runs/43351968519>.
- Full owner workflow is committed to `.github/workflows/p6b25-owner-human-reviewed-broker.yml` on the *research branch only*. It triggers **only** upon a future commit to `benchmarks/p6b25/REQUEST_HUMAN_REVIEW.txt`. No such activation marker has been created; the protected writer has never run.
- Independent read-only post-approval audit code exists at `benchmarks/p6b25/independent_human_review_audit.py`. The future audit job can only run after the environment-gated writer succeeds; its credentials are `contents:read` and `actions:read`.
- In the unit tests, a GitHub review with a wrong account, wrong environment, Bot account, rejected state, reused rerun attempt or no reviews is denied **before a single external write**. Tests simulating a valid review may exercise the exact-one-file writer algorithm, but those are explicitly synthetic development controls, not real human approval.

## User's mandatory UI setup

GitHub official environment documentation: https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments

1. Open https://github.com/risu-research/risu-verify/settings/environments and create **`risu-b25-human-owner-approval`**.
2. Enable **Required reviewers** and select GitHub account **`moon10021017`**. For this initial one-person direct approval demo, keep **Prevent self-review** OFF: the same authenticated account creates the source activation commit and will approve its pending job. If a genuinely separate reviewer is available, select that reviewer and enable Prevent self-review for stronger two-person separation.
3. Disable **Allow administrators to bypass configured protection rules** if available, and restrict deployment branches to `qualification/p6b25-real-review-credential-isolation-20261112`. Check configuration is saved.
4. Tell the assistant the settings are complete. The assistant can then create exactly one **`REQUEST_HUMAN_REVIEW.txt`** commit on the research branch to start the workflow without touching default `main` or any previously verified B23/B24 resource.
5. The user personally visits the queued GitHub Actions run, chooses **Review deployments → Approve and deploy** (or Reject), and the GitHub platform creates the actual account-specific approval record.
6. Only if approved does the trusted fixed writer proceed; a separate read-only auditor then checks the run-specific approval, immutable before/after GitHub file states, exact single-file commit and process/token boundary. If rejected, missing or misconfigured, there is no approved write.

No personal access token, GitHub App secret, private signing key or webhook URL needs to be created or shared with ChatGPT. GitHub's short-lived job-scoped `GITHUB_TOKEN` is used. A GitHub `workflow_dispatch` on a research-only branch would normally require the workflow to exist on the default branch, so this proof instead triggers from a narrowly scoped `push` marker to keep `main` unchanged.

## Limits and exact scientific status

- Current CI evidence supports **fail-closed absence-of-human-consent**, actual read-only account GitHub 403 and clean source/credential layout. It does **not** yet support a real human-reviewed successful write or independent observed post-approval outcome. That depends on the owner's actual GitHub environment UI configuration and review action.
- A real approved GitHub deployment record is platform-attested to an account, not proof of legal ownership of third-party assets or that a human used a GUI rather than an authorized API. The owner's specific approval of the named fixture in GitHub UI is a user action not performed on their behalf.
- The broker's short-lived `GITHUB_TOKEN` has **repository-level `contents:write`**, not GitHub-native per-file permission. It is **the fixed trusted writer code and OS subprocess isolation** that constrain the one-file operation. A malicious replacement of the privileged workflow/trusted writer (or a compromise of the GitHub Actions runner itself) could still bypass the program logic. Stronger enforcement would require an external credential broker/identity domain or platform path-level policy independent of the writer code.
- GitHub required reviewer protection availability depends on repository visibility/plan; public repositories support it across current GitHub plans. GitHub's admin approval of a job only releases the job after environment protection rules pass.
- No original code or GitHub owner resource has been modified after a real human approval (because no such approval has yet happened). No new upstream vulnerability discovered. Both `main` branches unchanged.
