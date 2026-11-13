# P6-B24 | Actual owner-issued permission with no-write agent and credential-isolated original MCP broker

**Research date:** 2026-11-12 US Eastern (GitHub Actions UTC 2026-11-13).  
**RISU branch:** `qualification/p6b24-no-bypass-owner-broker-20261112`  
**Actual resource owner branch:** `risu-research/risu-verify@qualification/p6b24-owner-authority-20261112`.  
**Status:** genuine external GitHub OIDC owner provenance; original read-only untrusted HTTP and MCP writes denied; one source-original official GitHub MCP write by separated credential-bearing broker; independently audited. No `main` change.

## 1. The new security boundary

B23 verified actual repository administrator authority and GitHub's signed provenance but the *executor itself* held the same contents-write token required by the original MCP tool. An untrusted agent with that token could bypass an application gate.

B24 changes the **capability graph**, not merely a boolean policy verdict:

| Independent GitHub Actions job | GitHub token | Can issue OIDC attestation? | Source/native role |
| --- | --- | --- | --- |
| `owner-provenance` | `contents:read` | **Yes, `id-token:write`, `attestations:write`** | Validate owner account and sign exact owner grant file |
| `untrusted-agent` | **`contents:read`** | No | Exercise bypass: real direct GitHub REST PUT and original GitHub MCP write |
| `trusted-broker` | **`contents:write`**, limited to this repository and job | No | Verify external signer and exact owner precondition; execute only one approved original MCP call |
| Independent follow-up auditor | `contents:read`, `attestations:read` | No | Revalidate real repository resources and complete original source/native evidence |

GitHub assigns a separate installation token to **each** GitHub Actions job. The untrusted agent cannot receive the trusted broker job's token through normal job-scoped GitHub Actions credentials. The broker runs as a separate job after the untrusted bypass attempts and uses the official GitHub MCP binary; no untrusted agent script is ever executed inside the broker job.

GitHub documentation on job tokens: https://docs.github.com/en/actions/concepts/security/github_token

**Critical distinction:** `GITHUB_TOKEN` contents:write is **repository-scoped**, not file-path-scoped. The trusted broker enforces the one-file policy in its own pinned source; its underlying GitHub credential is not restricted to that file by the platform. A compromised broker, its token or its original MCP binary is outside the enforced no-write-agent boundary.

## 2. Real owner identity and exact signed scope

A connected authenticated GitHub admin account `moon10021017` issued one B24 grant in the actual GitHub organization `risu-research` (organization ID `316025762`) and organization-owned `risu-verify` repository (repository ID `1350184511`).

Owner grant GitHub commit:
`f21a899fe5466963b19bfcc8986e10c11776afae`

Owner resource:
`benchmarks/p6b24/owner_only_resource.txt`
at
`qualification/p6b24-owner-authority-20261112`.

Original pre-change Git blob:
`bd6b674299ba329d871bb05790a85cab3a1f4e5f`.
Original content SHA-256:
`80b7fab7d10f7e5be558c42d664135f9e07ad45680f7cb3b3d6a6acbceabfd0f`.
Required resulting content SHA-256:
`b792024d10b7d1611b12dd59c4efde3529e84c7dcaffea29c6bfdf3dbf319774`.

The exact grant also constrains the `create_or_update_file` MCP tool, complete owner/repo/path/branch/commit-message/content/`sha` arguments, intended `REPLACE` effect, source-original release SHA-256, a unique nonce and time window.

**Actual authorization source:** a real organization administrator **delegated connected-account action**. The event was GitHub `push`. The original grant was signed by GitHub's OIDC/Sigstore attestation process in a separate read-only owner-provenance job. The trusted broker separately verified the attestation, actual admin permission, actual organization/repository IDs, GitHub workflow actor, exact grant bytes and original live file prestate before executing.

This is substantially stronger than a self-signed ephemeral CI owner: GitHub is the independently consulted identity/repository authority. It is **not proof that a separate human explicitly clicked Approve**. No separate natural person or external organization consented in the GitHub interface.

Owner/effect run:
https://github.com/risu-research/risu-verify/actions/runs/43341365204

## 3. Real untrusted-agent bypass tests, not merely a mocked result

In the actual independent `untrusted-agent` job with **only `contents:read` token**:

1. A direct authenticated REST `PUT /repos/risu-research/risu-verify/contents/benchmarks/p6b24/UNTRUSTED_DIRECT_HTTP_MUST_NOT_APPEAR.txt` was sent to GitHub. GitHub returned **HTTP 403**.
2. The untouched official **GitHub MCP Server v2.1.0**, archive SHA-256
   `a442f9db287cea01008bcb55fe6bc0292270301046c3edbd1a8b22d6e4157b2b`,
   was launched directly by the untrusted principal using that same read-only GitHub token. The real MCP `initialize → tools/list → tools/call` wire was recorded. The source-original `create_or_update_file` request targeted another harmless synthetic research-branch file. It returned `isError:true`, with the actual GitHub API **403 Resource not accessible by integration** failure.
3. GitHub GET requests confirmed both unauthorized paths were **absent**. The actual protected owner's initial Git blob remained unchanged before the later broker action.

No real private user data, credentials, repo defaults or unrelated files were touched. The denied HTTP request and original MCP tool call were actual external requests, not simulated policy refusals.

The successful firstpass job:
https://github.com/risu-research/risu-verify/actions/runs/43341365204

## 4. Trusted-broker only positive real external MCP effect

Only after the untrusted denial job succeeded did the **separate job** with `contents:write` start. It had no OIDC `id-token` signing privilege and could not legitimately reissue the owner's source-grant provenance. It downloaded the issuer artifact and verified its exact GitHub/Sigstore signer workflow identity.

The broker executed the official source-original `github/github-mcp-server v2.1.0` binary, using its own job-local GitHub write token. The complete native MCP protocol was captured and the official tool committed the exact signed replacement, resulting in genuine GitHub commit:

`140b47158ee6e03327e8fb8a98380479d0cd2554`

Actual resulting file Git blob:
`9a4caec165143b9fd6b4c57c09f410aaa36cc141`.

The actual source-native write changed `benchmarks/p6b24/owner_only_resource.txt` **and no other file**, as checked against GitHub's immutable remote commit diff. Exact expected file content now includes `status=OWNER_APPROVED_BROKER_EXECUTION`.

The broker additionally checked five forged/out-of-scope grant variants before starting the one official write, and refused reuse of the signed nonce afterwards. These local gate refusals are **additional to** the real 403 + real original MCP write denial of the untrusted job; do not combine them into one "external REST denials" denominator.

## 5. Third read-only job independent of product code

A completely separate read-only auditor imports neither the trusted broker nor the untrusted agent policy implementation.

It independently verifies against GitHub APIs:

- Actual issuer organization/repository IDs, admin permission and GitHub OIDC/Sigstore subject digest.
- Owner's original Git grant commit and authenticated workflow actor.
- Exact immutable original Git blob and approved bytes.
- Actual official GitHub publisher MCP native seven-line transport and exact `create_or_update_file` request parameters.
- Actual immutable GitHub effect commit, its single modified file and resulting exact content SHA-256.
- Independent untrusted agent REST 403 evidence and source-original MCP error response, original native wire digest and actual absence of two unauthorized paths.
- **The original GitHub Actions workflow source from the actual owner run's immutable head SHA**, proving that owner signer, untrusted agent and broker jobs had distinct declared token scopes.

Read-only auditor CI:
https://github.com/risu-research/risu-verify/actions/runs/43342185893

Falsification controls:
https://github.com/risu-research/risu-verify/actions/runs/43342408153

Three independently corrupted pieces of evidence were all rejected: owner grant's signed tool content, agent's native MCP transport bytes, and broker's claimed final GitHub blob.

The historical audit references the immutable actual effect commit `140b4715` rather than the moving owner branch head, allowing future research to proceed without destroying the original evaluation.

## 6. Installable RISU product and independent qualifications

New opt-in command:

```sh
risu-probe enforce-mcp-owner-credential-broker \
  --grant OWNER_OIDC_SIGNED_GRANT.json \
  --original-server ./github-mcp-server \
  --original-archive PINNED_GITHUB_MCP_v2.1.0.tar.gz \
  --authenticating-run ORIGINAL_OWNER_WORKFLOW_RUN_ID \
  --approval-mode DELEGATED_OWNER_ACCOUNT_GIT_COMMIT_AUTOMATED_DEVELOPMENT \
  --actor GITHUB_ADMIN_ACCOUNT \
  --out NEW_RESULT_DIRECTORY
```

This command is **only meaningful inside a separate restricted trusted-broker credential context** and deliberately refuses when `B24_TRUSTED_BROKER_JOB=yes` is absent. This marker is operational configuration, not a security secret. GitHub job token isolation is the actual permission boundary.

The live firstpass used the immutable benchmark source at commit
`135c79567f1df99ca68e0f8ad40b58a01123140c`. It was subsequently packaged in
`src/risu_mcp_owner_credential_broker.py` and strengthened to classify a
consumed signed nonce before reporting a stale original Git blob. Tests for
original scope/identity, replay, never executing a native write from an
untrusted product invocation and full older RISU regressions were added.
Do not misstate the installed product's later replay-classification edit as
a second actual authorized GitHub remote write. **One actual remote
positive commit** is the original evidence.

## 7. What still separates this from independent human consent or a general strong gateway

- **Human direct consent:** The connected authenticated GitHub repository admin delegated the approval; no separate independent human clicked a required GitHub environment reviewer control. The owner side must configure a protected required-reviewer environment or a verified independent external owner's signing service. No such manually reviewed job is claimed.
- **Credential isolation:** The untrusted GitHub Actions job has no write privilege. This is actual effective GitHub permission isolation in the tested workflow. The broker still holds contents:write for the **whole repository**, so a malicious trusted broker or malicious upstream server could violate the file-level policy.
- **No transfer to arbitrary agents:** A local process outside this controlled GitHub Actions job system might possess another credential; B24 only certifies the isolated job topology tested. Other MCP tools, other GitHub installations, hidden effects or a race-free general filesystem capability sandbox were not tested.
- **No novel upstream security defect:** GitHub's official server behaved correctly in positive and negative controls. This was a security-boundary qualification, not blind bug discovery.

**Next highest-value milestone:** owner-reviewed manual authorization from an independently operated account together with a trusted credential broker whose only write capability is a single approved resource, ideally through a narrow GitHub App installation and GitHub-enforced protected resource rules. A `workflow_dispatch` directly invoked by an authenticated owner requires the workflow to be on GitHub's default branch; configuring required environment reviewers also requires an explicit repository owner UI action. Neither was silently performed here.

References:
- GitHub GITHUB_TOKEN per-job uniqueness: https://docs.github.com/en/actions/concepts/security/github_token
- Deployment environment required reviewer approval and prevent self-review: https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments
- GitHub App installation tokens can be restricted to repositories and permission categories, not arbitrary file paths: https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation
