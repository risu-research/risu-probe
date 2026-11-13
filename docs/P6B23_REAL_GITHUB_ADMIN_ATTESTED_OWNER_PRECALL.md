# P6-B23 | Real GitHub repository administrator grant → pre-MCP gate → independently verified remote effect

Research date: 2026-11-12 US Eastern (evidence jobs continued on 2026-11-13 UTC).  
RISU Probe branch: `qualification/p6b23-github-owner-issued-gate-20261112`  
Actual resource owner branch in separate repository: `risu-research/risu-verify@qualification/p6b23-owner-grants-20261112`.  
Both repositories' `main` branches were left untouched.

## 1. Distinct issuer, executing tool and independent measurement

**Resource owner:** The real GitHub organization `risu-research` (GitHub organization ID 316025762), repository `risu-verify` (immutable repo ID 1350184511). GitHub's authenticated account `moon10021017` had actual repository `admin` permission. Using the user's connected GitHub account, the assistant created one explicit bounded approval file at `benchmarks/p6b23/OWNER_AUTHORIZATION.json` through the GitHub API. Owner grant commit: `4eab2daf0b705df27658f6159f02165da910bcf1`. This is a **real authenticated GitHub administrator's delegated API action**; a separate human owner did not independently click consent.

**External owner signature:** A GitHub Actions job in the *owner repository* independently checked account-level `admin` status through the GitHub API, exact organization/repository IDs and grant scope. GitHub OIDC/Sigstore signed a provenance attestation binding its exact original `OWNER_AUTHORIZATION.json` SHA-256. The original signer workflow was `.github/workflows/p6b23-owner-issued-github-mcp.yml`. The separate executor job had `id-token: none`, couldn't issue the same GitHub OIDC attestation, and independently verified the certificate, signer workflow/ref and the complete attested file through the real GitHub service.

**Actual MCP tool:** Unmodified official `github/github-mcp-server` **v2.1.0**, original November 3, 2026 GitHub release for Linux x86-64, original tarball SHA-256 `a442f9db287cea01008bcb55fe6bc0292270301046c3edbd1a8b22d6e4157b2b`. Its original stdio `create_or_update_file` MCP tool performed the actual repository operation, not an assistant-written fake GitHub tool.

**Independent effect:** A third job without GitHub content-write or OIDC-signing permission used its own read-only GitHub API requests plus `gh attestation verify` to recover the immutable original Git blob, the genuine post-effect GitHub commit, its file diff and the exact original publisher MCP wire. Its code does **not** import the RISU preflight product.

## 2. Precise owner-signed scope

The original owner's grant fixes:

- Organization/repository numeric identities and real GitHub administrator account.
- Research branch `qualification/p6b23-owner-grants-20261112`, exact path `benchmarks/p6b23/owner_sandbox.txt`.
- Tool `create_or_update_file`, full original MCP arguments: owner, repository, path, branch, commit message, replacement bytes, prior file blob SHA.
- Original precondition Git blob `de0b72cd177d6f1bb7153a9925bb3a5bf285d521` and content SHA-256 `63edefc58b885353c97883f1ecd6a70c9063c43b8a80d64585977b35a0e098a1`.
- Required resulting content SHA-256 `185f90a28d7775a1e91341c6a5f25807a9eeff49be86877f9e8468316580de9d`, single-use nonce, validity window, original publisher release/archive hash and `REPLACE` direction.

The executor verifies the exact signed policy document against **GitHub OIDC/Sigstore** and the actual GitHub admin/account/branch APIs before source-original server spawn; it then queries the live original remote Git blob. An untrusted agent cannot replace the signed grant without causing provenance verification failure. A locally owned one-time nonce ledger refuses repeat use of the same approval; the later installed prototype separately checks nonce consumption before the Git blob precondition to prevent misclassifying replay merely as stale state.

**Privilege limitation:** The executor's GitHub Actions job has an actual repository `contents:write` capability. The gate controls the ordinary bounded flow, but malicious code holding the same token could bypass this *application-level* preflight. This does **not** constitute mandatory token isolation or protection against a compromised executor. A production-grade design requires a trusted guard that is the only principal holding write credentials.

## 3. Source-original external behavior observed on GitHub

Original owner issue/executor run (B23 firstpass):
https://github.com/risu-research/risu-verify/actions/runs/43336892730

In the real external GitHub MCP `initialize → tools/list → tools/call` session, the official server emitted 7 native JSON-RPC lines and executed exactly one `create_or_update_file` operation. The result was **a real GitHub server-side repository commit**, not a local fixture file copied in CI.

Actual GitHub commit:
`6e7d3e80a3e2bf327a5a1d394010f6cba99c0467`

GitHub platform independently reports the commit modified exactly the authorized file `benchmarks/p6b23/owner_sandbox.txt`. The original blob was `de0b72cd177d6f1bb7153a9925bb3a5bf285d521`, its replacement blob is `c4c233d165eb354be7bdbb994fc1f49924b46377`. The post bytes contain the exact signed expected marker `state=APPROVED_BY_REPOSITORY_ADMIN`. The before and after SHA-256 values match the owner's signed policy.

Before the one approved source-native write, the executor's preflight logic rejected five independently constructed negative requests: no owner grant, modified owner grant, unauthorized path, wrong branch and different tool. Following the operation it also rejected reuse of the original approval. These six refusals were recorded as zero source-native calls and no original source process launched in the executor code path. Unlike B22, this set **does not include independent OS `execve` traces for the denied calls**; the independent report only supports the scope actually observed.

The user's grant and CI write did not modify either project's `main` branch.

## 4. Independent read-only auditor, provenance and falsification tests

Original independent read-only GitHub audit:
https://github.com/risu-research/risu-verify/actions/runs/43337547529

Stronger historical repeat after auditor hardening:
https://github.com/risu-research/risu-verify/actions/runs/43338759795

The auditor independently verified the real GitHub repository numeric identity, issuer admin permission, authenticated signer workflow actor, external GitHub OIDC/Sigstore attestation, original published binary SHA-256, the original 7-line MCP initialize/list/call transcript, the original pre-change immutable Git blob, exact replacement bytes, actual Git commit `6e7d3e80`, and the one-file changed diff.

A deliberate tamper of each of (1) GitHub owner grant bytes, (2) original MCP stdout protocol bytes, and (3) claimed remote post-effect Git blob was rejected.

**Important audit fix:** The new auditor references the **immutable original effect commit SHA** for the remote after-state rather than the moving research branch tip. A future authorized GitHub owner operation can thus occur without invalidating the historical B23 evidence. This was an auditor-hardening change after the original success; no original effect was modified.

Auditor: `benchmarks/p6b23/independent_github_owner_audit.py`, independent of `src/risu_mcp_github_owner.py`.

## 5. Installed product, regression and transparency

Packaged optional command:

```sh
risu-probe enforce-mcp-github-owner \
  --grant OWNER_AUTHORIZATION.json \
  --original-server ./github-mcp-server \
  --original-archive ./github-mcp-server_Linux_x86_64.tar.gz \
  --authenticating-run GITHUB_WORKFLOW_RUN_ID \
  --approval-mode DELEGATED_OWNER_ACCOUNT_GIT_COMMIT_AUTOMATED_DEVELOPMENT \
  --actor AUTHENTICATED_GITHUB_ADMIN_ACCOUNT \
  --out NEW_EXACT_RESULT_DIRECTORY
```

The **live firstpass used the independent benchmark runner pinned to source commit**
`2f4a59996b2ba0d7d919072828d19fdc1b0e070f`.
This verified logic was copied into the installed module
`src/risu_mcp_github_owner.py`, then hardened with an explicit
executor-owned, non-symlink nonce ledger and early replay classification.
The amended package was not claimed to execute a *second* signed live
write on the now-changed original resource.

Latest installed 3-OS CI:
https://github.com/risu-research/risu-probe/actions/runs/43338260387

**490 tests each on Ubuntu, macOS and Windows, all PASS**.
The new mock negative tests are separate from the actual GitHub-backed
external source evaluation and are never included as new bug discoveries.

## 6. Where independent human/organization authorization stands

**Achieved:** A real organization's actual GitHub repository was acted on through a real authenticated administrator's *delegated connected-account approval*, externally attested using GitHub's independent identity service, and a separate write-restricted auditor verified the remote effect.

**Not yet achieved:** A *separate independently participating natural person* directly approving a grant in the owner's interface. The firstpass owner workflow event is `push`, not `workflow_dispatch`. The grant was published by the user-authorized ChatGPT GitHub connector. This distinction is machine-readable in the report and was not concealed.

A manual owner `workflow_dispatch` branch path has been prepared to generate a fresh signed one-use policy at the current remote resource prestate after checking that the named GitHub administrator explicitly selected `yes`. **No manual dispatch is claimed to have occurred.** GitHub requires workflows with a `workflow_dispatch` trigger to be installed on the repository's **default branch** before that manual UI event can fire. We intentionally have not changed the user's `main`. Thus a separate owner choice to deploy/review that minimal workflow on the owner default branch is still needed to perform direct interactive consent.

Other boundaries: a GitHub Sigstore provenance certificate attests a repo/workflow and subject digest, not whether the grant text is legally valid. `GITHUB_TOKEN` was scoped to repository contents but did not cryptographically restrict the credential to only the named file. This is a successful bounded research proof, not an adversarially unbypassable authorization service.

External upstream vulnerabilities found: **zero**. The contribution is the independently traceable trust boundary and the actual original remote effect.

## 7. Recommended B24

Prefer a **human-controlled owner approval channel** (e.g. administrator-reviewed protected default-branch workflow, verified GitHub app installation identity or customer OAuth consent) combined with short-lived restricted write credentials issued only after signature verification. Enforce the actual target resource through a trusted writer rather than relying on an executor that already holds broad write credentials. Evaluate direct/revoked grants, identity substitutions, wrong repo and current stale-blob controls on an independently administered resource, and retain immutable per-call evidence.
