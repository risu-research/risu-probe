# RISU Probe P6-B33 | Three original Sigstore signatures, runner execution, native job authority and exact Git effect

**Original observations, 2026-11-13. Two positive real signed GitHub Actions runs in two separate RISU repositories; direct one-resource remote Git changes, cryptographically signed original candidate and fixed broker code plus signed post-effect receipt, and independently audited native run identity and timing.**

## Research question

For one claimed authorized execution, which source-specific original observations are required to infer that a particular signed program participated in a request, a specific privileged broker actually changed exactly one resource, and that the original run/actor and times are compatible? Can real and individually valid signing/effect evidence from two **different runs** be falsely combined into one complete action?

This work does not invent a signature protocol. GitHub's `actions/attest@v4` already produces SLSA/in-toto provenance signed by Sigstore; `gh attestation verify` already checks signature, identity and trusted timestamps. B33 evaluates an extra, concrete resource-action join in a GitHub workflow setting with separately retrieved **actual Git state**.

- Official provenance: https://github.com/actions/attest
- Sigstore verification: https://cli.github.com/manual/gh_attestation_verify
- GitHub signed workflow attestation docs: https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations

## Source-specific original positive 1, risu-verify

- Original repository: `risu-research/risu-verify`.
- Original GitHub Actions run: [#43458536273](https://github.com/risu-research/risu-verify/actions/runs/43458536273).
- Native actor: `moon10021017`.
- Exact original source commit: `9b02c07eed9293b3703e484562be322eaec10ac1`.
- Signed original GitHub Actions workflow: `.github/workflows/p6b33-signed-execution-effect.yml`.
- Original candidate source sha256: `4880ccf28667e779645b673990b45e5f27ad533dfec07f0ba9fb59bd9450e6b6`, Sigstore/Rekor [#67239736](https://github.com/risu-research/risu-verify/attestations/67239736).
- Original fixed trusted broker sha256: `f1d7bde4f87eaec2ec9b8a3805d3a54aae2e1b3f8510bbf1315ceae13e79d511`, Sigstore/Rekor [#67239762](https://github.com/risu-research/risu-verify/attestations/67239762).
- Candidate program executed without a GitHub write token, native runner-reported PID 2326.
- A separate trusted broker step with `contents:write` job permission verified the original policy and before-image and executed an actual **GitHub Contents API PUT**.
- Actual Git effect commit: [`ccd589714359eaefd8a84335d8d4982596dc6a4c`](https://github.com/risu-research/risu-verify/commit/ccd589714359eaefd8a84335d8d4982596dc6a4c). Its **sole parent** is the original source commit. Exactly one existing file was modified.
- The broker's post-write original execution receipt has original sha256 `90520f5aaf4ee85ece485b2483a7b9019322e65765be610e7bb843b2ed3c1dfb`; originally signed [#67239795](https://github.com/risu-research/risu-verify/attestations/67239795).
- Native separate readonly audit job #131999205840 independently reverified three signatures, the original run ID, actor, native job times, Git commit direct parent, exact file and before/after contents. **SUCCESS**.

### Actual UTC sequence

| Native or attested original | UTC 2026-11-13 |
| --- | --- |
| Privileged original GHA job starts | 16:01:55 |
| Original candidate source signed with Sigstore | 16:01:59 |
| Original fixed broker source signed with Sigstore | 16:02:03 |
| Candidate runtime start | 16:02:06.060373 |
| Candidate returns (runner report) | 16:02:06.060645 |
| Privileged broker starts | 16:02:06.322610 |
| Actual GitHub remote effect commit time | 16:02:07 |
| Privileged broker finishes | 16:02:08.635970 |
| Original effect receipt signed / Rekor time | 16:02:10 |
| Writer job completes | 16:02:13 |

Original resource path: `benchmarks/p6b33/owner_resource.txt`. Original SHA-256 changes from `3d94021520c4e5cbfe28f22e9a427caafcc8356a551ef54d36ad16c280418870` to `1edde392ee5291509129d34e99b89385edb978c75ef910e6a7b8628bc962f162`. The original Git blob IDs, native diff cardinality and the entire before/after bytes were checked independently, not inferred from the runner's self-report.

## Source-specific positive 2, different repository and different signed code

Before executing H2, the target branch, policy, exact original file, expected two hashes, source program, workflow and read-only auditor were frozen in [H2_PREREG.md](../benchmarks/p6b33/H2_PREREG.md).

- New **distinct repository**: `risu-research/risu-probe`.
- Original second run: [#43461936460](https://github.com/risu-research/risu-probe/actions/runs/43461936460).
- Native original source SHA `846f458a3721ebb42b97217f65e72cbfd0ef5482`.
- Signed workflow `.github/workflows/p6b33-holdout-signed-execution.yml`.
- Different candidate sha256 `18dcd2af4c41b37d58d444989baa18078619079e9af96c7fb271779780c8d696`.
- Different broker sha256 `9789a4b98d3e3eae2bffcce927489e648c7e6a74d776e6b5a9f7443ae2b3d80b`.
- Different signed execution receipt sha256 `243088705c3a461747f86f728d45722efddb3344a7869cebebdeb08762c0a6a7`.
- Original real remote Git effect [`1b5aa13d1dd7116cb4998a769a89740989cead3b`](https://github.com/risu-research/risu-probe/commit/1b5aa13d1dd7116cb4998a769a89740989cead3b). Native read-only audit job PASS and same mandatory direct-parent, one-file pre/post, signer actor/time checks.
- Crucial identity-collision control: both source repositories use the **same fixture relative file path and the same exact before/after file contents**, so matching file path or content alone would yield false joins. Repository, source SHA, actual signed program digest, run ID, signer cert and effect Git commit differ.

These runs are organizationally controlled by the SAME RISU owner. Two different repos are a valid **cross-repository technical holdout**, not proof of external organizational/independent human endorsement.

## RISU installed product algorithm

The shipped-in-qualification-branch code `src/risu_signed_effect_chain.py` is a **read-only original Github Actions + Sigstore adapter**. The installed command:

```bash
risu-probe verify-signed-effect-chain \
  --repo risu-research/risu-verify \
  --run-id 43458536273 \
  --workflow-path .github/workflows/p6b33-signed-execution-effect.yml \
  --artifact-name risu-b33-original-candidate-and-broker-receipts \
  --expected-actor moon10021017 \
  --out ./b33-original-live-verdict.json
```

The verifier reads original GitHub native REST run, job, original immutable workflow, candidate program source, fixed broker source, owner intent, run-original GitHub Actions artifact receipts, original effect commit and before/after bytes. It invokes the **official gh/Sigstore verifier** separately for the original candidate source, broker source and post-effect receipt. Verified X.509 certs must contain the same original repo, source Git ref+commit, workflow identity, runInvocationURI and signed subject SHA-256; signed original timestamp must be chronologically compatible with the trusted native GitHub job + commit timestamps. The source workflow must declare `contents:write` only for the broker job and read-only permissions for the distinct audit job. The exact changed resource Git SHA, one-file diff, direct parent of original source commit and before/after contents must match the source-pinned intent.

It reports high-confidence **platform-authorized same-run signed-source → runner-request → trusted-broker → actual Git effect** under explicitly stated trust assumptions. Structural `normalize` runs against an already normalized record, but its output is deliberately `STRUCTURAL_ONLY_ORIGINAL_SIGSTORE_GITHUB_FACTS_NEED_FRESH_VERIFICATION`, NEVER a claim of fresh cryptographic validation.

Real product CI first positive https://github.com/risu-research/risu-probe/actions/runs/43460058639 and two-positive original/product evaluation (later actual current CI run).

## Adversarial actual evidence comparisons

The test suite `tests/test_p6b33_signed_effect_chain.py` mutates normalized data **after native original GitHub + Sigstore verification** and explicitly refuses cross-run or actor mismatch, signer mismatch, source ref/commit mismatch, changed code digests, candidate runtime identity, different file path, changed pre/post hash, changed parent commit, extra modified file, altered native job permissions, one-use state or claimed external human owner. Time mutations cover program signing after execution, broker signing after runtime, receipt signed before actual effect, real Git commit outside runner interval and reordered runner events.

A separate, stronger **real-positive-to-real-positive collision** joins the original H1 and H2 signatures, receipts, candidate/broker and actual Git commits in combinations. Both originals are individually authentic. The verifier must deny mixed original sources even when the relative file path, before/after file bytes and actor login match. These are *structural post-verification attack controls*, not another cryptographic signing experiment. The intended consequence is preventing **evidence transfer across run/resource subjects**, not claiming native GitHub/gh lacks its own identity verification.

Evaluation must report actual CI test outcomes, not unexecuted plans.

## Assurance boundary

1. Candidate and broker code are genuine, cryptographically verified original artifacts from the specific workflow run and original source. The post-write receipt is a genuine signed record from that original workflow.
2. The **program instruction execution and receipt contents are claims from a trusted GitHub Actions runner/workflow**, not independent cryptographic measurement of machine instructions. No TEE, SGX, external observer or independent hardware attestation was used.
3. The actual resource update is independently verified from native GitHub original Git commit, Git blob and diff, not merely trusted from the signed receipt.
4. GitHub Actions `GITHUB_TOKEN` write permission applies to the repository. It does **not** cryptographically constrain this token to one file; the specific write path and exact bytes are enforced in fixed trusted broker code.
5. GitHub original source owner and signer are operated by RISU. The fixture operator committed policy intent; no separate independent real human owner approved it. Never describe it as a third-party owner consent proof.
6. GitHub/Sigstore existing provenance implementation remains the signature/identity baseline. B33 adds a concrete cross-evidence **resource-action correspondence condition**, not signature correctness or cryptographic superiority.

## Promotion guidance

Promote the read-only verifier CLI, package registration, negative tests and documentation to RISU Probe stable `main` **only** after both genuine original runs, native signatures, cross-run collision attacks, full Windows/macOS/Linux installed product suite and original single-run audit all pass. Never merge the experimental Verify/Probe privileged writer workflows or owner fixture to stable main; they remain qualification evidence only.

Next external validity target: independent third-party publisher execution records with same-run crypto attestation and actual resource effects, preferably a different genuine operator. That is beyond the present two-original-repository experiment.
