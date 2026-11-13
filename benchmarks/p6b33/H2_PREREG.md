# B33 H2 pre-registered distinct-repository, same-organization holdout (2026-11-13)

This file was committed **before the first H2 live GitHub Actions run**. It fixes the distinct target and expected outcome while preserving the B33 verification algorithm already validated on H1.

- First development system H1: `risu-research/risu-verify` Actions run `43458536273` source commit `9b02c07eed9293b3703e484562be322eaec10ac1`; actual one-file effect commit `ccd589714359eaefd8a84335d8d4982596dc6a4c`. Its signed candidate / trusted broker / post-effect signed execution report and separate read-only audit all succeeded.
- **Frozen held-out distinct repository H2**: `risu-research/risu-probe`, research branch `qualification/p6b33-signed-execution-effect-closure-20261113`, workflow path `.github/workflows/p6b33-holdout-signed-execution.yml`, owner target `benchmarks/p6b33/owner_resource.txt`.
- Before bytes exact SHA-256 `3d94021520c4e5cbfe28f22e9a427caafcc8356a551ef54d36ad16c280418870` (Git blob `8aadf1603c17e9966a7831c904ee0dcca620337c`).
- After bytes exact SHA-256 `1edde392ee5291509129d34e99b89385edb978c75ef910e6a7b8628bc962f162` (Git blob `8f9c63d77bbc5d66f94653d8b93bafa7b891094d`).
- One actual `contents:write` broker step separate from original signed `agent_candidate.py` tokenless process; two programs signed before execution; effect receipt signed after original GitHub Contents PUT; separate dependent read-only original auditor.
- The unchanged B33 product algorithm will be evaluated with the native H2 original GHA run ID, `--repo risu-research/risu-probe`, `--workflow-path .github/workflows/p6b33-holdout-signed-execution.yml`, and expected native GitHub actor. Do not relax source/broker digest, actor, timing, exact path or original Git commit parent checks.
- H2 is a **distinct repository and distinct signed original execution**, but belongs to the SAME RISU operator and organization. It is a valid cross-repo implementation holdout, not a separate independent human owner or third-party software publisher.
- Preserve a failing original run, if any, rather than silently substituting another release or pretending it passed.
- Additional **cross-run collision negative**: cryptographically valid H1 signed source, broker, or receipt cannot authorize the different H2 job, resource or effect commit, and vice versa. Both must fail a mixed-evidence join.
- Test quality threshold: two real positive original runs with signed-candidate / signed-broker / signed-receipt, native Git direct-parent one-file effect and independent read-only audit; invalid H1×H2 joins refused; offline structural reports explicitly not signed verification.
- The `GITHUB_TOKEN` is still repository-scoped `contents:write`; the trusted broker enforces exact one-file behavior. No claim of human owner approval independent of the workflow owner or TEE execution provenance.

Original B33 H1 product-verification module was implemented in `src/risu_signed_effect_chain.py` before this H2 execution. The goal is actual second original evidence, not an adjusted source-specific positive.
