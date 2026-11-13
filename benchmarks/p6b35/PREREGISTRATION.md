# P6-B35 | Sealed independent holdout and no-leakage protocol

**Sealed before B34-trained detector development.** Product starting point: public main `8d622b792b4ae58b7157fd81ee5f95d6febcfd53`, RISU Probe 0.9.23.dev0. This branch is isolated from the B34 development branch.

## Purpose

Determine whether an **algorithm developed solely with B34's five external failure cases, plus independent development-only normal controls**, generalizes to other, previously unused external MCP semantic losses. These may concern structured content, multimodal content, error status, output shape and remote API-to-MCP bytes. Score the existing frozen product AND the new detector under identical evaluation inputs.

## Locked selection/scoring before development

1. Acquire at most 9 externally authored, *merged*, original GitHub fixes. Record the first parent of the exact upstream fix commit, the merge commit and per-file original Git blob hashes from GitHub. Explicitly exclude the three organizations and issues from B34, every earlier RISU P6 B1-B33 tuning/example and any RISU-controlled source. Several holdout cases can share semantic categories; the *upstream source and defect must be untouched*. Record all excluded candidates and reasons. Prior external fixes are labels, not a claim that RISU itself discovered them.
2. Precommit `SEALED_HOLDOUT.json` before creating any new detector or reading holdout source file contents for algorithm design. Holdout manifest includes exact paths and hashes so evaluation is not cherry-picked. Do not import holdout code into development repo. GitHub provider may see these paths as checkout metadata, which does not constitute detector feedback.
3. Scope: inspect precisely pinned *changed original source files* for each case, not synthetic paraphrases. Python is the **primary cohort**; TypeScript and Rust are mandatory separately labeled **cross-language coverage cohorts**; never silently include unsupported languages in primary sensitivity denominator.
4. Eligible positive detection: new algorithm emits a mechanistically meaningful evidence candidate from the **before** source localized to an actual upstream correction (changed-lines intersection or structural anchor) and corresponding candidate is absent in the **after** source. Original fix itself is not a source-code signature, and string search for upstream project-specific names, line spans, issue text or fixed hashes is strictly forbidden.
5. The result MUST disclose source-fact limitations, e.g. a missing result field on one branch is only `SOURCE_HYPOTHESIS` until paired actual producer and MCP consumer behavior is executed and verified. No algorithm may present a source substring heuristic as a proven dynamic exploit.
6. Negative controls: original post-fix file, same upstream source unrelated helper functions selected before running the detector, and independently normal code. Confirmed false positives require an independently validated normal oracle. A zero finding on five or nine fixed patches is NOT a population FPR.
7. Missing source file, blob mismatch, a scan exception, platform mismatch, unsupported language, missing runtime dependencies or incomplete analysis must be recorded as `UNVERIFIED/UNSUPPORTED`, not as a hit or a clean pass. The B34 outcomes stay immutable 0/5 for the frozen product. Detailed B35 performance must show raw counts for each upstream owner and language, confidence level and complete audit artifact.
8. No post-selection case substitution, rule rewrites or B35-driven tuning before the primary one-time B35 verdict. Any later fixes based on B35 are development data; use a fresh B36 holdout for future claims.
9. Run an honest baseline `risu-probe check --format json --strict-incomplete` at the original frozen commit and the candidate new algorithm over the **same source inputs**, preferably via GitHub Actions read-only jobs. Record SHA-256 of outcomes, job IDs and exact tool version.
10. Never merge B35 raw cases and research harness into public `main`; external source and fixtures stay ephemeral read-only CI checkouts. No upstream project executes during source-only tests.

## Outcome definitions

- `VALID_LOCALIZED_SOURCE_HYPOTHESIS`: complete analysis, a rule with generic dataflow-based rationale detects pre-fix vulnerability source only and localizes to fixed lines.
- `MISSED`: analyzed eligible source, no qualifying detected rule.
- `FALSE_ALARM`: detector returns an actionable defect claim on independently shown normal source.
- `NOT_MEASURED`: evaluation incomplete; do not include in a sensitivity denominator.
- `UNSUPPORTED_LANGUAGE`: detector has no semantic parse for language; count explicitly outside eligible denominator. Source skim heuristics alone are NOT coverage.
- Record `UNVERIFIED` if GitHub lookup, blob/commit validation or after-source availability fails.

**No independent third-party user endorsement or external runtime execution is implied by sourcing third-party fixed commits.**
