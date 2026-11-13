# P6-B37 preregistration: independent repaired MCP defects, conservative static testing

**Frozen before any B37 source-code inspection, scanner tuning, or B37 execution.** Original public product: `8d622b792b4ae58b7157fd81ee5f95d6febcfd53` (`risu-probe-preview==0.9.23.dev0`). Prior development data: B34 H1–H5; B35 D1–D9; B36 B36A–B36H. B37 explicitly excludes *all* those upstream organizations, even where the old rule missed.

## Objective and non-negotiable ordering

1. Record a deterministic set of 8 externally maintained, distinct upstream organizations with genuinely merged bug-fix PRs, original *first-parent* before commit, merged fix commit, and changed original source-file Git object IDs in `SEALED_HOLDOUT.json`. This manifest must be committed **before implementing the B37 scanner**.
2. Build the candidate solely using prior B34/B35/B36 development issues, controlled native MCP stdio first-party results and independently selected normal source. **Do not read the B37 before/after source contents or view B37 evaluation results before committing the candidate algorithm and tests.**
3. Run exactly the locked B37 primary cases and their fixed sibling controls once, with the original published `risu-probe check`, previously frozen B34 algorithm, and newly frozen B37 candidate, each over identical pinned original sources.
4. Disclose everything, including misses. Do not change membership, score definition, or rule implementation after observing B37 results. Any later fixes create development evidence and require a fresh B38 untouched holdout.

## Eligible cohort and scoring fixed in advance

- Primary denominator: seven Python upstream *defect cases*, **one per organization**, where all pinned changed relevant UTF-8 source files can be read from the original Git tree and processed. A single affected file may have source-invalid syntax; an explicitly labeled **partial module** analysis can run over separately parsed top-level function definitions if complete validity is impossible. A partial result is **not** a full-file clean pass and belongs to a separate *partial-analysis cohort*, never silently to fully eligible cases.
- Cross-language capability-gap cohort: one Rust defect; unsupported unless a general Rust AST parser is implemented *before* the holdout is run. Regex-only cross-language scanning is not a valid language-wide capability claim.
- The original Git source file's SHA must equal the manifest and the Git tree path object ID at the exact full 40-hex commit. Fetch the exact blob bytes with `git cat-file blob`; compare commit, tree and blob; never trust transformed worktree content. Any mismatch or missing file is `UNVERIFIED` and **never repaired by choosing another upstream case**.
- Primary **localized source-hypothesis positive** requires (a) generic, previously frozen detector rule, (b) source span intersecting old code changed by original upstream official fix, (c) that exact same rule is absent in paired fixed source for that case, (d) rule's evidence chain plausibly describes the upstream defect mechanism. A generic unrelated warning, error string, source-code keyword or hit in a normal neighbor does not qualify.
- Report per-case `LOCALIZED_SOURCE_HYPOTHESIS`, `MISSED`, `PARTIAL_ONLY`, `UNVERIFIED`, or `UNSUPPORTED_LANGUAGE`; source hypotheses do **not** establish native execution loss.
- False-positive measurement: use separately designed normal controls with independently specified behavior, plus **unmodified real upstream normal functions** chosen before detector outputs. Distinguish synthetic verified normal controls, upstream fixed repair files (which can still have other defects), and unrelated external source fragments. Never equate “0 warnings on repaired source” with a population FPR of 0%.
- Native runtime verification: use actual MCP stdio SDK calls with pinned producer and consumer plus original raw wire record; controlled first-party simulations validate detector causality/false alarms only. Any genuine external upstream execution must separately identify exact upstream code SHA, setup, original wire and controlled impact. Never claim the first-party simulated call is a novel real-world bug.
- If a post-fix repair changes more than one function or file, evaluate all locked focused files, do not count one matching but unrelated function warning as a hit.
- Record per-category raw counts, detailed source span anchors, fixed-pair decisions, exact rule blob SHA, original case manifest blob SHA, GitHub Actions run IDs and result JSON SHA-256; retain original reports as downloadable artifacts. No early abandonment or branch-specific scoring.
- **Product decision:** research branches stay isolated from published `main`. Do not merge experimental detector on the strength of a small, purposively curated retrospective cohort alone.

## Baselines and original source outcomes

The published scanner currently handles a narrow set of Python HTTP/error fields. B34 source-channel algorithm is frozen at `c34def4a25b66cbc89df039ca235d6c1df2094f0` with source Git blob `79c8b45901766179c7e39b17969c726a276e543d`. B36 original source scored 0/3 and provenance-corrected supplement 0/4 (with one syntax-unparseable Python file and three non-Python cases). Those prior results are permanent, and **no B37 development may reinterpret them as independent success after training on them**.

## Why this is a stronger test

The new cases include structured-only result preservation, error flag propagation, SDK-encoding shape, old client compatibility, and multi-channel output. The selection is purposive and does not represent the MCP ecosystem's true prevalence. B37 evaluates coverage boundaries and overclaim resistance under previously unseen upstream source.
