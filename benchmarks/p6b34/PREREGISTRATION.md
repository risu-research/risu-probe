# P6-B34 | Pre-registered independent external MCP defect detection audit

**Baseline frozen before holdout selection and inspection:** `8d622b792b4ae58b7157fd81ee5f95d6febcfd53`, public `risu-probe-preview==0.9.23.dev0`. This is a frozen **commit**, not a promise that future `main` will not move.

## Evaluation contract (locked before measuring outcomes)

- **Unit:** one externally maintained MCP source repository at a pinned before-fix commit plus a linked, publicly recorded issue/fix explaining the actual defect, and if available an independently verified after-fix commit. Independence requires a distinct upstream maintainer organization and exclusion of every bug used in P6 B1–B33 detector tuning or demonstrations.
- **Selection:** record candidates and exclusions transparently. Prefer publicly licensed, original upstream source, explicit before/after correction, executable or directly inspectable oracle, no credentials/production endpoints. Freeze eligible cases **before running RISU**; no selecting cases based on RISU detection.
- **Baseline tested:** installed `risu-probe check <checked-out repository> --format json --strict-incomplete` at the baseline commit only. The read-only default parses Python/OpenAPI; unsupported TypeScript, Rust, Go, PHP or unrecognized source is *out of scope*, not an erroneous scan or a confirmed detection. They can be retained in a separate **capability-gap** cohort but may not inflate the detection denominator.
- **Positive classification:** case counts as detected only if RISU produces a preexisting rule ID and source path/line localized to the bug mechanism in before-fix source, without reading the fix; when verified after-fix source is available, the specific finding must disappear. A generic warning, unsupported scope, or unrelated static candidate is NOT a positive.
- **High-confidence claims:** `SUSPECTED` static findings are hypothesis detections only; no static result becomes a confirmed runtime MCP defect. `CONFIRMED` requires independently obtained raw before/after protocol and consumer witness with provenance; no replay built from labels or an evaluator's synthetic facts can be treated as a native upstream execution.
- **Negative controls:** include genuine upstream normal before/after sibling code or official independent fixed versions, selected without consulting detector output. Count unrelated candidates and false positives separately. Missing negative controls are marked `UNMEASURED`, never zero FPR.
- **Metrics:** eligibility/selection flow, positive eligible detected count and denominator, partial / unsupported / indeterminate / missed, negative eligible FP count and denominator, finding-localization precision, fix-differential specificity, first-diagnosis reproducibility, package/OS portability. Report per language. Never mix structural source findings and true runtime verified effects in one metric.
- **Protection:** no baseline code modifications, rule tuning or post-hoc eligibility changes after outputs. The P6-B34 audit/CI lives on this separate branch; do **not** merge preliminary metrics into `main` or call it product qualification.
- **Leakage:** prior RISU-used external findings are development history; exclude from the primary blinded cohort, even when fixed by a separate third party. Record every candidate and why retained or excluded.
- **Reproducibility:** record immutable `owner/repo@before_sha`, issue/fix URLs, exact setup/CLI command, original source retrieval SHA, output JSON SHA, assessment rule and assertion results. No executing third-party repository code by default. Only download/parse static public files in read-only CI.

## B34 phases

A. Freeze + preregister eligibility and scoring before external case discovery.
B. Identify and independently ground real external MCP defects and true before/after versions; record exclusions.
C. Run frozen product unchanged; commit exact outputs and judge hit/miss and negative controls.
D. Select next action only after reporting baseline metrics. Any subsequent improved detector is B34-development, with a *new* untouched B35 holdout needed to test it.

This preregistration is committed on the audit branch before the first public issue/fix candidate is chosen. The baseline's five current Python source rules (RPY101/102/201/202/203) concern error-body and error-envelope narrowing. This narrow coverage is intentionally reflected in eligibility/denominators, and unsupported languages are not silently treated as covered.
