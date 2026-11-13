# P6-B36 | Independent holdout preregistration

**Evaluation rules fixed before candidate detector tuning and before looking at original selected source code.**

Baseline: published RISU Probe main commit `8d622b792b4ae58b7157fd81ee5f95d6febcfd53` (0.9.23.dev0). Previously developed B34 generic source-channel detection algorithm `qualification/p6b34-development-channel-preservation-20261113@c34def4a25b66cbc89df039ca235d6c1df2094f0`, source Git blob `79c8b45901766179c7e39b17969c726a276e543d`. B35 is now **development history** and may inform a later, explicitly timestamped candidate algorithm, but not the original B36 first-look.

## Primary goal

Audit independent real upstream MCP loss repairs on original before/after source, with separate sound normal controls and, if possible, real native MCP stdio witnesses from safely controlled producers. Distinguish (a) static source candidate, (b) actual verified MCP runtime loss, (c) absence of findings, (d) incomplete coverage and (e) unsupported language. A read-only source test never equals confirmed runtime defect.

## Holdout criteria fixed in advance

- Up to eight merged GitHub fixes, different maintainer organizations, no repos or defects used in RISU B34 or B35. No historical B1–B33 issue re-use where identifiable. Select on published issue, source edit and original upstream repair **without consulting RISU detector output**. Archive selection/exclusions. Check original merge SHA and its first parent, plus before/after original Git file blobs. Inaccessible/invalid pre-commits are NOT replaced later.
- Primary eligible cohort: original UTF-8 Python source files at original pinned commits, with unmodified Py-3 AST analysis, successfully parsed. Include exactly the cases selected, record any incomplete files, do not omit cases because of misses.
- Cross-language Rust/Go/TypeScript sources: only exploratory capability-gap cohort. Generic Python rules must state `UNSUPPORTED_LANGUAGE` with no cross-language sensitivity claim.
- Positive static: at least one *pre-existing generic* rule candidate in the exact original source before correction, localized to the actual changed pre-fix region, and absent after upstream correction. No mere file-wide warnings, no human-coded paths/issue IDs/line numbers. `SOURCE_HYPOTHESIS` only. If rule appears both sides, it is not a paired differential hit.
- Different candidate algorithms: require frozen exact commit/blob and a separate preregistered comparison. The primary B36 first look runs B34's frozen previous algorithm first; no B36-dependent tuning. Any later algorithm revisions trained on B35 but not B36 can be run only after their own source blob is fixed and compared without inspecting B36 outcomes. The first B36 result becomes exposed development data once inspected.
- Normal controls: include repaired source plus separately authored/selected normal source scenarios with an independent semantic specification / execution reference. Post-fix source with zero warnings is **not an estimate of population FPR**.
- Runtime: native tool-client-server original MCP stdio calls should be recorded at JSON-RPC boundary using a minimal, sandboxed, credential-free server. For original upstream runtime claims require original pinned upstream code executing and protocol evidence; a synthetic demo only certifies the **checker** ability to observe loss. Clearly distinguish from original external execution.
- FPR: report `UNMEASURED` unless independent normal oracle cases and rule-level denominators are measured. Distinguish exact type of normal source and potential still-unverified behavior.
- Metric disclosure: per-case original repository and commit (full Git SHA), source path + blob SHA, line anchor, baseline result, candidate source warnings before/after, count of eligible Python cases, number of unsupported external languages, tool/job logs and SHA-256 of output, native runtime provenance. Never infer ecosystem-wide recall from small purposive sample.
- Reproducibility and safety: all upstream source is checked out read-only and never executed by default, no passwords, tokens, network calls made by test code. Fail closed when Git integrity or manifest changed; artifacts contain only results, not upstream full source.
- Product policy: do NOT merge experiment into public main or claim bug discovery; a source hypothesis on an upstream bug fixed by its own maintainers is retrospective detection.

## Stop conditions and future work

B36 first-look report must retain misses; never replace sources after seeing scanner results or retune then claim the same data as independent. Afterwards, treat B36 as development and seal fresh B37 for future independence if additional detector rules are designed.
