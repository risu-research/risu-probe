# P6-B35 | First independent source-code holdout, final frozen verdict

**Result:** the B34-developed, unchanged, Python AST channel-projection detector localized a source-level risk hypothesis in **2/4 eligible external Python defects** from new upstream organizations. Two eligible defects were missed. Five additional preselected cases in TypeScript or Rust are explicitly unsupported, not counted as successes or failures in Python sensitivity.

## Original chronological evidence and strict anti-leakage

1. Public baseline commit frozen before B34 or B35: `8d622b792b4ae58b7157fd81ee5f95d6febcfd53`, `risu-probe-preview==0.9.23.dev0`.
2. [B34 original failure audit](https://github.com/risu-research/risu-probe/actions/runs/43492815239) locked at **0/5** static detections, source-only.
3. B35 eligibility and scoring preregistered BEFORE the B34 new rule was implemented: `c73f5a40f4414f97c558d3ce8e5319f8f7ad8839`.
4. Nine third-party merged upstream defect/fix pairs, 12 changed source files, first-parent before SHA and after SHA plus Git blob IDs **sealed before development** in [SEALED_HOLDOUT.json](SEALED_HOLDOUT.json), commit `fa2e6321a0e3ee9de508e8b7d25db219dd5804da`, file Git blob `c04df79b2b07dda5e0e5e2920baf578117bae240`. The original sources were not imported into the development branch or used in writing the algorithm.
5. New *general-purpose* Python AST source projection analysis implemented only against B34 cases in [development branch](https://github.com/risu-research/risu-probe/tree/qualification/p6b34-development-channel-preservation-20261113); frozen algorithm commit `c34def4a25b66cbc89df039ca235d6c1df2094f0`; source Git blob `79c8b45901766179c7e39b17969c726a276e543d`.
6. [B34 development original-source CI](https://github.com/risu-research/risu-probe/actions/runs/43503757880) ran 8 synthetic positive/negative tests and the five original before-and-after pairs. It localized **2/5** source hypotheses and missed **3/5**, with zero candidates in the five corresponding post-fix files.
7. B35 first CI attempt [43504242251](https://github.com/risu-research/risu-probe/actions/runs/43504242251) failed **before any original holdout scanning** due to Python class-scope `NameError` in the evaluator. Only that evaluator's binding was repaired; neither the nine-case seal nor the pre-frozen detector was modified. The subsequent first successful original-source holdout is [run 43504385244](https://github.com/risu-research/risu-probe/actions/runs/43504385244), all steps PASS.
8. B35 result artifact: `risu-p6b35-nine-original-external-fixes-first-look` on successful CI, 90-day retention. Exact results JSON SHA-256: `bcd33f441b0748dc7d34212a2ba57652cc8c2432e46c213310a22a2387adb082`.

## B35 cases, all preselected independent upstream organizations

| Case | Original upstream and fix | Language | New algorithm | Source evidence |
|---|---|---|---|---|
| D1 | [DeepEval #3533](https://github.com/confident-ai/deepeval/pull/3533) | Python | MISSED | SDK 2 structured-content attribute mismatch |
| D2 | [Tencent AI-Infra-Guard #727](https://github.com/Tencent/AI-Infra-Guard/pull/727) | Python | **LOCALIZED SOURCE HYPOTHESIS** | `RSEM102` at original `mcp-scan/mcp_scan/utils/mcp_tools.py:376`: only `result.content[0]` consumed, later content blocks can be lost |
| D3 | [AutoGPT #16265](https://github.com/Significant-Gravitas/AutoGPT/pull/16265) | Python | **LOCALIZED SOURCE HYPOTHESIS** | `RSEM101` at original `autogpt_platform/backend/backend/blocks/mcp/block.py:199`: result's `content` projected without `structured_content` |
| D4 | [PostHog #1166](https://github.com/PostHog/posthog-python/pull/1166) | Python | MISSED | MCP 2.x API/context compatibility |
| D5 | [NanoCoder #1960](https://github.com/Nano-Collective/nanocoder/pull/1960) | TypeScript | UNSUPPORTED | Multi-block result conversion |
| D6 | [Microsoft Playwright #43973](https://github.com/microsoft/playwright/pull/43973) | TypeScript | UNSUPPORTED | Non-JSON evaluation result serialization |
| D7 | [Langfuse #19579](https://github.com/langfuse/langfuse/pull/19579) | TypeScript | UNSUPPORTED | MCP `isError` loss |
| D8 | [TeamCity MCP #556](https://github.com/Daghis/teamcity-mcp/pull/556) | TypeScript | UNSUPPORTED | Failure envelope treated as success |
| D9 | [Affinidi Agent Gateway #201](https://github.com/affinidi-ai/agent-gateway/pull/201) | Rust | UNSUPPORTED | Binary HTTP result converted incorrectly |

## Strict observations and limitations

- All original pre/post GitHub source commits, changed file paths and 24 corresponding Git blobs were validated before processing. 12 source file pairs were examined from nine upstream organizations. Four Python cases had complete source files on both sides and parsed successfully.
- Original public RISU Probe `check` returned **zero static findings in all four B35 Python before sources**. The new algorithm localized two *hypotheses* around actual original fix hunks and emitted no hypotheses on those corresponding post-fix source files.
- Zero candidates on repaired source files is a limited clean-control observation, **not** a validated false-positive rate or proof that every other behavior is intact.
- This is **source-only** first-look verification, NOT runtime MCP execution, not a new previously unknown bug discovery, not external developer endorsement, and not a randomized or blinded survey of MCP systems. The human evaluator knew upstream defect titles during selection, although original B35 source bytes and detector outputs were withheld from algorithm development.
- The Python-eligible 2/4 sample is small; selection favored externally reported and already repaired semantic defects. The 2/4 figure is a within-sample result, not an estimate of overall software defect recall.
- TypeScript and Rust are unsupported rather than negative outcomes. Consequently **2/9**, **7/9**, or cross-language recall figures would be misleading.
- All hit criteria, parent SHA matching, original Git source blob hashing, source-file-only scope and separate Python/TS/Rust denominators were defined before evaluating B35. The evaluator-only scope fix did not change the detector or source cases.

## Algorithmic finding and next phase

The broad, transferable mechanism is **MCP response-channel projection**. The source of a `CallToolResult` may contain multiple content blocks, a separate structured result, media and error status. A consumer that projects a single block or only the text/list content into its own result can erase another observable channel. The current algorithm produces conservative, source-code-level evidence and *does not execute or repair external programs*.

B34 development + B35 untouched first look supports exploring this **narrow consumer-side content channel** further rather than inventing one static rule per upstream bug. Prioritize these changes next: (1) additional normal adapters and negative controls, chosen without inspecting the detector's outputs; (2) independent native MCP stdio producer/result/consumer witnesses to demonstrate an actual effect, with correct side-by-side raw before/after; (3) TypeScript support only if a reliable parser and source-to-sink semantic method can be independently validated; (4) another **new B36 holdout, selected and sealed before any B35-driven tuning**.

**Product decision:** DO NOT merge this new research detector into `risu-probe/main` yet. Existing stable main and B31/B32/B33 behavior remain unmodified. B34 training cases and B35 original holdout are now exposed and must NOT be reused as untouched independent evaluation evidence after further tuning.
