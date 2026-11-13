# P6-B34 | Frozen public product vs. five external MCP losses

**VERDICT: ZERO LOCALIZED STATIC DETECTIONS IN FIVE PRESELECTED EXTERNAL CASES.** The audit *succeeded* as an evidence-producing experiment; its **detection result was 0/5**.

## Strict chronology and reproducible inputs

- Product frozen before selection: `8d622b792b4ae58b7157fd81ee5f95d6febcfd53`, `risu-probe-preview==0.9.23.dev0`.
- Eligibility/scoring registered in `PREREGISTRATION.md` commit `bf9fc4cb34c1f03facc5e76bfc5c577ae55560d5`.
- Five external defect/fix source pairs locked in `LOCKED_HOLDOUT.json` commit `a8738974164a6b8408fd346dc86e1160af98df9a`.
- Locked manifest SHA-256: `c792681528ad26e3ca8f7d4df30e42c4853ce354b24fdb9817f2dab17731f385`.
- Exact original upstream Git SHAs and individual source Git blob hashes verified **before** scanner invocation for every before/after source.
- Actual audited execution: [GitHub Actions run 43492192850](https://github.com/risu-research/risu-probe/actions/runs/43492192850), PASS. The published baseline output JSON SHA-256 is `d638a10cd72d9122bcb8117a8c539eeaf71448917909970459d2c708e8c3ab59`.
- Result artifacts: `p6b34-preregistered-frozen-external-holdout-results` on that run (90-day artifact retention). The exact original JSON also contains all ten detector output records and input file SHA-256 digests. The source code was never copied into the artifact.

## Primary holdout outcomes

| Pre-locked case | Independent original defect + official fix | Before status | After official fix | Localized detection |
|---|---|---|---|---|
| H1 | [AgentScope #3389](https://github.com/agentscope-ai/agentscope/pull/3389) structuredContent lost when TextContent absent | NO_STATIC_FINDINGS | NO_STATIC_FINDINGS | MISSED |
| H2 | [Hermes Agent #21328](https://github.com/NousResearch/hermes-agent/pull/21328) ImageContent silently dropped | NO_STATIC_FINDINGS | NO_STATIC_FINDINGS | MISSED |
| H3 | [MCP Python SDK #3756](https://github.com/modelcontextprotocol/python-sdk/pull/3756) typing.Dict wrapper shape changed | NO_STATIC_FINDINGS | NO_STATIC_FINDINGS | MISSED |
| H4 | [MCP Python SDK #3758](https://github.com/modelcontextprotocol/python-sdk/pull/3758) bare dict structured output absent | NO_STATIC_FINDINGS | NO_STATIC_FINDINGS | MISSED |
| H5 | [MCP Python SDK #3812](https://github.com/modelcontextprotocol/python-sdk/pull/3812) unknown capability metadata lost | NO_STATIC_FINDINGS | NO_STATIC_FINDINGS | MISSED |

Aggregate: **5 eligible source-file cases**, **5 original files parsed**, **5 post-fix files parsed**, **0 localized pre-fix-only hypotheses**, **5 missed**, **0 unverified**, **0 candidates on the five post-fix source controls**, **3 independent upstream maintainer organizations**. The original defect labels and fix PRs were visible to the evaluator; **the detector code and decision rule were locked before results**. Do not call this a blinded/double-blind study or imply an external independent human ran the audit.

## What these numbers mean

The public `risu-probe check` default is conservative, read-only Python/OpenAPI source analysis. Its existing RPY101/RPY102/RPY201/RPY202/RPY203 static rules concern *HTTP error fields, exception summaries and error-text truncation*. The five selected cases are *valid MCP semantic loss cases in different field/type/schema paths*. Thus the observed 0/5 is a direct **coverage gap** of the currently shipped public rules on this preselected set. It is not a failure of CI, and `NO_STATIC_FINDINGS` is **not** an assertion that the upstream buggy code is safe.

The audit used sparse original upstream checkouts targeting **one exact changed Python source file per case**, matching GitHub Git blob SHA before analysis. It did NOT scan complete upstream repositories, execute third-party code, start external MCP servers, or collect native original MCP wire traces. Therefore it did not measure actual running MCP protocol behavior, whole-project recall, comparative performance against MCP Inspector, or effectiveness of optional non-default RISU commands.

The three Python SDK cases include two sequential fixes touching the **same source file**. Cases are independent fault instances but **not five independent organizations or five independent SDKs**. Zero warnings on five official post-fix controls is a narrow observation, **not a population false-positive rate**. The original upstream pull-request evidence supports defect/fix provenance, not independent first-hand runtime proof generated in B34.

## Explicitly excluded from primary cohort before testing

- Python SDK #3644: duplicate issue, proposed #3650 fix unmerged.
- Python SDK #3385: closed not planned, proposed #3429 fix unmerged.
- Python SDK #3843: open, no merged repair control.

## Decision and next test design

**Do not tune on this holdout and then report the same five as an independent success rate.** Retain the frozen result above permanently. For a possible next development phase, H1–H5 may become a *training/development set* for narrowly specified semantic-preservation checks:

1. Track information flow from MCP `structured_content`, image content blocks, and capability metadata through response adapters; prove a field is dropped before claiming a result.
2. Separately check schema/type transformations such as `typing.Dict` versus `dict` and bare `dict` annotations, rather than inventing a universal rule that would be prone to false positives.
3. Require normal implementations and actual pre/post remote original sources as negative/positive controls, and native MCP stdio execution only when the risk is contained.
4. Preselect a **different, untouched B35 external holdout before implementing rules** to estimate actual generalization. Prior H1–H5 cannot be reused for claimed out-of-sample sensitivity.
5. Do not merge experimental detection logic into product `main` until independently verifiable value and conservative false-positive behavior are demonstrated.

**Status:** Frozen B34 baseline complete; no public product code or CI status changed by this research branch.
