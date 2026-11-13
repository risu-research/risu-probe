# P6-B36 | Independent external holdout, real native MCP stdio controls, and decision

**Status: completed original first look and separately labeled provenance-corrected supplement. Public product `main` remains unchanged.**

## Chronological integrity record

1. The originally published RISU Probe product and generic source-channel detector were frozen at `8d622b792b4ae58b7157fd81ee5f95d6febcfd53` and `c34def4a25b66cbc89df039ca235d6c1df2094f0`, respectively. The detector module Git blob is `79c8b45901766179c7e39b17969c726a276e543d`.
2. **Before inspecting the B36 original source or tuning the detector**, independent eligibility, outcomes and case replacement rules were committed in [PREREGISTRATION.md](PREREGISTRATION.md), commit `39addcda7a62ab7f92d1cf38e7f9468a6438cc8a`.
3. Eight distinct external upstream owner organizations and their original merged before/after repair commits were sealed in [SEALED_HOLDOUT.json](SEALED_HOLDOUT.json), commit `03ba2b9f1b33e2f46eee882dc0b257934ec809fb`, Git blob `d73d8a029c78c216f6a0167d891f63299c89798a`. Five cases are Python primary; three are TS/Rust/Go capability-gap controls. Twelve pre-existing changed source-file pairs were identified; an after-only helper is recorded but not treated as a paired file.
4. The first complete [B36 original Git-blob audit run 43507574960](https://github.com/risu-research/risu-probe/actions/runs/43507574960) finished successfully, recording `0/3` qualifying Python source detections, **2** unverified, **3** other-language unsupported, and no original upstream runtime executions. The first-look JSON SHA-256 is `4076a879bf1c5de179490f7b14f92636ac75536caa20749b9e3dcd76af342b44`.
5. One unverified case, Stitch Manager, resulted from an evaluator manifest **clerical SHA transcription error**: the preregistered source blob string had only 38 hex characters. The actual immutable Git tree contains a 40-hex SHA for the *same* already-selected repository, path and commit. A public [PROVENANCE_ERRATUM.json](PROVENANCE_ERRATUM.json) documents the exact string, original API tree source, original first-look output SHA, and a post-first-look supplement. The original sealed manifest and first-look result remain unchanged.
6. The [separate supplementary evidence run 43509179387](https://github.com/risu-research/risu-probe/actions/runs/43509179387) recorded `0/4` Python source detections and **1** unverified (AgentArea). The same product and exact same frozen detector were used. SHA-256 of the supplementary result is `5ca825162f8f4fdef8b9bea0dfb814ece2d1901dad445b7471f5b3f08d1a85d9`.
7. A separately developed, controlled local **genuine MCP SDK 2.3.0 stdio wire witness** passed on Ubuntu, Windows and macOS: [run 43508400255](https://github.com/risu-research/risu-probe/actions/runs/43508400255). The source is in [research branch](https://github.com/risu-research/risu-probe/tree/qualification/p6b36-real-stdio-evidence-20261113).
8. A further cross-platform [run 43508823004](https://github.com/risu-research/risu-probe/actions/runs/43508823004) connected frozen B34 source hypotheses (`RSEM101`, `RSEM102`) to a **real controlled MCP stdio client** that discarded two of three original content blocks. A normal pass-through client had zero source findings and preserved all blocks and structured data. All three operating systems passed.

## Original eight-case external results

| ID | Original upstream merged repair | Language | Original first look | Supplementary |
|---|---|---|---|---|
| B36A | [AgentArea #957](https://github.com/agentarea/agentarea/pull/957) | Python | UNVERIFIED | UNVERIFIED: original Python file fails to parse |
| B36B | [Daimon #1689](https://github.com/pymc-labs/daimon/pull/1689) | Python | MISSED | MISSED |
| B36C | [Microsoft Agent Framework #9972](https://github.com/microsoft/agent-framework/pull/9972) | Python | MISSED | MISSED |
| B36D | [Stitch Manager #19](https://github.com/StitchWB/Stitch-Manager/pull/19) | Python | UNVERIFIED: malformed 38-hex manifest SHA | MISSED after explicit metadata erratum |
| B36E | [OPNsense MCP #17](https://github.com/meyergru/opnsense-mcp-server/pull/17) | Python | MISSED | MISSED |
| B36F | [Data Fair Agents #95](https://github.com/data-fair/agents/pull/95) | TypeScript | UNSUPPORTED | UNSUPPORTED |
| B36G | [Arcships DIM #1366](https://github.com/arcships/dim/pull/1366) | Rust | UNSUPPORTED | UNSUPPORTED |
| B36H | [CodeReady Toolchain Tarsy #423](https://github.com/codeready-toolchain/tarsy/pull/423) | Go | UNSUPPORTED | UNSUPPORTED |

**Important independent upstream parsing observation:** The AgentArea original source `agentarea-platform/libs/execution/agentarea_execution/workflows/helpers.py` contains the invalid Python 3 syntax `except json.JSONDecodeError, KeyError, TypeError:` at line 918 in the before-fix source and line 927 in the after-fix source. The frozen Python 3.11 AST analyzer refuses that file. This source-level issue is unrelated to the selected nested result sanitization fix and therefore **cannot be scored as a detected MCP semantic loss**, or silently converted to a missed eligible case. An independent syntax-checking tool may investigate this separately.

All evaluable Python source files (three original, four with the erratum) produced zero local source candidates from the frozen public product as well as zero localized candidates from the B34 source-channel detector. The older B35 independent 2/4 result was on different upstream semantic mechanisms; B36 shows a meaningful **coverage boundary**, not a reliable population recall estimate.

## Native protocol controls: what is actually proven

- A locally authored MCP SDK 2.3.0 server process was launched over **real OS stdio**, handling genuine legacy MCP JSON-RPC initialize, list-tools, and calls. The raw request/response transcript was saved as an artifact.
- The producer emitted three content blocks (text, image, text) plus `structuredContent`. A one-block consumer discarded **two blocks and the structured channel**. A one-text-block consumer lost nothing. The negative/error status control distinguished `isError=true` from text-only output.
- A second run used the official MCP `Client(StdioServerParameters(...))` over real stdio. The unmodified, previously frozen B34 source detector emitted `RSEM101` and `RSEM102` on the purposefully lossy consumer function; it produced **zero findings** on the normal pass-through function. Real returned data confirmed two blocks were dropped by the lossy code.
- This is **controlled first-party runtime evidence** that checks a source-to-real-effect connection. It is NOT evidence that these exact original external upstream defects were executed, and it does not establish an external population false-positive rate. It is also not a demonstration of novel unpublished bugs.

## Evaluation limitations and next engineering decision

- Eight targeted cases are retrospective repairs, not a random sample. Only five Python cases were preselected for primary analysis; four ultimately had valid original source and evaluation, following a clearly disclosed mechanical Git SHA erratum. Three other languages remain unsupported. No claim of 0/8 or ecosystem-wide performance follows.
- Source-only static flags are hypotheses even when they overlap genuine original repair hunks. No upstream project source was executed by the sealed holdout harness. Official after-fix sources are paired controls, not an independent normal-source population FPR sample.
- Full-file syntax parsing is an availability bottleneck. A valid project with one unrelated invalid fragment can defeat source-file-wide analysis, as AgentArea demonstrates. The correct next design should isolate parse-error regions and degrade coverage **explicitly**, without inventing a clean pass.
- The detector demonstrates a real **narrow channel projection** mechanism in controlled stdio and two B35 external fixes. It missed four eligible B36 real fixes because error payload propagation, serialization shape/alias handling and structured output schema contracts are distinct mechanisms.
- **Do not merge this experimental source-channel feature to public `main` yet.** Prioritize external normal adapters, native raw protocol producer-to-consumer witnesses in safe original upstream environments, robust per-function parsing and independent B37 held-out cases *before* tuning on B36. Old B36 source is now development evidence and must not be reused as an untouched test.
- Product opportunity remains targeted: RSEM101/RSEM102 could become an opt-in diagnostic with strong warnings and incomplete coverage status if independent normal controls show low false positives. Avoid universal MCP-loss marketing and claims that passing CI means all real-world problems are detected.

**Final state:** B36 sealed first-look and original supplementary report both persisted, native controlled SDK stdio tests PASS on all three OS, `main` remains the original public product.
