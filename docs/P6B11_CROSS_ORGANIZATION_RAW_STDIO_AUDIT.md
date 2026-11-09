# RISU Probe P6-B11: Cross-Organization Display-Fidelity Detection on Actual MCP Stdio

**Qualification completed:** November 8, 2026 (U.S. Eastern) / November 9, 2026 (UTC).  
**Status:** isolated experiment branch; no change to product `main`, no new released package or broad recall claim.  
**Starting point:** P6-B10 `15896dadc12d538d2937a6f6253c30148f8f20b5`.  
**Immutable preselection:** `benchmarks/p6b11/prelocked_three_organizations.json`, first committed in `4515e5d753a70bd3566ee1e9e491667e84cf7e19`, before execution of the selected source pairs.

## Result: three distinct open-source organizations, all selected root causes accounted for

| Preregistered issue family | Real upstream source execution and capture | Frozen RISU on old | Official fix | Normal control | Status |
|---|---|---|---|---|---|
| [PARTICULARS15](https://github.com/nodelogicau/particulars-cli/issues/15) · `nodelogicau` | **Native original Go MCP CLI**, actual stdin/stdout JSON-RPC bytes | **RMC509** on `workspace_status` and `topics_list` | zero findings | pass | **verified** |
| [HITCH60](https://github.com/tylerklose/hitch-rails/issues/60) · `tylerklose` | **Original Ruby result normalizer**, unchanged result delivered over real Python MCP SDK stdio test wrapper | **RMC509** on default structured object without author text | zero findings | pass: explicit author text and text-only | **verified** |
| [ROBOT682](https://github.com/robotcodedev/robotcode/issues/682) · `robotcodedev` | **Original Python Markdown formatter**, real Python MCP SDK stdio test wrapper | **RMC507** on literal-code-span `#FF00FF` | zero findings | pass: plain code value | **verified with transparent source revision recovery** |

**Independent cross-run audit:** [GitHub Actions run #42549450253](https://github.com/risu-research/risu-probe/actions/runs/42549450253) downloaded all three earlier real-source CI artifacts, verified SHA-256 of **six exact original captured stdio transcripts**, compared original signed-off family scores with the manifest, and generated `risu-b11-independent-three-owner-raw-stdio-ledger`. It independently confirmed **3 preselected, 3 distinct repository owners, 3 old/fix reproductions, 3 relevant detections, 0 missed, 0 missing, 1 native MCP server + 2 source-to-stdio test wrappers**.

Counts are **defect families**, not tool invocations: two PARTICULARS15 tool calls represent a single defect. The dataset was deliberately chosen from already-repaired historical public issues; **3/3 is NOT a representative sensitivity estimate, and narrow passing normal controls do not establish a population false-positive rate**.

## What changed in the frozen product

The B10 display contract can check explicitly selected JSON pointer values under `markdown-rendered` and `raw-copy` modes. B11 adds one more **opt-in** mode:

**`RMC509`: declared full structured JSON text-mirror mismatch.** The user must explicitly assert that a tool's successful `structuredContent` **must appear as complete serialized JSON in at least one `content[]` text block**. Arbitrary other human summaries may precede the full JSON. Only that specific asserted contract is checked. A tool returning only a brief summary **does not automatically violate the MCP specification**, which generally recommends, rather than universally mandates, a text copy of structured content. Without an explicit user contract, this new rule does not run.

Example `display-contract.json`, for a tool that promises a complete text mirror:

```json
{
  "schema": "risu-mcp-display-contract-v1",
  "rules": [{
    "id": "my_export_contract",
    "tool": "export_records",
    "source": "",
    "content_index": null,
    "prefix_raw": "",
    "mode": "json-text-mirror",
    "on_error": false
  }]
}
```

```bash
risu-probe verify-mcp-trace original_stdio.jsonl \
  --display-contract display-contract.json --format json
```

- Compares parsed JSON trees exactly, including boolean versus integer, nested fields, array order and missing values. Different JSON object member order alone is not a defect.
- Accepts a leading human summary plus a later complete JSON block.
- Refuses duplicate-key JSON, nonfinite numeric literals, missing structured source, ambiguous or oversized captured values, and unsafe/untrusted contracts as described in the B10 bounded checker. When an assessment cannot be safely completed, emits `UNVERIFIED` instead of declaring a mismatch.
- The generic report never echoes raw tool content, and analysis remains offline, bounded and opt-in. Analyzer code does not start external services.
- Frozen P6-B11 analyzer Git blob SHA-1s, embedded in original experiment CI: `src/risu_mcp_trace.py` **`9f017ca0344d94cf54bd0229ddb14d4f586101c8`**, `src/risu_display_fidelity.py` **`6785b2ed912d3e9a41dda956da537dc2e5f4f8e3`**. **Both remained unchanged across source trials.**

## Evidence tier and original wire provenance

The capture script `benchmarks/p6b11/capture_native_stdio.py` sends a bounded synthetic client request through real process stdin; it **preserves every complete original server stdout response line byte-for-byte** and interleaves it with the exact outbound client request bytes. It checks JSON-RPC 2.0 response IDs, successful initialize, advertised tool declarations, protocol version, expected successful calls, bounded size and source executable SHA. Data are synthesized in disposable workspaces. The binary/run environment is isolated, without a real user account, live remote MCP service or credentials.

**Native original server, stronger evidence.** `nodelogicau/particulars-cli` was compiled as its actual original `particulars serve --mcp --workspace …` at immutable old and fixed revisions. The runner made a new synthetic workspace through the actual program. Both versions negotiated MCP `2025-11-25`, and old `workspace_status` and `topics_list` returned structured data while text-only consumers were limited to summaries; `RMC509` captured each in raw output. The fixed program appended complete JSON to text without changing the structured payload, so those findings disappeared. [Native original Go run #42548135441](https://github.com/risu-research/risu-probe/actions/runs/42548135441).

**Genuine SDK stdio, but not the native product transport.** For Hitch, the exact upstream Ruby `Hitch::MCP::Internal::ResultNormalizer` was loaded from each original Git revision and executed using synthetic `Result.structured` objects. An independently written Python MCP SDK test bridge returned **the unchanged canonical Ruby response**, and the scorekeeper compared the Ruby component outputs against the SDK's actual stdout result fields, before applying frozen RISU. The real product speaks Rails/HTTP; **we did not execute the production Rails endpoint**. [Original Ruby + actual SDK stdio run #42549158812](https://github.com/risu-research/risu-probe/actions/runs/42549158812).

**Genuine SDK stdio with a non-MCP upstream formatter.** RobotCode's real `MarkDownFormatter` converted source-code-like docstring text into a display code span, then a synthetic MCP SDK stdio server transmitted that exact formatter output without rewriting text; `structuredContent` supplied the known scalar oracle. The old code-span `#FF00FF` gained an unwanted escape, the fix did not, and the unaffected control was clean. **RobotCode is not itself the native MCP server in this test.** [Original formatter + real SDK stdio run #42549158894](https://github.com/risu-research/risu-probe/actions/runs/42549158894).

### RobotCode source fetch recovery: do not erase this limitation

The initially preregistered old full Git SHA `43aaa4f65df5c30ca6b38eabe4de025bc5123a0f` could be read through the GitHub source connector but was not shallow-fetchable by the runner. Initial source CI failed before execution, [run #42548055678](https://github.com/risu-research/risu-probe/actions/runs/42548055678). A subsequent attempt exposed a separate synthetic wrapper environment defect: resolving the venv Python launcher symlink launched the base interpreter without the MCP SDK. Both errors were repaired **only in the evidence acquisition harness**, without changing the analyzer or the original preselected target list.

The successful source test checked out the **direct parent of the official fix**, `2ed4d2f00c1afb4069744fb607e0243d3b07ab9b`; it has byte-identical **upstream formatter source blob `d5b229f8058cd7312c9afcef1327591f71ce0f94` and imported Markdown helper blob `6c206efd252c86a6ae946b9a2420e0afaee08831`** to those at the preregistered old commit. This supports equivalence of the executed relevant source code, **not a claim that the complete original preregistered Git tree itself ran**. The provenance correction and failed attempt are permanently documented in `benchmarks/p6b11/robot682_execution_recovery.json`.

### Historical chronology and qualification boundaries

- PARTICULARS15: the source correction was already committed October 11, 2026, while GitHub issue #15 was filed on October 30, 2026. We tested actual historical before/after source, not a fabricated chronological sequence suggesting the later issue caused the earlier fix.
- HITCH60: the upstream original Ruby normalizer was executed with actual business-logic input; testing through a Python MCP bridge does not confer Rails endpoint validity.
- ROBOT682: only the original formatter and its source-equivalent helper ran inside a test MCP bridge. Even though genuine original stdio bytes were saved, they belong to **the bridge** rather than an independently implemented RobotCode MCP product.
- The source states passed in the evaluator's own before/fix adjudication before scoring RISU. Source-level outcomes, raw transport integrity and detector findings are reported as separate criteria.
- The aggregate CI does not silently discard non-executed or failed controls: denominator remains 3; `benchmarks/p6b11/aggregate_three_organizations.py` and `tests/test_p6b11_score_aggregation.py` enforce that policy.
- No statistical precision, recall, cross-ecosystem generality or production conformance claims follow from this targeted suite.

## Source artifact identity and reproduction

Each GitHub Actions artifact carries synthetic request bytes and unmodified stdout response byte lines for original old/fix processes, SHA-256 trace fingerprints, source identity from Git commits/file blobs and the frozen RISU score. ZIP digests are **integrity references**, not cryptographic attestations of execution. Artifacts are retained 21 days, until approximately November 30, 2026 UTC; the runnable CI workflows and source pins remain in Git.

| Source family | CI artifact | GitHub-reported ZIP SHA-256 |
|---|---|---|
| PARTICULARS15 | `risu-b11-particulars15-native-stdio` | `5b286faca9a3b9ff916c08d3a2ac88b2bf7485be178174805df5b5de917db116` |
| HITCH60 | `risu-b11-hitch60-original-ruby-bridged-stdio` | `d83dad4bf80efbde0adfe128c6a21324e14b33e7abda85ca81d449a1bde5fcb7` |
| ROBOT682 | `risu-b11-robot682-real-sdk-stdio` | `9566bbfb01a097562184e71856940ede9ebaac24e45f006da5591eb341bb06ac` |
| Cross-run ledger | `risu-b11-independent-three-owner-raw-stdio-ledger` | `8c73673511f9dd3c1c04bf2fbcb82f8192a94dcbf007beb333179c2639e5688a` |

## Additional generated robustness checks

`tests/test_p6b11_json_mirror.py` verifies strict contract validation, JSON tree equality, summary-plus-full-JSON normal cases, missing source, oversized values, duplicate keys, booleans versus numbers, opt-in only behavior and failure-safe redaction. `tests/test_p6b11_score_aggregation.py` guards against cherry-picking, unsupported claimed scores, misclassified native stdio sources and missing negative controls. `tests/test_p6b11_mirror_metamorphic.py` generates **600 healthy JSON mirrors and 600 mutated counterparts** with varied nested values, whitespace, Unicode, object order and summaries. Generated cases are internal tests **not external independent defects**, and cannot estimate real-world false-positive rates.

Run the full platform-specific installed-wheel suite via `.github/workflows/p6b11-full-regression.yml`. New B11 source-level cases were evaluated with the detector frozen **prior** to their execution; extra scoring and harness fixes never altered the rule implementation. All experimental work remains isolated from `main`.

## Best next engineering gate

The technical result is stronger than B10: one genuinely native third-party MCP server plus two real source components carried on authentic MCP SDK stdio, each independently checked against its published fix. The next gate should grow beyond intentionally cherry-picked fixed bugs: obtain **genuinely blind and heterogenous third-party MCP server samples**, additional independent healthy text/Markdown controls, and avoid schema-wide mirror assumptions. Where the upstream product itself offers no MCP transport, keep component and test-wrapper provenance visible. Audit renderer client behavior separately when claiming GUI copy semantics. Only then consider a preview release or broad product-level accuracy claims.
