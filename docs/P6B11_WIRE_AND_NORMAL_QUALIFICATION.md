# RISU Probe P6-B11 — Normal-Case Reliability and Genuine MCP Wire Qualification

**Date:** 2026-11-08 UTC. **Branch:** `qualification/p6b11-real-stdio-normal-controls-20261108`. **Product state:** qualification preview only; original `main`, B9 and B10 source/scoring remain unchanged; package still declares `0.9.25.dev0`. No population performance or production certification.

## Executive outcome

1. Discovered a real B10 **false-positive** class during a seeded normal-control evaluation: Python `str.splitlines()` treats Unicode U+2028 as a physical line boundary, even when CommonMark preserves that character inside a valid inline code literal. **The initial frozen 1,100 normal / 200 mutated corpus returned 50 false positives, 200/200 injected defects detected, 0 unverified.** Keep this failed baseline unchanged as an auditable result.
2. Implemented a **separate side-by-side preview** `src/risu_display_fidelity_b11.py`, parsing only CR, LF or CRLF as physical capture text line boundaries. The original B10 checker is immutable, Git blob `8bc96f64eba96a314479dfaea17af46b38e1ad0a`; B11 preview blob `007dfb0d829123087ad53e4bfb156630c6adafea`. Optional `risu-probe verify-display-fidelity-b11` CLI is packaged without overwriting `verify-display-fidelity`.
3. **Development replay** over the identical exposed 1,100 normal / 200 injected corpus: 0 false positives, 200/200 injected errors detected, 0 unverified. This replay is rule-development evidence, not a fresh independent score.
4. **Separate, purposive post-discovery challenge**, selected in `benchmarks/p6b11/followup_challenge_prelock.json`: 640 varied normal values including Unicode NEL U+0085, line separator U+2028, paragraph separator U+2029, Korean/Japanese/emoji, Markdown metacharacters, backtick spans, CR/LF and whitespace; 120 injected corruptions. B11 preview: **0/640 normal findings, 120/120 injected corruption findings, 0 unverified**. This is a deliberately selected synthetic challenge, not population specificity or randomly sampled external code.
5. **Authentic SDK STDIO**: a genuine Python `mcp==1.28.0` `ClientSession` connected through a byte-preserving proxy to a real separate MCP SDK server subprocess. It completed `initialize`, `tools/list`, 12 `tools/call` requests; raw bidirectional UTF-8 JSON-RPC frames were saved as base64 of **original frame bytes** with per-frame SHA-256, frame order and whole-capture checksum. Ten valid display values passed, one intentionally injected corruption was isolated to its own named tool, one missing declared line was marked UNVERIFIED. Zero JSON Schema findings. The raw record is not merely a reconstructed JSON-RPC envelope.
6. **Real third-party upstream server STDIO**: official `modelcontextprotocol/servers` Filesystem Server was built at source commit `3bd1337713c796ada8a3dbb088dd911aa83dc932` and official fix `0dce8bd9b65d91a6f7afe1d8f99ffea5d5cf8fe4`. In each version the actual Python SDK client talked to the original external Node MCP server over stdio and its unchanged bidirectional wire was captured in the tee. Normal `read_text_file(head=2)` succeeded in both; old `head=0` read the whole file, fixed returned empty. The opt-in `RMC506` explicit behavior oracle identified only the old. **This is the already-known FS5184 development case from B7/B8 and not new independent detection.**
7. Public-only synthetic data throughout. No actual customer traffic, credentials or remote production MCP endpoints.

## Reproducible evidence with accurate provenance

- Experiment prelock: `benchmarks/p6b11/frozen_experiment.json`, created from B10 commit `f7f3701442e4928387ff49056265d5960ba8294d`, froze the baseline before first B11 evaluation. Original B11 frozen baseline failure is visible in https://github.com/risu-research/risu-probe/actions/runs/42515796717.
- Repair/secondary challenge prelock: `benchmarks/p6b11/followup_challenge_prelock.json`, registered **before the separate B11 source module** was written. Its population claim is explicitly limited.
- The original seeded generator is **unchanged** at `benchmarks/p6b11/normal_stress.py`; `compare_repaired.py` re-executes B10 exactly, then runs repaired checker on the same cohort, then the separate post-discovery challenge with isolated score files. It asserts all categories and fails on any unexplained new anomaly.
- Genuine local SDK stdio: `stdio_server.py`, `stdio_tee.py`, `stdio_client_run.py`, `score_real_stdio.py`. Frame records store `raw_base64`, `frame_sha256`, sequence and direction, and the offline normalizer verifies every reconstructed JSON value corresponds to actual source bytes before scoring. Captures are **locally observed and not externally cryptographically attested**.
- Real external original Filesystem Server stdio: `external_filesystem_tee.py`, `external_filesystem_client.py`, `score_external_filesystem.py`, `.github/workflows/p6b11-external-filesystem-wire.yml`. Both clone revisions and their `src/filesystem/server.ts` Git blob hashes are verified before test-only Node execution. The proxy independently repeats the Git source/commit checks, whitelists its executable and refuses paths other than the known synthetic `sample.txt` data directory.
- Successful external upstream wire GitHub Actions: https://github.com/risu-research/risu-probe/actions/runs/42516821541. Preserved artifact `risu-p6b11-real-original-external-mcp-stdio`, artifact ID `13631357655`; ZIP SHA-256 `879603aaa9e9ac70f561d323521d2b3d153da73ad9dedf388bafcd4a23271356`. Actual frame capture SHA-256 old `7b3e2cf99cf390dfa9972722e6bcf20c71feed9417e07c2819ece13ac048783a`; fixed `80b911202228ce15c1ee788340840184065f2e69af7dcbfcae1b1233d2be03bc`.
- Main qualification workflow: `.github/workflows/p6b11-qualification.yml`. It runs the public-source audit, two immutable detector-hash checks, explicit frozen failure retention, repaired/development and post-discovery challenges, genuine SDK wire capture, and wheel-installed unit tests on three platforms.
- B11 Unicode regression: `tests/test_p6b11_unicode_physical_lines.py`; the earlier Windows `cp1252` test-write failure was test harness only, corrected with explicit UTF-8. The test cases include NEL, LS, PS, actual physical newline mismatches and missing line gaps.

## Results boundaries and scoring discipline

| Evidence family | Grounded observation | Countable claim | What cannot be claimed |
|---|---|---|---|
| Original frozen B10 normal corpus | 50 Unicode-separator false findings on 1,100 declared-normal synthetics | Baseline detector flaw demonstrated | No post-hoc deletion or relabeling of 50 |
| Same corpus B11 rerun | 0/1,100 normals flagged; 200/200 injected mismatches | Bug fixed on development regression | Not new heldout evidence |
| Post-discovery Unicode/Markdown normal challenge | 0/640 normal flagged, 120/120 mutations detected | Purpose-built challenge successful | Cannot estimate general population false positive rate |
| Official SDK synthetic server real stdio | 12 real calls over raw saved frames, 10 valid, 1 deliberate bad, 1 gap | SDK transport and analyzer linkage works | Not a third-party source defect |
| Official external filesystem server real stdio old/fix | Source identity fixed; bug and normal head-two reproduced, optional oracle old-only | Actual external SDK-level STDIO verification, known development case | Not newly discovered or independent detector generalization |

Normal observations are positive only for the selected cases, policy assumptions and protocol versions actually checked. The user-supplied value mapping and behavior oracle remain essential. The changed B11 line parser is a targeted repair, not general Markdown semantic reconstruction.

## Reproduce safely

From this branch with Python 3.11 or newer:

```bash
python -m pip install '.[fidelity]'
risu-probe verify-display-fidelity-b11 saved-public-jsonrpc.jsonl --contract explicit-fidelity-contract.json --format json

# For source/CI reproducibility, rerun the pinned GitHub Actions workflows
# p6b11-qualification.yml and p6b11-external-filesystem-wire.yml on this branch.
```

Both workflows run synthetic-only fixtures; no third-party customer data. GitHub Action archives have a 21-day retention period, so source code and frozen commit pins are the durable reproduction route. Archived ZIP digests identify files, **not cryptographic signatures of executed provenance**.

## Next meaningful gate

**P6-B12 prospective generalization**: Find and preregister new, previously unused open-source MCP servers with genuine safe offline STDIO or SDK protocol executions. Run diverse normal controls from real upstream response formats and capture original wire for each; measure unverified separately from false positives; keep at least one completely untouched source family until all new rules are frozen. Do not merge experimental B11 into `main` or claim population-level precision from purpose-built synthetic distributions alone.
