# P6-B13 original native MCP discovery, independent first-pass results

Evaluation frozen before upstream execution on 2026-11-12 (US Eastern). The new research branch retains P6-B12’s analyzer bytes exactly. Source selection was informed by public tool documentation; cohort is not random, and no first-pass detector or selected call was changed after observation.

## Executed, selected and verified
- FS2: j0hanz/filesystem-mcp, ff783caf6191eb41f5a3de0e5f924dcc18f770ce. Six preregistered tool calls executed against its native read-only stdio process with a disposable file. Original source stdout SHA-256: e222228be7ad03ace2974df8ea12e2afc7f49a40e0c7a48e70622a86ad4fe313.
- SQL2: rusq/mcp-sqlite, 455a196ac2b2783f7a4250ba4ad6d736ddc6437b. Seven preregistered tool calls executed against its native stdio process, limited to a synthetic SQLite database. Original source stdout SHA-256: 6f7a695496d7ad68236d0633466cd891c0636f78246d1730a6c72eed0081544b.
- Initial workflow: https://github.com/risu-research/risu-probe/actions/runs/43276733731. Both separate original native server jobs succeeded; their original traces, initial scores, scanner results, fixture metadata and provenance hashes were uploaded as separate artifacts.

## Initial frozen outcomes
- FS2: five independent oracles PASS; one UNVERIFIED; zero mismatches; zero RISU findings.
- SQL2: five independent oracles PASS; zero UNVERIFIED; zero mismatches; zero RISU findings.
- In total, 13 selected tool calls, ten successful independent checks, one initially unverified; zero candidate mismatches or confirmed novel bugs.

## Postfreeze correction, recorded separately
FS2's absent-pattern search response from the untouched native stdio artifact carries `_meta.totalMatches: 0` and `_meta.matches: []`. The original evaluation asked only for `structuredContent.totalMatches`, so marked the known-absent result UNVERIFIED. A separate postfreeze audit reads original raw source messages, reconstructs the initial scored checks, confirms the original source hashes, and marks this one check PASS in its **separate** rescore without changing the initial score. The postfreeze total is 11/11 independent checks PASS, zero UNVERIFIED, zero mismatches.

The zero errors and zero alerts from 2 selected nonrandom servers cannot estimate ecosystem detection or false-positive rates. No new, previously unreported root cause was discovered in these probes. No upstream issue was opened, and no code or execution was changed on main or the B7–B12 preserved evaluation branches.

## Reproduction
```bash
# The workflow downloads both artifacts from the exact original run ID.
python benchmarks/p6b13/audit_postfreeze.py \
  --record FS2=.b13-evidence/FS2 \
  --record SQL2=.b13-evidence/SQL2 \
  --out .b13-audit/verified_originals.json
```

The audit checks original source SHA-256, real server response containment in original wire capture, pinned original manifest, unchanged first-pass scores, frozen RISU findings and the separately adjudicated metadata location. The firstpass/score files and sources are read-only input.

## Next decision
B13 has demonstrated reliable acquisition and independent oracle checking on fresh producers, but no unknown-bug discovery. Next experiment should diversify behaviors and publisher origins and precommit richer oracles (cursor/repeated-call consistency, representation fidelity, hidden truncation, authorization gate/no-side-effect). Every candidate must be reproduced independently with a minimal counterexample and a historical issue/fix check; the paper/tool should report negatives and inconclusive cases.
