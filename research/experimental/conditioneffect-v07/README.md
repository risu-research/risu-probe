# ConditionEffect v0.7 — frozen research archive

**Status:** experimental, unsupported research checkpoint (2026-11-12). **Not part of RISU Probe CLI, package, detection policy, release, or certified security analysis.** PLDI 2027 standalone-method direction: **NO-GO**.

This folder preserves a narrowly scoped Go AST extractor, a separate Python certificate checker, a mutation suite, and a **byte-for-byte full research ZIP** encoded as Base64. The ZIP includes historical source snapshots and their license notice, reference behavior, reproducibility scripts, original outputs, and research decision notes. It is intentionally archived on a dedicated branch, with no integration into `main`.

## Why retain it

In the **known Overcast historical source**, the extractor labels:
- Before revision `4d08f68d17031e8f31e3f2cd06e2514249984ce1`: `PutObject`, `CompleteMultipartUpload`, `CopyObject` as `MISSING_GUARD_CANDIDATE`.
- After revision `18397a7d68080ffe2142ab0f5aa56e03fa698161`: `PutObject` and `CompleteMultipartUpload` as `STRUCTURALLY_GUARDED`; `CopyObject` still as `MISSING_GUARD_CANDIDATE`.

The original development-set mutation suite has **20 deliberately constructed mutants**, producing 19 `ABSTAIN` and 1 missing-guard candidate, with zero unjustified `STRUCTURALLY_GUARDED` labels. These numbers are **not** an independent accuracy/recall estimate. The referenced external defects and their original fixes predate this experiment.

The independent verifier recomputes only *bounded source-structural obligations*. It cannot prove the behavior of Go helper functions, atomic writes, concurrency correctness, real-world security, or generalization. Positive classification is tied to an exact audited helper-source SHA-256 and specific Go AST shapes. Unsupported variations cause `ABSTAIN`.

## Reproduce locally

Requirements: Python 3.9+, Go 1.23+, and a shell for `run_all.sh`. No private data, credentials, or network access required.

```sh
python3 restore_archive.py
cd restored/PLDI_2027_ConditionEffect_v07
bash run_all.sh
```

On Windows, `py restore_archive.py` works in PowerShell; run `run_all.sh` using Git Bash or WSL, or execute its commands individually. `restore_archive.py` verifies the embedded ZIP SHA-256 before extraction. The human-readable root-level code files here are preserved from the same archive, including exact Git blob content.

Original ZIP filename: `PLDI_2027_ConditionEffect_v07.zip`. ZIP SHA-256:

```
2612dfc24a580de882ae9a2f64f6e0eb5dc006de6fc15ab65d79cc0aca7c2e70
```

## Public evidence and scholarly status

- [Historic source snapshot CI](https://github.com/risu-research/risu-probe/actions/runs/43248553166)
- [Overcast before/after runtime checks](https://github.com/risu-research/risu-probe/actions/runs/43242128469)
- [Extended CopyObject checks](https://github.com/risu-research/risu-probe/actions/runs/43244718690)
- [Floci S3 backend controls](https://github.com/risu-research/risu-probe/actions/runs/43245342708)
- [Overcast issue #1636](https://github.com/overcast-sh/overcast/issues/1636), [issue #1678](https://github.com/overcast-sh/overcast/issues/1678), [Floci PR #4984](https://github.com/floci-io/floci/pull/4984)

The CodeQL comparison proposed for this specific three-operation analysis was **not finalized at the frozen v0.7 checkpoint**. CodeQL already supports Go control-flow/dataflow and domain-specific modeling; this experiment has **no established superiority over CodeQL or novelty as a general program analysis**. Do not cite the archive as a validated production checker.

The original RI​SU Probe `main` and releases remain unchanged. Existing independent/blinded research test sets remain untouched. If a future project reuses this work, create a new reviewed implementation with independent holdout evaluation rather than silently enabling this archive.
