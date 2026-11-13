# B32 held-out publisher policy, sealed after implementation (2026-11-13)

The B32 source implementation and main-installed product tests were committed and passed as of qualification SHA a3ab9b0faaa377a2d2ce3fba4e4ee7d2c92caea0, before observing either H5 or H6 cryptographic attestation or their signed subject names.

**H5, independent new publisher**: `klodr/gmail-mcp`, release `v3.0.0`, original GitHub release asset `index.js`, official release SHA-256 `682301b9d0aaf51fbdbd05a1abea28387f1f4d06bfb9a0490a47e6421960cc4e` (223,312 bytes). Original source workflow is `.github/workflows/release.yml`; GitHub tag-event source ref expected `refs/tags/v3.0.0`. Pre-set expected signer certificate identity `https://github.com/klodr/gmail-mcp/.github/workflows/release.yml@refs/tags/v3.0.0`.

**H6, second independent new publisher with different signed artifact class**: `libredb/libredb-studio`, release `1.3.0`, original GitHub release SBOM asset `libredb-studio-1.3.0.cdx.json`, official SHA-256 `7baef425849d7e54252bdf7bddb552f8fb27de39f0069e88c3af7efbcd4e87e8` (641,245 bytes). Original source workflow (inspected BEFORE first cryptographic run) is `.github/workflows/release-artifacts.yml`, whose SBOM job uses `actions/attest-build-provenance` on `sbom/libredb-studio-*.cdx.json`. The tag-event source ref expected is `refs/tags/1.3.0`. Pre-set expected signer certificate identity `https://github.com/libredb/libredb-studio/.github/workflows/release-artifacts.yml@refs/tags/1.3.0`.

## Frozen independent evaluation

1. Official `gh attestation verify --repo SOURCE` against actual bytes is the cryptographic baseline, with original source and signer identity. It is NOT an owner-permission baseline.
2. Reuse B32 main-based implementation `risu_delegated_signer.py` **unchanged**. It matches exact signed subject name or a single optional leading `./`; it has no general `dist/` or `sbom/` path alias rule and does not silently accept unknown subject names.
3. Compare GitHub baseline and RISU's additional policy acceptance for these *new* publishers. A native PASS + RISU refusal is a measured strict **false rejection / unsupported signed-subject naming convention**, not a cryptographic false positive. Native failure is reported `UNVERIFIED`, not unsafe.
4. If H5 or H6 exposes a previously unseen signed subject path, record the exact path in the original certificate and report it; do not rewrite H5/H6 into a new "blind" test after adjusting the rule.
5. No signed software artifact certifies authorization to change unrelated GitHub files or database rows. Every outcome should retain owner consent and remote execution effect as `UNVERIFIED`.

**H6 is an SBOM attestation, not a standalone execution artifact.** It tests whether the artifact's actual signed subject identity can survive copying from its build directory to a GitHub release asset while preserving content digest. This is a reasonable cross-artifact provenance claim test; it does not prove the SBOM's claims are factually complete.

Publisher workflows and official release metadata were inspected before freezing this test; these are independent software publishers from H1-H4, but not randomly sampled. Source from github.com release metadata and original workflow at release ref. No external collaborators.

The held-out evaluation may legitimately fail on both cases. Preserve original observations rather than silently broadening policy or substituting new projects.
