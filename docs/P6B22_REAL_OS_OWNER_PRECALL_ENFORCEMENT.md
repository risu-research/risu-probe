# P6-B22 | Independent OS resource-owner consent enforced before original MCP execution

**Date:** 2026-11-12 (US Eastern); source CI runs continued across UTC midnight.  
**Branch:** `qualification/p6b22-os-owner-precall-enforcement-20261112`  
**Research stage:** opt-in, bounded, source-pinned pre-call gateway; actual independent POSIX principals; CI-local synthetic owner, **not an independently consenting human participant**.

## 1. Question and contribution

B21 could diagnose a mismatch between physical effects and a resource owner's signed scope *after* an MCP server had already executed. B22 asks a different, testable question:

> Can a separate resource-owner account issue a binding signature for one exact action, while an unprivileged executor with no access to the owner's private key **allows or prevents the original unmodified MCP process from starting**, according to independent owner approval, POSIX access control, a revocation list and durable local replay prevention?

The B22 opt-in `enforce-mcp-preflight` gate answers **yes for the preregistered bounded local `write_file` profile**. A source-native success or refusal is determined by actual Linux syscalls and real target-file state, not the gateway's self-reported success bit.

This is an engineering conformance result. The original tested external `filesystem-mcp` server was used as a normal behavior control in B20 and B21. **No new external upstream bug was found or claimed.**

## 2. Three identities that should never be conflated

1. **Vendor/software origin:** The original unmodified `kujirahand/mcp_server-filesystem` source at commit `1aff1e094ed317ec2c5de06591978781d660c48a`. Published `filesystem-mcp==1.0.2` PyPI wheel SHA-256 `94610f0b73df1d3ada4ef0353353eb93695645c7b82f71ca80ed13dc1022c235`, `filesystem_mcp/server.py` SHA-256 `c754a7720d52d92eb49324649b19f58b07b20703fcc2c2c1b02ce1f20152fcc8`. Wheel's module was byte-equal to its separately pinned upstream Git source. **No vendor-signed PyPI release attestation is claimed** for this version.
2. **Independent OS resource principal:** Actual unprivileged Ubuntu `www-data` UID **33** owns a newly created private resource directory and an Ed25519 private key in its own `0700` home, with key mode `0600`. The other account cannot read or stat the private key. The owner itself signs the exact grants, revocations, and **before/after physical file observations** in separate OS processes.
3. **Actual tool executor:** Different unprivileged Ubuntu `nobody` UID **65534** owns a `0700` atomic nonce ledger and performs source-original MCP calls only after the preflight gate. Its access to the synthetic target is separately limited by POSIX directory/file ACL.

**Threat-boundary warning:** These are real separate Linux UIDs, but they are **not two independently consenting people**. The privileged GitHub-hosted CI operator can `sudo` to both users and generated the fixture and trust-root workflow. An unrelated third-party person's approval, independently registered identity-provider trust root, real customer consent, and OAuth access tokens were **not obtained**. B22 reports `OS_UID_ISOLATED_FIXTURE_ONLY`.

MCP's OAuth authorization specification primarily governs HTTP transports; stdio uses environment-provided credentials and process isolation. MCP tool annotations are not sufficient user-grant authority. Official standard: https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization .

## 3. Bounded signed original-call gate

Installed opt-in CLI:

```sh
pip install '.[effect-authority]'
risu-probe enforce-mcp-preflight \
  --request ORIGINAL_TOOLS_CALL.json \
  --grant PREISSUED_OWNER_ED25519_GRANT.json \
  --trust-root OWNER_PUBLIC_ROOT.json \
  --trusted-root-sha256 PINNED_FROM_TRUSTED_CHANNEL \
  --revocations LATEST_OWNER_SIGNED_REVOCATIONS.json \
  --revocations-sha256 PINNED_LATEST_REVOCATION_DIGEST \
  --original-wheel PINNED_VENDOR_WHEEL.whl \
  --ledger EXECUTOR_PRIVATE_NONCE_LEDGER \
  --server-python PINNED_ORIGINAL_VENV_PYTHON \
  --out RESULT.json
```

Scope is deliberately narrow: the original `write_file` tool, a direct-child regular file under an explicitly owner-controlled directory, text payload up to 4096 bytes, `append=false`, original server module `filesystem_mcp`, no arbitrary paths or tool execution. The complete tool call is bound to its exact canonical JSON SHA-256.

The owner-signed pre-call grant uses a domain-separated Ed25519 signature over:

- Exact resource owner/executor UIDs, owner identity and resource ID.
- Exact target directory and target file path.
- Entire native MCP request hash, exact tool and approved server module.
- Original package wheel SHA-256, desired content SHA-256.
- Precondition content digest, intended `CREATE`, `REPLACE` or `NO_CHANGE`.
- Unique 256-bit nonce and five-minute experiment grant window.

The gate requires a caller-pinned public-root SHA-256, cryptographically valid owner grant, independently signed and currently pinned revocation epoch, exact OS identity and filesystem owner, **live directory and file-level POSIX DAC**, matching target precondition and requested direction. Only then does it consume the nonce atomically with `O_CREAT|O_EXCL` in the executor-private ledger.

**Execution branches:**

- **Denied**: exit code 3, no source MCP server spawn, no native tool call, target unchanged; an evidence JSON report still records the refusal class.
- **Authorized**: original source process starts as UID 65534, runs MCP `initialize`, `tools/list`, native `tools/call`, checks the final file digest; evidence retains original raw MCP wire, original server PID, real external state. Error during original tool or postcondition returns exit code 4.

The product does not inject policy into the unmodified upstream server or run with owner privileges. It performs precise *pre-call screening* rather than remote OAuth authorization or race-free OS syscall mediation. Pre-call checks plus original server execution still have TOCTOU and hidden-side-effect limits.

## 4. Original external experiment, exact denominators

Original `write_file` against local synthetic content; no private files or network requests are supplied.

| Preregistered scenario | Separate owner signed policy and OS situation | Actual observed outcome |
| --- | --- | --- |
| `allowed_create` | CREATE signed; target directory ACL permits executor | Original MCP executed, new 42-byte file |
| `allowed_noop` | NO_CHANGE signed for existing identical bytes | Original MCP executed; unchanged file |
| `allowed_replace` | REPLACE signed, owner also grants executor file write ACL | Original MCP executed; 64-byte file becomes 42 bytes |
| `denied_replay` | Same valid NO_CHANGE grant reused after first consumption | Denied, no MCP spawn |
| `denied_no_grant` | No grant was issued | Denied, no MCP spawn |
| `denied_signed_scope` | Signed NO_CHANGE but request actually needs CREATE | Denied, no MCP spawn |
| `denied_revoked` | Valid prior grant, subsequently revoked by owner's separately signed new epoch | Denied, no MCP spawn |
| `denied_os_dac` | Valid signature but owner removes executor POSIX ACL | Denied, no MCP spawn |
| `denied_stale_state` | Owner changes file after grant; separate file ACL still permits executor | Denied due stale state, no MCP spawn |
| `denied_tampered_request` | Request payload changed after owner signed it | Denied, no MCP spawn |

**Actual firstpass:** 3/3 approved native MCP calls started original source and succeeded; 7/7 refused cases caused no original server `execve` and left their target bytes unchanged. A separate `strace -f -e execve` process under executor UID records precisely whether the original `-I -m filesystem_mcp` command was ever started.

The owner UID 33 *itself* separately signed the exact physical before/after file snapshot for **every** case: 20 signed source observations per run, with literal synthetic file bytes, SHA-256, byte count, target path, owner UID, and case/stage label. The executor and ordinary CI user could not read the private owner directory.

First real run: https://github.com/risu-research/risu-probe/actions/runs/43332919600

## 5. Independent real run and adversarial audit

A **fresh different GitHub-hosted Ubuntu VM** independently rebuilt the exact original upstream virtualenv, created new temporary resources and a **new Ed25519 owner private/public key**, and repeated all ten decisions.

Independent auditor `benchmarks/p6b22/independent_os_owner_preflight_audit.py` imports **neither the original pre-call product nor B20/B21**. It separately verifies:

- Both original vendor release/source digests, actual native MCP request/result wire and in-band catalog.
- The 3 real original `execve` calls and the absence of server process creation in 7 denials from `strace`.
- Every signed exact owner grant; both originally signed revocation epochs.
- **20 genuine Ed25519 owner-signed original physical observations** and literal archived target bytes each run.
- Exact source file owner/executor UID claims, private-key 0600 mode reported by the owner itself, and OS POSIX DAC withdrawal evidence.
- All replay, no-grant, restricted operation, revocation, stale-state and request-mutation negative cases.

Three independent *postfreeze evidence-corruption controls* were deliberately rejected: altered owner-signed file observation, altered actual file bytes, and synthetic forged original `execve` appended to a denied case.

**Both independent VMs yielded exactly 3 native source-allowed calls and 7 pre-spawn denials with matching refusal reasons.** Their owner public-key SHA-256 values differed, proving they used fresh signing identities.

Independent audit and second native run:
https://github.com/risu-research/risu-probe/actions/runs/43333559961

Across both source-native runs: **6 actual original MCP calls, 14 pre-spawn denials, 40 independently owner-signed physical before/after observations, two different ephemeral signing keys.**

## 6. Product regression and development-set integrity

The complete installed RISU preview package, including all B15–B21 functions and additional B22 adversarial tests, passed **471 tests each on Ubuntu, Windows and macOS**.

https://github.com/risu-research/risu-probe/actions/runs/43332643910

**Methodological history is recorded openly** in:

- `benchmarks/p6b22/FROZEN_PRECALL_OS_OWNER_EVALUATION.json` (original plan, initial kernel source blob).
- `benchmarks/p6b22/FROZEN_PRECALL_OS_OWNER_EVALUATION_V2.json` (explicit amended kernel).

A source-informed development run uncovered a legitimate **real OS file-DAC barrier**: a signed REPLACE grant alone did not allow the executor to overwrite an owner-owned mode `0644` file. The original server returned an error. We strengthened the gateway to test target-file OS write access *before* spawning the original server, and had the owner separately grant the OS file ACL for the approved replacement. This was a real architectural improvement, not a new upstream vulnerability. All earlier development CI runs and failures remain publicly visible. The original software, previous products and evidence truth-table denominators were preserved; amended kernel Git blob is `651af884c3303bbe6729a751a89b57d939e9eb6d`.

The independent auditor initially equated exact mode `0700` with OS DAC denial and rejected an actual `02700` mode containing a harmless setgid directory bit. Audit corrected this by evaluating owner/group/other POSIX permission bits, preserving exact owner access and no group/other rights. The original native execution evidence was untouched.

## 7. Scientific and security limits / next real step

B22 establishes the **pre-execution enforcement boundary** for an explicitly bounded source-original tool under separate actual Linux UIDs, with actual protected owner signing keys, source-traceable positive calls, independent owner-signed physical measurements, revocation, replay control and OS ACL checks.

**Not established:**

- Authentication or consent of an independently participating external **human owner**; our CI privileged operator can impersonate both system UIDs.
- Trust-root registration, identity-provider binding, delegation or revocation from a real organization.
- Production OAuth 2.1 HTTP MCP access token validation or consent; these experiments used local stdio.
- Mandatory interposition over all possible MCP tools/side effects or race-free OS file-object handles.
- Durable globally coordinated nonce and monotonic revocation ledger outside the one executor profile.
- Comprehensive protection from hidden effects of an original server executing after a grant.
- A novel upstream defect, blind detection performance or population-wide false-positive rate.

**Next meaningful test:** An actual separate human/organization owner **independently generates its key and explicitly approves one named sandbox resource and request** on its own machine. RISU ingests only the public root and signed one-time grant over a truly authenticated resource identity, then demonstrates external unauthorized request refusal before execution with OS-level enforcement and trusted audit. Where OAuth is used, validate the issuer, audience, scopes and consent via an actual independently operated authorization server, rather than substituting a client claim or self-signed CI fixture key.

The public branch intentionally remains separate from `main`.
