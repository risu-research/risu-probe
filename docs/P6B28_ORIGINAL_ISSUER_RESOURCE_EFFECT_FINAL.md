# RISU Probe P6-B28 | Original issuer, native resource effects and one-use delivery

**Status: verified original OpenBao-to-PostgreSQL execution, independent native audit, portable installed RISU evidence checker.** Research branch only; `main` untouched. UTC 2026-11-13.

## Evidence and exact pinned releases

- Original live issuer-to-resource run: https://github.com/risu-research/risu-probe/actions/runs/43377450878
- Immutable original nonsecret evidence: https://github.com/risu-research/risu-probe/actions/runs/43377450878/artifacts/14015406555
- Three-OS installed RISU verifier and adversarial controls: https://github.com/risu-research/risu-probe/actions/runs/43378448871
- Per-OS original-record certificates (GitHub original artifacts):
  - Windows: https://github.com/risu-research/risu-probe/actions/runs/43378448871/artifacts/14016260065
  - Ubuntu: https://github.com/risu-research/risu-probe/actions/runs/43378448871/artifacts/14015925186
  - macOS: https://github.com/risu-research/risu-probe/actions/runs/43378448871/artifacts/14015790898
- Original external issuer: OpenBao **2.7.2**, version commit `9e0a0d3c3504a0a00b45e61355afac5e35c78379`, published official archive `openbao_2.7.2_linux_amd64.tar.gz`.
- Original OpenBao release archive SHA-256 (verified against the official checksums.txt with pinned digest): `582b1f3c2fdc5afd443b2d57a225ef654de75adea609fdb66731fd582a9cbc96`.
- Official checksum manifest SHA-256: `d839d376448eceef3ccb5cdd44c4a0749a92a6e4aa2fdaf47255cfa949dfb77e`.
- Original resource server: PostgreSQL **18.6** (`Ubuntu 18.6-1.pgdg26.04+2`), unmodified native SQL and row-level security.
- Official behaviors: https://openbao.org/docs/secrets/databases/postgresql/ ; https://openbao.org/docs/api/system/wrapping-unwrap/ ; https://www.postgresql.org/docs/current/ddl-rowsecurity.html .

## Real permission and effect chain

The fixture root operator boots original OpenBao and PostgreSQL, configures distinct PostgreSQL resource owner (`b28_owner`) and native OpenBao database-issuer login (`b28_bao_issuer`), and defines one NOLOGIN template role (`b28_template_writer`). The issuer login is neither PostgreSQL superuser nor BYPASSRLS role. The resource owner enables forced RLS with an UPDATE `USING` condition on exact old state and `WITH CHECK` on the exact desired new state.

The original OpenBao PostgreSQL plugin creates a **new dynamic PostgreSQL user** and a distinct leased password using a native `database/creds/b28-write` request. The trusted fixture operator asks original OpenBao to **wrap that returned credential** with a five-minute response wrapping token. The agent receives only the opaque one-use wrapping token, never the issuer operator token or resource owner's password.

A separate Linux UID **65534** child directly calls OpenBao `POST /v1/sys/wrapping/unwrap` exactly once; the response includes the actual native PostgreSQL username, password and lease ID. A second unwrap is HTTP **400**; the consumed wrapper cannot call `database/creds/b28-write` (HTTP **403**). The original owner and issuer process environments are not readable to the child. Anonymous credential issuance and administrative issuer API requests were also refused.

With its newly minted original PostgreSQL database credential, the agent bypasses all RISU gateway code and tests **14** actual native SQL negative controls, all rejected or affecting **zero rows**. These cover different object and same-prefix neighbor, changed approved bytes, wrong direction, immutable owner metadata, SELECT leakage, role elevation, RLS bypass, and other unauthorized data modification operations.

The owner independently reads the three original rows and sees **no change** after the denied controls. After a separate explicit owner-side continuation, the agent's permitted native SQL UPDATE changes exactly **one** row from `WAITING / ORIGINAL APPROVED` to `APPROVED / APPROVED CONTENT`; both other rows remain unchanged. A second UPDATE with the **same still-valid database credential** affects **zero** rows because PostgreSQL's old-state RLS condition no longer matches.

While the agent still retains its original PostgreSQL password in memory, OpenBao's trusted original operator revokes that exact native dynamic credential lease through `bao lease revoke`. The original ephemeral PostgreSQL role disappears and the actor's **new independent native PostgreSQL connection is rejected**. This confirms a live credential lifetime and revocation boundary across two original upstream software products.

## Independent third-source audit and adversarial tests

A **separately authored auditor** imports neither the test harness nor actor source and directly queries:
- original PostgreSQL system catalog, FORCE RLS and policy old/new expressions;
- actual full original PostgreSQL stored resource rows and native template grants;
- native PostgreSQL resource owner, issuer login privileges, and absence of the revoked dynamic role;
- original OpenBao HTTP database mount, native role configuration and service health.

The audit reports PASS and rejects an explicitly tampered positive effect report. None of the original GitHub evidence artifacts contain the OpenBao root token, actor's wrapped token, PostgreSQL passwords, or native original server private logs.

A new installed product command validates the **recorded original artifacts** with strict schema, raw SHA-256, JSON duplicate-key rejection, source identity, before/after hashes, native policy catalog checks, issuer one-use wrapper evidence, role revocation and the independent auditor's output. It *refuses* unsupported external-human and third-party-service ownership claims. It is explicitly an **offline recorded-evidence consistency checker**, not a fresh network check.

```sh
risu-probe verify-mcp-external-authority --evidence-dir ./original-evidence --out certificate.json
```

The test suite includes direct evidence-tampering counterexamples for forged third-party owners, mismatched issuer checksum, modified rows, altered policy scope, new-access after revocation, incorrect actor Linux UID, duplicate or missing attack cases, wrapper reuse, and unauthorized extra database credentials. **Ubuntu/Windows/macOS: 569/569 product source tests per platform, including 11 specific artifact tests per platform, all passing.** Installed wheel, CLI and independent certificate artifacts are preserved in the original GitHub run.

## An important failed design, retained as an actual result

The first B28 runs (`43376379234`, `43376530043`, `43376662217`, `43376863672`) attempted dynamic database issuance using an OpenBao client token with `num_uses=1`. Original OpenBao returned **HTTP 400**; redacted native diagnostics implicated the child lease being invalidated when a limited-use token is consumed. This is not treated as an upstream vulnerability.

The repair was recorded in [AMENDMENT_WRAPPED_LEASE_NOT_ONE_USE_ISSUER_TOKEN.md](../benchmarks/p6b28/AMENDMENT_WRAPPED_LEASE_NOT_ONE_USE_ISSUER_TOKEN.md), preserving the original prior preregistration. **One-time delivery** now comes from OpenBao's native response wrapping; **database credential lifetime** comes from the native issuer lease; **one-time resource effect** comes from the native PostgreSQL old-state RLS transition. They are three different properties and should never be collapsed into one.

## Supported claim-specific results

| Distinct verified obligation | Actual result |
|---|---|
| Two independently developed original software implementations | VERIFIED (original OpenBao and PostgreSQL) |
| Real native dynamic credential generation | VERIFIED |
| One-time delivery of the original wrapped credential | VERIFIED |
| Original agent kernel UID distinct from operator/issuer | VERIFIED within disposable CI |
| Issuer operator password or root token given to agent | NO |
| Unauthorized native PostgreSQL direct requests | 14 controls refused / zero changed resources |
| Exact approved content and old-state transition | VERIFIED for three-row fixture |
| Replay of identical SQL effect | ZERO additional rows |
| Owner's real OpenBao lease revoke affects fresh database login | VERIFIED |
| Separate native resource/issuer audit and modified-record rejection | VERIFIED |
| True independent human resource owner approval | **NOT TESTED** |
| Original services independently operated by outside organizations | **NOT TESTED** |
| Wrapping token cryptographically bound to recipient identity | **NOT SUPPORTED** |
| Malicious issuer/root operator or PostgreSQL superuser resistance | **OUTSIDE THREAT MODEL** |

## Limits, security interpretation and future progression

The third software publisher makes this a stronger independent *implementation* validation than B26. The issuer and resource are still set up and operated by RISU's GitHub CI root administrator. **The operator is not an independent external resource owner**. The original OpenBao dev server runs only in a disposable localhost CI fixture with in-memory storage and **without TLS**, so it is not an example production deployment.

An OpenBao wrapping token is a bearer secret: whoever obtains it *first* can unwrap the original credential. It is not by itself cryptographically bound to the intended agent identity or to a separately authenticated human. PostgreSQL's exact SQL transition rule protects resources after receipt; the wrapper restricts one-time **delivery**, not all subsequent use of the database credential. This division is central to interpreting the result.

The novel, potentially generalizable RISU contribution is **claim-specific composition of distinct issuer, recipient, execution and observed-effect proof obligations**, including explicit refusal to certify missing human-owner or identity-binding evidence. The upstream cryptographic tokens, RLS and database leasing mechanisms are existing technologies; no previously unknown upstream CVE or universal security result is claimed.

Next meaningful test: an **actually independently controlled human/resource operator** separately authorizes a specific action, keeps issuance credentials outside RISU, and can revoke/deny a direct-to-backend bypass. A new external service/issuer pair, not used to tune these rules, should then test the locked B28 certificate logic. The user must explicitly arrange participation of an independent account/operator; do not invent approval or create a synthetic second account and present it as independent.

## Reproduction and preservation

- Original study: [PRE_REGISTERED_EXTERNAL_ISSUER_PROTOCOL.md](../benchmarks/p6b28/PRE_REGISTERED_EXTERNAL_ISSUER_PROTOCOL.md)
- Transparent post-negative amendment: [AMENDMENT_WRAPPED_LEASE_NOT_ONE_USE_ISSUER_TOKEN.md](../benchmarks/p6b28/AMENDMENT_WRAPPED_LEASE_NOT_ONE_USE_ISSUER_TOKEN.md)
- Trusted fixture launcher: [run_original_openbao_postgres.py](../benchmarks/p6b28/run_original_openbao_postgres.py)
- Linux UID 65534 original API and SQL actor: [untrusted_openbao_pg_actor.py](../benchmarks/p6b28/untrusted_openbao_pg_actor.py)
- Native independent live auditor: [independent_b28_openbao_pg_audit.py](../benchmarks/p6b28/independent_b28_openbao_pg_audit.py)
- Reusable portable recorded-evidence checker: [risu_mcp_external_authority_certificate.py](../src/risu_mcp_external_authority_certificate.py)
- Adversarial portable tests: [test_p6b28_external_authority_certificate.py](../tests/test_p6b28_external_authority_certificate.py)
- Live native CI and installed cross-OS certificate CI are directly linked in the first section.

**Exact B28 research branch:** `qualification/p6b28-external-issuer-live-revocation-20261113`; preserve `main` unchanged.
