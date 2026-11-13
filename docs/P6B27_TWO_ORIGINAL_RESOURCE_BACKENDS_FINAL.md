# RISU Probe P6-B27 | Two independently published original resource services

**Final observed outcome: native, claim-specific resource authorization differs by backend.**

Research branch: `qualification/p6b27-external-resource-enforcement-20261112`. All modifications are on qualification branches; no RISU Probe `main` changes. Captured at 2026-11-13 UTC.

## Why B27 matters

P6-B25 demonstrated a real GitHub deployment approval, bounded trusted writer and independent one-file Git effect. B26 demonstrated native resource-side issuer enforcement inside a RISU-authored isolated HTTP+SQLite service. B27 asks a different question: **When the gateway and RISU code are bypassed, does an independently published resource service enforce the owner's exact object, intended content, state transition, one-time effect, and revocation?**

We preregistered a native PostgreSQL policy case and an independent SeaweedFS S3 IAM policy holdout. Both upstream implementations ran without RISU patches. Native credential and policy provisioning was done by separate synthetic issuer principals in isolated CI; neither experiment establishes approval from an unrelated real human or any third-party customer.

## Frozen upstream identities and original runs

| | PostgreSQL | SeaweedFS |
|---|---|---|
| Independent upstream publisher | PostgreSQL Global Development Group | seaweedfs/seaweedfs |
| Upstream original version | 18.6 (Ubuntu 18.6-1.pgdg26.04+2) | 4.53, upstream source commit 4ab66fb76da83700739f5839e62fcaf15fb7d02a |
| Artifact provenance | Ubuntu-installed original postgres binary; SHA-256 in package identity artifact | Original GitHub release linux_amd64.tar.gz; published sha256 d1a7dec9f48d8b33895a0ea8951971defc2dc5312906dcc76fa5a5f74a6ee90d |
| Protocol / native issuer | PostgreSQL direct SQL + owner-issued LOGIN/GRANT/REVOKE/RLS | Direct S3 SigV4 PUT / GET + original embedded IAM CreateUser, PutUserPolicy, CreateAccessKey, UpdateAccessKey |
| Native effect CI run | https://github.com/risu-research/risu-probe/actions/runs/43363316209 | https://github.com/risu-research/risu-probe/actions/runs/43365564417 |
| Original evidence artifact | https://github.com/risu-research/risu-probe/actions/runs/43363316209/artifacts/14009520787 | https://github.com/risu-research/risu-probe/actions/runs/43365564417/artifacts/14010580338 |

Native backends are different and have different native authorization primitives. PostgreSQL's policy explicitly constrains both old and new row states; SeaweedFS's IAM policy explicitly grants `s3:PutObject` on a single object ARN. The comparison assesses whether each *configured original authorization* preserves a stricter claim-specific owner instruction; it does not say the products had identical advertised policy features.

## Original effects, independently audited

**PostgreSQL**: native FORCE ROW LEVEL SECURITY on three protected rows, with `USING` restricting the original object's old state and `WITH CHECK` requiring the exact new content and direction. Direct actor SQL bypasses every RISU gateway. All 15 prelisted unauthorized queries were denied or affected 0 rows, including neighboring object, other object, wrong text, wrong state, unauthorized owner metadata, role elevation and RLS disable. Two simultaneous permitted native UPDATEs affected [0, 1] rows, one approved change. Replay, replay after actual original server restart, and writes after owner's native GRANT revocation did not change the resource. Separate native catalog/actual row auditor PASS. Original author and caller are distinct SQL principals and agent SQL ran as Linux UID 65534. This is a bounded old-state/transition rule, not generic cryptographic single-use authorization.

**SeaweedFS**: official SHA-pinned 4.53 original release, mini launched with its official `-s3.iam.readOnly=false` setting so issuer may use the native IAM write API. The owner created one exact-object native access key and one bucket-wide positive-control key. Exact-object PUT returned HTTP 200, same-prefix neighbor and different-object PUT returned HTTP 403, forbidden listing returned HTTP 403; owner made access key Inactive and the next PUT returned HTTP 403. But the native exact-object key also performed a different-content PUT and a repeated PUT, both HTTP 200. An independent read-only auditor fetched original S3 objects and original IAM metadata, verified the exact ARN and revoked key, and refused a tampered fake case. Eight direct native S3 requests ran in a separate Linux UID 65534 process with only its IAM credentials; the processes could not read the trusted root-owned issuer and publisher-server `/proc/.../environ` files. The owner/CI fixture administrator and binary remain trusted.

**Native policy equivalence:** The original SeaweedFS IAM API returns singleton `Action` and `Resource` fields as strings, even though the owner submitted one-element arrays. The independent auditor accepts only those two IAM-standard equivalent singleton representations; it rejects added actions, resources or fields and checks the live policy and remote bytes. No upstream policy was broadened to obtain success.

## Strict cross-publisher claim matrix

The independent aggregate imports the exact previously recorded original CI artifacts (not a newly generated simulation) and refuses missing or tampered native evidence.

| Authority/effect question | PostgreSQL original service | SeaweedFS original service |
|---|---|---|
| Does server enforce target object / row scope? | YES | YES |
| Does server enforce approved **new bytes** with this issuer rule? | YES | NO, alternate content PUT accepted |
| Does server enforce approved **old-state -> new-state direction**? | YES | NO, object PUT policy has no such constraint |
| Does server prevent repeat effect with this issuer rule? | YES, old-state RLS makes repeated UPDATE affect 0 rows | NO, repeated PUT accepted |
| Does native owner/key issuer revoke later writes? | YES | YES |
| Was the external effect audited using original stored data? | YES | YES |
| Was an unrelated third-party person authenticated and asked for consent? | NO | NO |

Independent cross-backend matrix: https://github.com/risu-research/risu-probe/actions/runs/43365668801

Original aggregate artifact: https://github.com/risu-research/risu-probe/actions/runs/43365668801/artifacts/14009802925

The independent two-backend aggregate also rejects a deliberately altered SeaweedFS response. It required that the SeaweedFS actor's observed UID be 65534 and that it could not read the publisher or issuer environment.

## Main scientific result and uncertainty

The bounded observation supports a **compositional claim-specific authority check**: authorization evidence needs separately demonstrated constraints for *which object*, *which new value*, *which old-to-new transition*, *how many effects*, and *whether issuer revocation has taken effect*, followed by independent verification of the actual remote change.

Native IAM and RLS are established mechanisms. B27 does **not** discover a new upstream flaw or replace their implementations. A native exact-object S3 PutObject policy permits writing arbitrary bytes to that object and reuse by design; such a privilege cannot by itself certify a stricter owner's one-time approval for particular bytes. PostgreSQL's original row policy in this test could enforce the latter specific row transition, but production decisions need policy review and trustworthy issuer identities.

## Exact trust limits

1. All users and owners in B27 are CI-controlled fixture principals. A second, independently controlled human owner, off-platform credential issuer, or true cross-organization domain has **not** been tested.
2. The original PostgreSQL and SeaweedFS backends are independent publisher software, but both experiments were orchestrated by RISU within GitHub's infrastructure, not deployed by independent operators.
3. The original native issuer, service executable, kernel and fixture admin are trusted. A malicious privileged service/admin could override policy; no server-supply-chain compromise is assessed.
4. The SeaweedFS OS isolation proof is a real, unprivileged child process attempt to open `/proc` environment files plus source and CI evidence. The post-run auditor checks the recorded proof and actual native IAM/object state; it is not a forensic independent kernel trace.
5. PostgreSQL's content/one-time enforcement arises from our **configured** RLS `USING/WITH CHECK` constraints, while S3's exact-object policy grants only `PutObject`. These are not feature-comparable default configurations. This difference is precisely what the capability matrix is intended to make explicit.
6. Only two original upstream backends are tested. No universal effectiveness rate or novel external security vulnerability is established.

## Frozen code and evidence

- Native PostgreSQL test: [run_external_postgres.py](../benchmarks/p6b27/run_external_postgres.py)
- Independent PostgreSQL audit: [independent_postgres_audit.py](../benchmarks/p6b27/independent_postgres_audit.py)
- Original SeaweedFS S3: [run_original_seaweedfs.py](../benchmarks/p6b27/run_original_seaweedfs.py)
- Separate untrusted UID client: [seaweedfs_untrusted_client.py](../benchmarks/p6b27/seaweedfs_untrusted_client.py)
- Independent original IAM and bytes audit: [independent_seaweedfs_audit.py](../benchmarks/p6b27/independent_seaweedfs_audit.py)
- Pinned artifact comparison: [compare_external_backends.py](../benchmarks/p6b27/compare_external_backends.py)
- Preregistered challenge sets: [PRE_REGISTERED_PROTOCOL.md](../benchmarks/p6b27/PRE_REGISTERED_PROTOCOL.md), [SEAWEEDFS_HOLDOUT_LOCK.md](../benchmarks/p6b27/SEAWEEDFS_HOLDOUT_LOCK.md)

## Research next step, not prematurely claimed

Move toward a genuinely **independently controlled issuer** and **externally operated resource**. Before issuing credentials, freeze an agreed intent containing object identity, exact desired content, expected original state, one-use limit and expiry, and decide whether issuer-issued capability or native server policy enforces each field. Measure direct-to-backend bypass and the actual effects from the resource owner independently. Create a third, previously unseen publisher holdout, and include positive controls and concrete negative controls. If a native API cannot enforce a field, mark **UNSUPPORTED** rather than retroactively adding a trusted proxy and calling the backend secure.
