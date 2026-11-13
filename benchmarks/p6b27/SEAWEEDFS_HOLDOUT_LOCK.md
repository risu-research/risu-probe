# P6-B27 external S3 holdout lock | SeaweedFS 4.53

Frozen before any B27 SeaweedFS run. Do not modify the expected case set to turn a failure into a positive result.

## Publisher and original artifact
- Publisher: seaweedfs/seaweedfs (independent of RISU Research and PostgreSQL).
- Official upstream release: https://github.com/seaweedfs/seaweedfs/releases/tag/4.53
- Original release timestamp: 2026-11-08 18:10:39 UTC.
- Download asset: https://github.com/seaweedfs/seaweedfs/releases/download/4.53/linux_amd64.tar.gz
- Official GitHub release asset digest: sha256:d1a7dec9f48d8b33895a0ea8951971defc2dc5312906dcc76fa5a5f74a6ee90d
- Original server must be run directly, with no RISU patch or proxy. Installation integrity must be checked before starting.
- Original APIs: S3 PutObject/GetObject, embedded IAM CreateUser/CreateAccessKey/PutUserPolicy/UpdateAccessKey.

## Development / heldout boundary
PostgreSQL native RLS is the B27 policy construction reference. SeaweedFS S3 is a separate external backend with its original semantics. No rule, server patch, or fallback policy should be invented after inspecting its test outcomes.

## Prespecified roles
- Synthetic resource admin/owner inside CI starts original SeaweedFS and creates its own local bucket.
- Native IAM "exact" account receives a policy Allow s3:PutObject on one exact original S3 object ARN only.
- Native IAM "coarse" account receives a separate bucket-wide PutObject policy, a positive control that checks IAM setup works.
- Both roles receive native SeaweedFS access keys created by IAM, not credentials constructed by RISU.
- All actual effect requests go directly to the original S3 endpoint, bypassing any RISU gateway.

## Locked observations (classify rather than assert)
1. Admin pre-seeds exact object, a same-prefix neighboring object, a foreign object, and a coarse-control object. Record byte hashes.
2. A coarse-control account must PUT in its bucket scope; otherwise infrastructure setup is invalid, not a valid authorization result.
3. Exact-object identity PUT of the specified object, with approved bytes. Outcome is recorded as ALLOW or DENY without fallback.
4. Exact-object identity PUT of same-prefix neighbor and foreign path, and object listing. Both operations should be denied; any actual out-of-scope object mutation is recorded as a SCOPE_BYPASS.
5. If #3 succeeded, try changed content on the same object using the same exact-object credential. An accepted changed-content PUT demonstrates that an object ARN alone cannot bind bytes. A second accepted PUT demonstrates lack of one-time consumption under these native S3 credentials; it is not necessarily an upstream bug.
6. Disable the exact-object IAM access key and retry; record the native S3 verdict.
7. Independent auditor reads all original objects with the admin credential while original server is running and verifies all claimed responses against actual bytes.

## Known external context, do not count as original discovery
SeaweedFS issue https://github.com/seaweedfs/seaweedfs/issues/10191 reports that embedded IAM inline prefix-scoped resource policies previously denied even in-scope PutObject. Positive target denial must be explicitly reported as that class of authorization/compatibility mismatch, not reported as access-control strength.

## Evaluation labels
- EXTERNAL_NATIVE_OBJECT_SCOPE_SUPPORTED: exact target allowed, neighboring objects denied.
- EXTERNAL_NATIVE_POLICY_REJECTS_VALID_TARGET: control works, exact resource policy target denied.
- EXTERNAL_SCOPE_BYPASS_OBSERVED: out-of-scope effect recorded by independent admin read.
- ENVIRONMENT_UNQUALIFIED: upstream release failed integrity, admin policy setup broken, or live server not available.
- CONTENT_BOUND_TO_CONSENT: requires native enforcement of the exact approved bytes, not merely key path. A granted S3 PutObject alone is insufficient to claim this.
- REMOTE_KEY_REVOKED: native owner/key-issuer revoked and a formerly usable key no longer works.

No real third-party human approved access and no production account or customer resources are involved.
