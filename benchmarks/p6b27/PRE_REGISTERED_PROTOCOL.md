# RISU Probe P6-B27 | Preregistered external backend enforcement trial

## Frozen target and why it is independent

Target: original, distribution-installed PostgreSQL server from the PostgreSQL Global Development Group. The server is unmodified; RISU implements no PostgreSQL access control. Native PostgreSQL LOGIN credentials, GRANT/REVOKE and row-level security (RLS) are issued/configured by an independently authenticated fixture database owner. Agent requests directly use the original psql client and PostgreSQL protocol with the actor's own database credential.

Primary source specifications (read before recording outcomes):
- https://www.postgresql.org/docs/current/ddl-rowsecurity.html
- https://www.postgresql.org/docs/current/sql-createpolicy.html
- https://www.postgresql.org/docs/current/sql-createrole.html

This is not a claim that an unrelated real human has directly approved access. Owner, agent and adversary are distinct synthetic PostgreSQL and Linux principals created inside a controlled GitHub CI environment.

## Locked hypothesis

With resource-native per-object and per-result policies, an actor holding its own native database credentials cannot modify another object, select another protected object, change the approved output, write immutable owner metadata, elevate database role privileges, disable RLS or replay a one-directional change. The owner can revoke credentials without changing an agent-side gateway. The original PostgreSQL server remains authoritative even when all RISU gateway code is bypassed.

## Original fixture (not modified during case selection)

- Protected table with 3 resources: object/approved, object/same-prefix-extra and outside/foreign.
- Actor's original privileges: SELECT object_key/state/body/owner_epoch, UPDATE only state/body. Other role lacks UPDATE.
- Owner attaches a native SELECT policy scoped to exactly object/approved and a native UPDATE policy:
  - USING (object_key='object/approved' AND state='WAITING' AND body='ORIGINAL APPROVED');
  - WITH CHECK (object_key='object/approved' AND state='APPROVED' AND body='OWNER APPROVED VALUE' AND owner_epoch='e1').
- FORCE ROW LEVEL SECURITY on original protected table.
- Single approved effect: object/approved WAITING / ORIGINAL APPROVED -> APPROVED / OWNER APPROVED VALUE.
- Other rows must remain byte-identical.
- Negative direct native SQL requests: wrong object, same-prefix neighbor, wrong output bytes, wrong direction, changed owner_epoch, DELETE, INSERT, TRUNCATE, ALTER TABLE DISABLE RLS, DROP POLICY, SET ROLE owner, SET ROLE postgres, row_security=off, other principal, cross-object SELECT.
- Two simultaneous native UPDATE requests using the actor's valid credential must yield native affected-row counts [0,1].
- Plain replay, replay after original PostgreSQL restart and owner-native REVOKE must not modify any resource.

## Evidence and independent audit

The original executor collects observed exit status, native UPDATE counts, before/after PostgreSQL snapshots and server version. The independently written auditor imports no RISU gateway or runtime harness module. It uses a privileged *read-only query path* to PostgreSQL system catalogs, live protected rows and per-role table privileges; it verifies the case set and exact final state, as well as policy metadata, issuer capabilities and native revocation. Tampering a refused case in a copied report must cause the auditor to fail. This audit is independent in code and query path, not independent third-party hosting.

### Threat boundary

- Trusted: CI fixture administrator, PostgreSQL server binary and OS, native owner issuer, audit reader.
- Untrusted: agent's own PostgreSQL login session, separate OS uid for agent, unrelated login, unrestricted SQL query text and bypassed RISU gateway.
- Outside scope: malicious superuser/owner, PostgreSQL server compromise, credential theft from fixture root, external human authorization, real provider customer accounts, independent cloud tenancy, transactional business process semantics or proof that RLS enforces cryptographic one-time grants.
- No new original third-party security vulnerability is claimed. RLS is an established upstream mechanism; the contribution is the connection of native decision scope, bypass attempts and independently observed effects.

## Holdout boundary

Do **not** tune this PostgreSQL-specific harness against the later S3 holdout. Next holdout candidate: pinned signed original SeaweedFS release v4.53, IAM policy and S3 object operations. Its exact version and scope must be locked and its original implementation run independently. Failure cases must be reported rather than silently broadening the target claim.
