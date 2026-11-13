# RISU Probe P6-B26 | Resource-side owner enforcement

**Verified development experiment, 2026-11-13 UTC.**

## What was implemented

An experiment-specific Ed25519 owner-issued authorization grant binds the receiver's public key, resource ID, operation, expected resource state SHA-256, desired content SHA-256, audience, nonce and expiry. The requesting agent signs the actual HTTP request with its separately held private key.

The protected resource service checks **both** signatures and the scope before changing state. Its SQLite transaction checks the current resource bytes, consumes the nonce and commits the permitted effect atomically. Authorization remains enforced at the service even if the MCP gateway is bypassed or the legitimate holder sends a different object or content. The protected database and the issuer private key are not accessible using the agent's OS UID.

Four separate Linux UIDs (issuer, service, agent, attacker) are created by the disposable CI runner. The root fixture administrator is explicitly trusted in this test and is outside the threat model.

## Results

- Final GitHub Actions full run: https://github.com/risu-research/risu-probe/actions/runs/43359724240
- Source branch: qualification/p6b26-resource-side-owner-enforcement-20261112
- Final CI workflow commit: 1a11040fe860b813e1a21d78a0fb0a7bd1cf7f7a
- Source module: src/risu_mcp_resource_guard.py
- Installed CLI: risu-probe enforce-mcp-resource-side
- **Three OS installed wheel regression: 558 tests on Ubuntu, 558 on Windows, 558 on macOS, all passing.**
- **Linux four-UID real HTTP positive/negative experiment: 13 calls, 1 authorized write, 12 denials.**
- Two simultaneous clients reusing one signed grant: HTTP 200 and 409; exactly one SQLite commit.
- Replay after service restart: HTTP 409, with the nonce still consumed.
- Legitimate agent with valid private key and valid grant but changed target/bytes: HTTP 403.
- A separate attacker UID possessing only the owner's signed grant but a different private key: HTTP 403.
- Actual Linux agent UID direct SQLite read and write, and issuer private-key read: kernel DAC denied.
- Independent auditor directly opens raw SQLite bytes without importing the implementation. Verifies issuer signature, holder request proof, unchanged second resource and all 13 observed response codes; PASS.
- Tampering with an original case outcome causes independent audit to refuse the report.

Original CI evidence ZIP:
https://github.com/risu-research/risu-probe/actions/runs/43359724240/artifacts/14007402378

The evidence ZIP contains original_live_result.json, owner_resources.sqlite3, independent_audit.json and the server's live log. The GitHub Actions audit and a separate offline rerun against the downloaded original evidence produced byte-identical audit JSON.

## Boundaries and value

The real enforcement result is stronger than a post-execution audit: the protected service itself rejected out-of-scope changes. This advances B25's fixed-trusted-writer design to receiver-side, object-bound permission enforcement.

**Scope of evidence:** A separately executing, access-controlled Linux research fixture and an implementation authored for this experiment. It does not verify a second independent *human*, a production *external* resource owner, or a third-party MCP server. Compromising the resource-service UID, the issuer UID, or the root fixture administrator is outside the test. This is not an OAuth or DPoP interoperability claim or a new upstream software vulnerability.

B25.1's real GitHub human approval remains a separate verified positive case:
https://github.com/risu-research/risu-verify/actions/runs/43355918665

## Research continuation

Freeze the B26 reference service as a development benchmark. The next evaluation should challenge the approach using at least one **independently authored resource service** with its own native object-level authorization enforcement and a **separately controlled credential issuer**, without rewriting the rules after observing its outcomes. Use independent normal controls, deliberately mis-scoped requests and actual before/after bytes.

Context standards: NIST SP 800-162 (ABAC), RFC 9396 (fine-grained OAuth authorization details), RFC 9449 (sender-constrained tokens). The B26 fixture is an experiment-specific reference protocol, not an implementation of those RFCs.
