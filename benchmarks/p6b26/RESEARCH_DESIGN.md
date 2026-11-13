# RISU P6-B26: Resource-side, object-bound authorization

Status: development experiment in isolated research branch. This is a bounded positive and negative reference fixture, not a production permission service.

## Research question

Can a resource service refuse an out-of-scope mutation even when an agent bypasses every MCP gateway and sends an HTTP write directly? Can a holder with a valid signed grant be prevented from editing other objects or other bytes?

## Tested trust boundaries

1. A separate Linux issuer UID owns an Ed25519 private signing key. Signed grants bind exactly one object, expected current SHA-256, desired content SHA-256, operation, audience, sender public key, nonce and expiration.
2. A separate resource-service UID owns a mode-0700 directory and mode-0600 SQLite database. The service verifies issuer signature and sender's Ed25519 request proof at its own HTTP mutation endpoint. An atomic SQLite transaction checks current bytes, consumes the unique nonce, and updates exactly one object.
3. The agent is a third UID, able to sign arbitrary requests using its legitimately bound key. Attempted changes to a different object, different data, and another operation must be denied by the service, independently of gateway checks.
4. A fourth attacker UID has the signed grant but lacks the holder private key; sending it must be denied.
5. Root is the trusted fixture administrator and OUTSIDE the attacker threat model. The issuer is a fixture OS identity, not a different human or external vendor.

## Fixed original state and evaluation

Protected objects: alpha = alpha-original; beta = beta-protected. Only the authorized outcome alpha = alpha-authorized is allowed; beta must remain unchanged.

Thirteen real HTTP calls: exactly 1 success and 12 denials. Two concurrent signed requests for the same authorized grant must yield one 200 and one 409, preserving one committed effect. Replays across service restart and new grants with stale preconditions must be denied.

The agent must be unable to read or write the SQLite DB or read the issuer's private key under actual Linux discretionary access controls.

An independent auditor does not import the subject implementation. It checks the signatures and cryptographic hashes, directly opens original SQLite database pages, verifies the exact resources and persisted nonce, checks all live HTTP statuses and rejects mutated evidence.

Unit tests and cross-platform product regression are development compatibility tests. Linux service, multiple OS UIDs and real HTTP requests are an independent execution environment when performed in GitHub Actions.

## Limits

This is a controlled service written for the experiment. It does not establish actual authorization by an independent external human, does not test compromise of root or the trusted resource-service process, and does not identify a defect in a third-party MCP server. Production OAuth, RFC 9396 authorization-details interoperability and RFC 9449 DPoP JWT conformance have NOT been tested.

The next holdout should use a new independent implementation and a separately controlled grant issuer, without modifying the B26 rules after examining evaluation results. Keep the controlled case as the development positive control.

References: NIST SP 800-162, RFC 9396 and RFC 9449.
