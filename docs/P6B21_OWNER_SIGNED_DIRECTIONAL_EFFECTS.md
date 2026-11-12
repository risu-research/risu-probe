# P6-B21 | Directed state effects against a resource owner's signed pre-execution scope

**Research date:** 2026-11-12  
**Branch:** `qualification/p6b21-directed-signed-owner-effects-20261112`  
**Maturity:** opt-in offline qualification prototype, 3-OS full regression and two independent original native MCP executions.

## Problem and deliberate separation of three kinds of authority

B19 established a real upstream-publisher-signed historic vulnerability where
a successful read-only-looking MCP response concealed a real external program
execution. B20 created a general direction-agnostic 2×2 state-effect
comparison and transferred it from that B19 developer positive to
another developer's original filesystem MCP server.

B21 addresses a distinct question: given a verified **observed effect**,
can we distinguish *which direction* it took and whether that exact action
was within a separately authenticated resource owner's **pre-call declared
scope**?

Three statements must remain separate:

1. **Publisher provenance**: who released or built the code that ran.
2. **Resource owner policy**: who was entitled to permit or forbid a
   selected operation against a particular resource.
3. **Physical effect**: which actual state transition occurred when
   a native MCP call completed.

An MCP tool annotation is not a resource-owner policy. In the official
2025-11-25 MCP tools specification, `ToolAnnotations` are untrusted hints.
The official March 16, 2026 MCP blog explicitly distinguishes metadata
hints from enforcement. The separate MCP HTTP OAuth authorization
specification also does not make stdio tool annotations proof of
resource ownership.

Sources:
- https://modelcontextprotocol.io/specification/2025-11-25/server/tools
- https://blog.modelcontextprotocol.io/posts/2026-03-16-tool-annotations/
- https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization

## Core: typed directional transitions

New installed opt-in checker:

```sh
risu-probe verify-mcp-effect-authority \
  --plan frozen_effect_plan.json \
  --evidence-root ORIGINAL_NATIVE_EVIDENCE \
  --authority-manifest ORIGINAL_OWNER_AUTHORITY_MANIFEST.json \
  --trust-root PINNED_OWNER_PUBLIC_ROOT.json \
  --trusted-root-sha256 DIGEST_FROM_TRUSTED_CHANNEL \
  --format json --out owner_scope_result.json
```

`src/risu_mcp_effect_authority.py` composes the **unmodified B20 source-
and-catalog-bound original MCP effect parser** with:

| Sensor | Direction | Exact rule |
| --- | --- | --- |
| Boolean | `ACTIVATE` | `false → true` |
| Boolean | `DEACTIVATE` | `true → false` |
| Counter | `INCREASE` | `after > before`, retain `delta` |
| Counter | `DECREASE` | `after < before`, retain `delta` |
| Digest | `CREATE` | `null → sha256` |
| Digest | `DELETE` | `sha256 → null` |
| Digest | `REPLACE` | two different non-null SHA-256 values |
| All | `NO_CHANGE` | same strictly typed value |

Original typed before/after values are recovered from the B20 episode
and are independently hash-checked against source JSON pointers.
The engine refuses a result if the original source record, raw native
MCP trace SHA-256, in-band catalog, tool arguments SHA, result SHA or
typed sensor statement is missing or inconsistent.

The **direction classifier has no references to Git, Python file writes,
specific vulnerabilities, application permissions, vendor identities or
fixed package versions**.

## Resource-owner authority chain

The user must explicitly pin the **trusted owner's public-root file hash
out of band**. The default policy engine never accepts an unknown self-signed
root or a server's MCP metadata as a substitute.

Each owner's root declares the exact `issuer`, the Ed25519 public-key SHA,
and the exact resource identities it is trusted to control. Prefix and
wildcard grants are refused. A separate original pre-call permission
envelope is Ed25519-signed over a domain-separated canonical JSON
document that identifies:

- The owner issuer, pinned public key, exact resource ID and actor claim.
- Exact original native `tools/call` name, arguments SHA-256 and resource
  argument's signed JSON pointer and value SHA-256.
- Exact original software distribution artifact SHA-256.
- A unique run nonce, one-hour-maximum grant validity and time window.
- The exact **allowed directions for each predeclared sensor**, with
  omission interpreted as missing evidence, not an implicit grant.

The engine checks the signature *before* interpreting any permission,
uses a separate original invocation event to correlate its time window,
and checks the physical state and signed direction scopes **after**
the source-native tool call. An observed transition outside the exact
signed operations yields `SIGNED_SCOPE_OBSERVED_VIOLATION`.

An unverifiable signature, wrong public-root hash, untrusted issuer,
wrong target path, stolen/reused nonce across cells, wrong original
software artifact, expired grant or inconsistent original trace
**fails closed as unverifiable evidence**, never as a confident
unauthorized action verdict.

**Caution:** A cryptographically valid signature only proves possession
of its issuing private key. The owner-of-resource relationship must be
independently justified through the trust-root onboarding process. This
prototype evaluates only **a CI-local synthetic resource owner**, so it
makes no claim of production user consent, legal authority, delegated
OAuth identity or protected resource rights. The claimed actor is also
not separately authenticated.

## Source-informed original external MCP evaluation

The source-original server is the *separate external project*
`kujirahand/mcp_server-filesystem`, fixed commit
`1aff1e094ed317ec2c5de06591978781d660c48a`, source blob
`f886fcbc6e61f3be8e6fd76b6e5f3ad1f8cbb7b6`.

The unmodified official public PyPI `filesystem-mcp==1.0.2` wheel has SHA256
`94610f0b73df1d3ada4ef0353353eb93695645c7b82f71ca80ed13dc1022c235`.

Its original `server.py` source bytes, PyPI wheel's module and the
installed original server module all had SHA-256
`c754a7720d52d92eb49324649b19f58b07b20703fcc2c2c1b02ce1f20152fcc8`.

This is an **original public PyPI release whose code bytes were verified
against Git**, but no upstream publisher's cryptographic release signature
is claimed here. B19 remains a **distinct already publisher-signed
historical known-bug development positive**.

For B21's new experiment, a CI runner first creates a new
POSIX-local owner-controlled **temporary fixture directory**. It creates
a fresh *real* Ed25519 key in memory, saves the corresponding public root
and its SHA-256 **before any original MCP tool call**, and issues a
separate signed permission **before each native `write_file` invocation**.
The temporary key is never written into the public artifact; a new
independent runner uses a different key.

The third-party MCP server's original package is neither patched nor
made to understand the policy. The signed scope belongs to the
**separate test fixture owner**, not to the package publisher.

### Predeclared cases

All four use the same original upstream version. The `before` and
`after` labels are fixture axes, **not versions of a repaired product**.

| Original case | Before → after | Signed owner scope | Actual B21 finding |
| --- | --- | --- | --- |
| `before_trigger` | Missing file → 29-byte file | `ACTIVATE`, `CREATE`, `INCREASE` | All 3 permitted |
| `before_control` | Identical 29-byte content → identical | `NO_CHANGE` for each | All 3 permitted |
| `after_trigger` | Missing file → 29-byte file | **`NO_CHANGE` only** for each | **3 signed-scope violations** |
| `after_control` | Existing 67-byte content → 29-byte content | `NO_CHANGE`, `REPLACE`, `DECREASE` | All 3 permitted |

Every one of the four original native MCP operations **succeeded**. That
includes the deliberately prohibited test case, because RISU currently
**audits after execution**; it is not a mandatory authorization gateway
enforcing the signed policy at the server boundary.

The actual original short-file SHA-256 is
`64073484d3790a8ec697e955a0dda6485913936edf25a7de259ff1891c9835f8`.
The actual original long-file SHA-256 is
`44c74ff17e699e9c7f0c85266c4048bf1a19e34b8084c41dde2f2ac46b453817`.

Observed first-pass result:

- **4 original source-native MCP calls correlated**.
- **4 Ed25519 pre-call fixture owner signatures verified**.
- **12 directional sensor/permission assessments**, **8 actual changes**.
- **9 transitions inside signed fixture-owner scope**.
- **3 observed changes outside signed scope**, all in one intentionally
  prohibited control case.
- **0 novel upstream vulnerabilities**.

First real original run:
https://github.com/risu-research/risu-probe/actions/runs/43327020115

The owner's public-key root hash was
`035c9494012d6b0c44cbf1fd4e557a9d48dd481b4b991b3bd01f390fd01b3f84`.
It authenticates only this local CI fixture's policy.

## Independent execution and unshared source-free audit

An entirely separate GitHub runner reinstalled the same untouched
original external wheel, generated a **different fresh private/public
owner key**, issued fresh signed pre-call policies, launched four new
original native MCP processes, and reproduced exactly the same directional
permission results.

The two independently generated public owner-root hashes differed,
as designed. Each independently verified run had 4 true original calls,
4 genuine Ed25519 signatures, 12 typed assessments, 9 within signed
scope and 3 deliberately outside scope.

The independent auditor
`benchmarks/p6b21/independent_signed_owner_real_effect_audit.py`
does **not import either RISU verifier**. It reverified:

- Original external release wheel digest and original pinned Git blob.
- Every Ed25519 signature and owner-resource scope independently.
- The original MCP JSON-RPC request/response bodies and tool catalog.
- The exact signed resource-path hash and original argument hash.
- The original physical file bytes **before and after** each call.
- The preissued signed grant's recorded UTC time window and original
  execution event identity.
- The original B21 product report's directional/permission results.

An independently corrupted physical file and an altered owner-signed
policy were rejected, with all source evidence preserved.

Independent second run:
https://github.com/risu-research/risu-probe/actions/runs/43327518214

## Historical regression and adversarial cases

The original installed package, including all B15–B20 functionality
and new B21 controls, passed **444 tests each** on Ubuntu, Windows
and macOS:

https://github.com/risu-research/risu-probe/actions/runs/43326394106

The new synthetic adversarial suite includes copied grant contents,
different signatures, different pinned public-key roots, wrong resource
ownership declarations, wrong tool, mismatched actual argument, wrong
software distribution, expired or postdated grant, cross-case nonce
reuse, forged original observer, invalid transition scopes, and
the `DECREASE`, `DEACTIVATE`, `DELETE` and `REPLACE` classifiers.
These adversarial mutations are not counted as external defects.

## Scientific and engineering boundaries

**What is actually supported:** Given a pretrusted fixture owner root,
the source-integrity-correlated original MCP call, an original
preissued signed scope, and actual original measured before/after
values, RISU can distinguish direction-specific scope compliance
from deliberately out-of-scope operations. The same signed grant
cannot be silently reused on a different tool, target resource,
package version, or case without rejection.

**What remains to demonstrate:** The root issuer's authority over a
*real independent user's resource*, binding a real authenticated
actor (e.g. end-user consent and OAuth scopes), a trusted independent
sensor, an actual enforcement gateway, durable replay prevention, and
a previously untested third-party defective/repaired software pair.
These are not established by the fixture-only positive controls.

An observed `SIGNED_SCOPE_OBSERVED_VIOLATION` is a **scoped policy
disagreement**, not an assertion that the third-party MCP server
exploited or bypassed OS access controls. It does not prove arbitrary
unmonitored side effects or whether a policy is legally valid.

### Highest-value follow-up

Deploy a **pre-call guard** that checks a real owner-approved scope and
blocks forbidden actions before server execution, then use OS-level
read/write permissions plus a normal authorized path as independent
controls. Integrate a genuinely independent principal/owner registry
with key rotation/revocation and a replay ledger. Then freeze the
authorization decisions before evaluating a different real third-
party before/fix pair. This would move the work from post-hoc signed
scope conformance toward externally trusted **permission enforcement**.
