# B28.1 methodological amendment: one-use wrapped delivery versus leased database credential

**Issued after initial native CI negative and before the corrected B28.1 CI execution.** The original preregistration `PRE_REGISTERED_EXTERNAL_ISSUER_PROTOCOL.md` is retained unchanged as the original statement of intent. The original OpenBao 2.7.2 publisher and PostgreSQL source versions, trusted principals, three owner rows, pre/post bytes and 14 direct resource attack cases remain exactly fixed.

## Observed infrastructure counterexample

The initial B28 GitHub runs #43376379234, #43376530043, #43376662217 and #43376863672 used an OpenBao token with `num_uses=1` to call the original PostgreSQL dynamic credential endpoint. Every attempt returned HTTP 400. The native secret error safely fingerprinted `secret cannot ... token use ... credentials ... revoked` without exposing original credential bytes or backend error text.

The 1-use *issuer token* is not interchangeable with a one-use *credential handoff*: when OpenBao's original database plugin creates a child lease tied to a consumed/revoked token, that lease cannot remain viable for subsequent database use. Claiming native one-use issuance from that design would be scientifically invalid.

## Fixed repair and scope

OpenBao, under an independently held root operator token that never reaches the agent, performs the original `database/creds/b28-write` generation and returns only its own response-wrapping token via native `bao read -wrap-ttl=5m`. The agent runs as POSIX UID 65534 and receives **only that wrapping token**, without OpenBao root or a client token able to call the credential issuance endpoint.

- The actor directly calls original `POST /v1/sys/wrapping/unwrap` once. The unwrapped data must contain a native, actual leased PostgreSQL username/password and lease ID.
- The actor repeats unwrap using the same token. Original issuer must reject it.
- The actor directly attempts `GET /v1/database/creds/b28-write` using that consumed wrapping token. It must refuse to mint another credential.
- Original OpenBao native lease **continues independently** until the owner revokes it. The agent uses the leased database credential to attempt all previously frozen direct SQL attack cases, authorized one-row effect and replay check.
- Original issuer operator calls `bao lease revoke` while the agent still holds the actual PostgreSQL password in memory. A **fresh native PostgreSQL login** must be denied, and the independently queried original ephemeral role must disappear.

This preserves stronger issuer-vs-agent separation and the exact resource scope while correcting the invalid assumption that an OpenBao `num_uses=1` client token can keep a child database lease alive. The limitation is explicit: one-use **delivery** is demonstrated by wrapping; one-use **database effect** comes from PostgreSQL's native old-state RLS rule, not response wrapping itself. The separate issuer operator, OpenBao service, PostgreSQL service, and underlying CI are all controlled by RISU in the disposable test. No new independently controlled human approval is claimed.

Official native behavior: https://openbao.org/docs/api/system/wrapping-unwrap/ and https://openbao.org/docs/secrets/databases/ .
