# B53 — Official SDK native stdio qualification

2026-11-27. Development integration, not an independent third-party agent holdout.

- B52 frozen five-module ZIP SHA-256: 976870182cd87d286788328360e0ed874957bcefc7e2ea153166565c35d332e9.
- Evaluator SHA-256: afcee0cb29dc3ffa6ac333966eea59acc08a4aa5fbce5fce049d0c1bf9344b96.
- Official MCP Python SDK 2.3.0 wheel SHA-256: dd0c44c089d16453e8ae31a3877a0054d7a2314caaa81f5e0541b9b1734b2377; PyPI publishing source 2118f14f8a19bc158d8a1cf90af58d85d187f849.
- Preregistration e7dd9a6f13bf4a677703b6a27408dd1112a6010c. Sources under benchmarks/p6b53/; workflow .github/workflows/p6b53-official-sdk.yml.
- Actual successful push run https://github.com/risu-research/risu-probe/actions/runs/46077846632 (head 0d96764d93aa85f68aa07138d09919cfc90b0d6c), job 140769668447. Job log includes wheel and frozen source hash checks and B53_OFFICIAL_SDK_PASS.
- Evidence artifact 15236101621 (32379 bytes), SHA-256 ca63cc90378c00a7a09da06e855dc8780194e1b5436acd68171c13bd9bd5795c. Downloaded exact archive and verified all 38 manifest entries and archive CRCs. Offline forensic re-read from SHA256 Git bundle and read-only SQLite: 6/6 cases, five START rows, three terminal rows, one apply commit, one withdrawal, final effect 7. Original owner grant, actor execution and dispatch signatures and winning attempt verified. A local bare clone initially did not import the custom ref; explicit ref fetch succeeded. Forensic clone is evidence only, not the original live inode-bound destination.
- Negotiated MCP protocol 2026-07-28 on all six fresh stdio connections; native SDK ID 3 in each, separately scoped by trusted test-launcher connection ID. Before-effect crash exit 81/no reply; after-effect crash exit 82/no reply, winning attempt proven; retry successful without duplicate change; terminal crash exit 93/no reply; wrong signed ID and withdrawn grant both SDK is_error true. B52 canonical journal projection is separate from the actual captured SDK wire, and no canonical byte-equality claim is made about SDK response encoding.
- Additional draft PR #5 to B44 qualification (not main) completed official SDK job 140769785690 successfully, run https://github.com/risu-research/risu-probe/actions/runs/46077881627; closed without merge. Primary quantitative claims use original push run only.
- Public main verified still 8d622b792b4ae58b7157fd81ee5f95d6febcfd53. No release.

Trust boundary: official SDK client/server unmodified; test-owned signing proxy rewrites the dispatch argument after observing SDK request ID; model IDs and connection namespace are fixture-issued, not authenticated external agent or remote HTTP identities. Shared OS privilege, no separate key custody qualification, no real LLM. Official SDK wire compatibility here is stdio and narrow fixture tool only. No independent external agent or production API validation. Dependencies recorded but only SDK wheel and frozen code hash pinned. Next: original external agent with retained tool call ID, source-pinned, instrument a minimal boundary before SDK transport and independently capture raw frames. Qualify simultaneous calls on one connection, raw SDK response evidence, HTTP identity, and trusted key custody separately.

Evidence is available in the Actions archive (retention 90 days) and the B53 local master checkpoint.
