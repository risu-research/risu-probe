# Public-only development and execution policy

RISU Probe's source repository and standard GitHub Actions are PUBLIC. Every commit, PR, log and downloadable artifact must be safe to disclose permanently.

1. Only publicly licensed source, synthetic fixtures, public vendor specifications and explicitly sanitized evidence may be committed. Do not include private repository code, customer records, credentials, local environment files, private endpoints, raw nonpublic MCP/HTTP traces or unpublished sensitive results.
2. CI token permissions must be restricted to **contents: read**. Use **pull_request**, never **pull_request_target**, for untrusted PR code. Git checkout must set **persist-credentials: false**. Never pass secrets or private repository tokens into public workflows. Do not auto-merge, tag, deploy or publish.
3. Ordinary PR CI builds the public package and tests local, synthetic fixtures. It must not run target application code, launch MCP servers, contact production endpoints or check out private source. No Git submodules.
4. Expensive external-source historical tests are opt-in or restricted to trusted migration-branch push. Only immutable public Git commits are checked out. Hooks are disabled. The scanned source is input data, never imported or executed.
5. Public artifacts retain only reviewable, non-sensitive summaries and hashes; do not upload real wire payloads, user directories, proprietary code or environment dumps.
6. A future proprietary component must live in a separate private repository with separate CI. A public workflow that obtains private source through a token is NOT an acceptable workaround.
7. Any release/publishing requires explicit human approval. Protected branch reviews should enforce these guarantees; the workflow's self-check is only defense in depth.

Never assume that a scanner proves all files are safe to disclose. Human review is mandatory before merging contributions.
