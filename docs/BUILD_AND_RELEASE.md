# Build and release policy (P6-A)

The **only** production source input is `src/` in this product repository. The immutable P5-E reference wheel remains in the [public research repository](https://github.com/risu-research/openapi-mcp-problem-semantics) and is SHA-256-verified before explicit migration-parity runs. It is not the product source. Historical research and early experiments remain intact.

## Developer workflow

```bash
python -m pip install --upgrade setuptools wheel
python -m pip wheel --no-deps --no-build-isolation --wheel-dir dist .
python -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/risu-probe doctor
.venv/bin/risu-probe check ./project
```

Windows uses `.venv\\Scripts\\python.exe` and `.venv\\Scripts\\risu-probe.exe`. `uv tool install .` is also supported. Explicit source-path installation is important; this version has not been published to PyPI.

## CI contract

- `provenance/verify_distribution.py`: SHA-256 of all 38 source modules must match historical P5-E CI reference; wheel cannot contain extra, missing or modified engine modules.
- `tests/test_product.py`: installed wheel CLI, static no-exec, Unicode, doctor, YAML, SARIF, legacy command help and error guidance.
- `benchmarks/parity.py`: ten fixed public Git commits, full JSON output exact parity between historical installed wheel and rebuilt installed wheel, and complete static scan coverage.
- Linux, Windows, macOS are tested independently. If a platform fails, no cross-platform promotion claim.
- CI artifacts retain the two installed wheel hashes, report hashes, and the ten-repo comparison. Tests do **not** run code from scanned repositories.

## Safe promotion / changes

First confirm exact module parity. If a future release changes product code, update this provenance in a new version with explicit rule changes and independent counterexample regression tests. Never blindly update the expected SHA hashes merely to make tests pass. Publish documentation, wheel, and pinned diagnostic rules together; do not auto-merge to `main` or publish to PyPI without explicit release review.

Modelled practices: Ruff's stable CLI and explicit rule semantics, uv's one-path install, oasdiff/mcpdiff's compatibility CI, Schemathesis's reproducible counterexamples and Renovate's reviewed gated changes.

## Safe public CI

PR checks have read-only GitHub token permission, `persist-credentials: false`, no secrets, no `pull_request_target`, and no package deployment. The 10-external-repo historical parity job is isolated from external PR checks and uses only pinned publicly readable Git commits. No customer data or private repository code is allowed in public CI.
