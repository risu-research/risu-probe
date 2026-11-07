# Contributing

Contributions that make the CLI more useful, precise or safe are welcome.

- Submit minimal, reproducible examples using synthetic or explicitly public inputs.
- Never submit credentials, personal/customer data, private logs, proprietary source, unapproved upstream patches or raw confidential protocol traces.
- Explain the observed behavior, expected behavior and affected rule or command.
- For behavior changes, add a test that detects the regression and confirm there are no unexpected verdict changes.
- Run unit tests and an installed-wheel `risu-probe check .` before opening a PR.
- PR CI runs with read-only permissions and no secrets. No release, deployment or automatic merge is authorized.
- Avoid any new project-code execution or remote API access in the default check path.

See [Public-only CI policy](docs/PUBLIC_ONLY_POLICY.md).
