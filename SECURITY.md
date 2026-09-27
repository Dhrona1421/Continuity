# Security Policy

## Supported version

Security fixes are developed against the latest code on the `main` branch. There are no separately maintained release branches at this time.

## Report a vulnerability

Please do not report vulnerabilities in a public issue. If GitHub's private vulnerability reporting is enabled for this repository, use **Security → Report a vulnerability**. Otherwise, contact the maintainer through [the project owner's GitHub profile](https://github.com/Dhrona1421) and ask for a private reporting channel.

Include a concise description, affected version or commit, impact, and reproduction steps. Do not include real credentials, personal data, or data from systems you are not authorized to test. Please allow time for review before public disclosure.

## Credential exposure

If a provider key, password, or token is exposed, revoke it with the provider, replace it in the private deployment environment, and remove it from logs or screenshots where possible. Deleting a key from a later commit does not remove it from Git history.

## Security boundaries

Continuity is a development project, not an independently certified security product. Demo fixtures are synthetic and response actions default to dry-run. Review [the security model](docs/SECURITY.md) and [response policy](docs/RESPONSE_POLICY.md) before deploying it with real data or integrations.
