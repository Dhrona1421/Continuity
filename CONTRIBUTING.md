# Contributing to Continuity

Thank you for helping improve Continuity. Contributions of code, tests, documentation, and clear bug reports are welcome.

Before participating, please read the [Code of Conduct](CODE_OF_CONDUCT.md). For security issues, use the private process in [SECURITY.md](SECURITY.md); do not open a public issue with credentials or exploit details.

## Before you start

- Search existing issues and pull requests to avoid duplicating work.
- For a large feature or breaking API change, open an issue first to discuss its scope.
- Keep changes focused and explain the problem they solve.

## Development setup

Requirements: Python 3.11–3.13, Node.js 20 or newer, and `make` for the full one-command workflow.

```bash
make install
make verify
```

You can run focused checks directly after `make install`:

```powershell
.\.venv\Scripts\ruff.exe check backend\app backend\tests backend\alembic\versions
.\.venv\Scripts\pytest.exe backend\tests
Push-Location frontend
npm ci
npm run lint
npm run build
Pop-Location
```

On macOS or Linux, use the virtual-environment executables under `.venv/bin` and run the frontend commands from `frontend/`:

```bash
.venv/bin/ruff check backend/app backend/tests backend/alembic/versions
.venv/bin/pytest backend/tests
cd frontend && npm ci && npm run lint && npm run build
```

Docker setup, provider configuration, and demo commands are in [INSTALL.md](INSTALL.md) and the [README](README.md).

## Pull requests

1. Fork the repository and create a branch such as `fix/memory-search` or `docs/setup-guide`.
2. Make the smallest change that addresses the issue.
3. Add or update tests and documentation when behavior changes.
4. Run the relevant checks and describe their results in the pull request.
5. Include screenshots for user-interface changes when practical; use synthetic or redacted data only.

In the pull request, summarize the change, why it is needed, how it was verified, and any configuration or migration impact. Call out unverified provider behavior instead of presenting it as tested.

## Project-specific expectations

- Keep Hindsight as the incident-memory layer and Groq as the configured reasoning provider; do not describe Groq as Grok.
- Preserve provenance checks: recalled facts without a retained source record must not be presented as verified incident history.
- Recommendations remain advisory. Preserve policy, approval, audit, and dry-run safeguards.
- Keep NovaBank fixtures synthetic. Do not add real customer, tenant, or incident data.
- Never commit `.env`, API keys, passwords, tokens, logs, or generated local databases.
- Keep `.env.example` limited to blank credentials and safe placeholders.

## Reporting bugs

Include the steps to reproduce, expected behavior, actual behavior, and relevant sanitized logs. Remove credentials, personal data, and private incident details before sharing logs.
