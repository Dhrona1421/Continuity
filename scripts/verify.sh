#!/usr/bin/env sh
set -eu

printf '%s\n' '== Backend lint and tests =='
(cd backend && python -m ruff check app tests alembic/versions && python -m pytest --cov=app --cov-report=term-missing --cov-fail-under=85)
printf '%s\n' '== Migration check =='
(cd backend && GHOSTSOC_ENV=test GHOSTSOC_DATABASE_URL="sqlite:///./migration-check.db" alembic upgrade head && GHOSTSOC_ENV=test GHOSTSOC_DATABASE_URL="sqlite:///./migration-check.db" alembic check && GHOSTSOC_ENV=test GHOSTSOC_DATABASE_URL="sqlite:///./migration-check.db" alembic downgrade base && rm -f migration-check.db)
printf '%s\n' '== Frontend dependency audit, lint and build =='
(cd frontend && npm audit && npm run lint && npm run build)
if grep -R "React\\.StrictMode" frontend/dist/assets >/dev/null 2>&1; then
  echo 'Frontend build contains an unbound React.StrictMode namespace' >&2
  exit 1
fi
printf '%s\n' '== Secret-like tracked file scan =='
if git grep -nEI '(AKIA[0-9A-Z]{16}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----|ghp_[A-Za-z0-9]{36})' -- ':!docs/*'; then
  echo 'Potential secret found' >&2
  exit 1
fi
printf '%s\n' 'Verification passed.'
