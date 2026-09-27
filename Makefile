.PHONY: install test lint build run migrate demo reset verify

install:
	python3 -m venv .venv
	.venv/bin/pip install -e './backend[test]'
	cd frontend && npm ci

migrate:
	cd backend && ../.venv/bin/alembic upgrade head

run:
	cd backend && ../.venv/bin/uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

test:
	cd backend && ../.venv/bin/pytest

lint:
	cd backend && ../.venv/bin/ruff check app tests
	cd frontend && npm run lint

build:
	cd frontend && npm run build

demo:
	python3 scripts/demo_client.py run

reset:
	python3 scripts/demo_client.py reset

verify:
	PATH="$(CURDIR)/.venv/bin:$$PATH" ./scripts/verify.sh
