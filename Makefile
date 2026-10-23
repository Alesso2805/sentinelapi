.PHONY: install up down migrate demo test lint format typecheck check-imports bench

install:
	uv sync --all-extras

# Migrates, then starts the API; --wait returns once every healthcheck is green
up:
	docker compose up -d --build --wait

down:
	docker compose down

# Creates or upgrades the audit table at SENTINEL_DATABASE_URL
migrate:
	uv run sentinel migrate

# The demo app with the memory backend and SQLite, reloading on changes
demo: migrate
	uv run uvicorn examples.demo_app.main:app --reload

test:
	uv run pytest

lint:
	uv run ruff check .
	uv run ruff format --check .
	uv run lint-imports

format:
	uv run ruff check --fix .
	uv run ruff format .

typecheck:
	uv run mypy

# Fails if the library needs a package that is only an extra or a dev dependency
check-imports:
	uv run --isolated --no-dev python scripts/check_imports.py

# Latency SentinelAPI adds per request; with SENTINEL_BENCH_REDIS_URL set, on Redis too
bench:
	uv run python benchmarks/overhead.py
