.PHONY: install up down demo test lint format typecheck check-imports

install:
	uv sync --all-extras

up:
	docker compose up -d --build

down:
	docker compose down

# The demo app with the memory backend and SQLite, reloading on changes
demo:
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
