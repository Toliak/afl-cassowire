.PHONY: all prepare-dev tests lint format typecheck

all: prepare-dev

# ---------------------------

prepare-dev:
	uv sync

tests:
	uv run pytest

lint:
	uv run ruff check .

format:
	uv run ruff format --check .

typecheck:
	uv run mypy .
