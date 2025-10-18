## Simple developer helpers

.PHONY: install-dev test lint format openapi

install-dev:
	poetry install

test:
	poetry run pytest -q

lint:
	poetry run ruff check . && poetry run mypy .

format:
	poetry run ruff format .

openapi:
	poetry run python scripts/generate_openapi.py
