## Simple developer helpers

.PHONY: install-dev test lint format openapi mutmut docker-build-https

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

mutmut:
	poetry run mutmut run --paths-to-mutate tacacs_server --tests-dir tests || true
	poetry run mutmut results

docker-build-https:
	docker build -f https-setup/Dockerfile.https -t tacacs-server:https .
