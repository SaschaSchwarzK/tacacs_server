## Simple developer helpers

.PHONY: install-dev test lint format openapi mutmut docker-build-https docker-test-https

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
	docker build -f docker/Dockerfile.https -t tacacs-server:https .

docker-test-https:
	# Build HTTPS image
	docker build -f docker/Dockerfile.https -t tacacs-server:https .
	# Ensure no old test container is running
	-docker rm -f tacacs-https-test 2>/dev/null || true
	# Run container with self-signed cert (no real Azure required)
	docker run -d --rm --name tacacs-https-test \
	  -e CUSTOMER_ID=test \
	  -e AZURE_STORAGE_CONNECTION_STRING=UseDevelopmentStorage=true \
	  -e STORAGE_CONTAINER=tacacs-data \
	  -e ADMIN_PASSWORD=DevAdminPass1 \
	  -e API_TOKEN=devtoken \
	  -p 8443:8443 \
	  tacacs-server:https
	# Wait for HTTPS health endpoint
	@echo "Waiting for HTTPS health on https://127.0.0.1:8443/health ..."
	@set -e; \
	for i in $$(seq 1 30); do \
	  if ! docker ps --format '{{.Names}}' | grep -q '^tacacs-https-test$$'; then \
	    echo "Container exited unexpectedly"; \
	    docker logs tacacs-https-test || true; \
	    exit 1; \
	  fi; \
	  if curl -kfsS https://127.0.0.1:8443/health >/dev/null 2>&1; then \
	    echo "HTTPS container healthcheck OK"; \
	    break; \
	  fi; \
	  sleep 2; \
	  if [ $$i -eq 30 ]; then \
	    echo "Timed out waiting for HTTPS health"; \
	    docker logs tacacs-https-test || true; \
	    exit 1; \
	  fi; \
	done
	# Cleanup
	-docker rm -f tacacs-https-test 2>/dev/null || true
