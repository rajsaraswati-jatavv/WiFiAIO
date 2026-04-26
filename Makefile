# ============================================================
# WiFiAIO - Makefile
# ============================================================
# Usage:
#   make install        - Install dependencies
#   make dev-install    - Install with dev dependencies
#   make test           - Run test suite
#   make lint           - Run all linters
#   make format         - Auto-format code
#   make clean          - Remove build artifacts
#   make docker-build   - Build Docker image
#   make docker-run     - Run in Docker
# ============================================================

.PHONY: install dev-install test lint format clean docker-build docker-run \
        docker-up docker-down docker-logs help typecheck check

# --- Configuration ---
PYTHON       ?= python3
PIP          ?= $(PYTHON) -m pip
DOCKER       ?= docker
COMPOSE      ?= docker compose
PROJECT_NAME ?= wifiaio
IMAGE_NAME   ?= wifiaio:latest

# --- Virtual Environment ---
VENV         := .venv
VENV_PYTHON  := $(VENV)/bin/python
VENV_PIP     := $(VENV)/bin/pip

# ============================================================
# Help
# ============================================================
help: ## Show this help message
	@echo "WiFiAIO - All-in-One WiFi Auditing & Security Toolkit"
	@echo "====================================================="
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'
	@echo ""

# ============================================================
# Installation
# ============================================================
venv: ## Create virtual environment
	$(PYTHON) -m venv $(VENV)
	$(VENV_PIP) install --upgrade pip setuptools wheel

install: venv ## Install core dependencies
	$(VENV_PIP) install -r requirements.txt
	$(VENV_PIP) install -e .

dev-install: venv ## Install core + dev dependencies
	$(VENV_PIP) install -r requirements-full.txt
	$(VENV_PIP) install -e .
	$(VENV_PIP) install pre-commit
	@if [ -f .git/hooks/pre-commit ]; then echo "pre-commit already installed"; \
		else $(VENV)/bin/pre-commit install; fi

# ============================================================
# Testing
# ============================================================
test: ## Run test suite
	$(VENV_PYTHON) -m pytest tests/ -v --tb=short

test-cov: ## Run tests with coverage report
	$(VENV_PYTHON) -m pytest tests/ -v --cov=wifiaio --cov-report=term-missing --cov-report=html

test-quick: ## Run tests (fail fast, no coverage)
	$(VENV_PYTHON) -m pytest tests/ -x -q

# ============================================================
# Code Quality
# ============================================================
format: ## Auto-format code with black and isort
	$(VENV)/bin/isort src/ tests/
	$(VENV)/bin/black src/ tests/

lint: ## Run all linters
	@echo "=== flake8 ==="
	$(VENV)/bin/flake8 src/ tests/
	@echo "=== isort (check) ==="
	$(VENV)/bin/isort --check-only --diff src/ tests/
	@echo "=== black (check) ==="
	$(VENV)/bin/black --check --diff src/ tests/
	@echo "=== mypy ==="
	$(VENV)/bin/mypy src/
	@echo "=== pylint ==="
	$(VENV)/bin/pylint src/

typecheck: ## Run mypy type checker
	$(VENV)/bin/mypy src/

check: lint test ## Run linters AND tests

# ============================================================
# Docker
# ============================================================
docker-build: ## Build Docker image
	$(DOCKER) build -t $(IMAGE_NAME) .

docker-run: ## Run WiFiAIO in Docker (interactive, host network)
	$(DOCKER) run --rm -it \
		--net=host \
		--privileged \
		--cap-add=NET_ADMIN \
		--cap-add=NET_RAW \
		-v $(PWD)/captures:/opt/wifiaio/captures \
		-v $(PWD)/wordlists:/opt/wifiaio/wordlists \
		-v $(PWD)/logs:/opt/wifiaio/logs \
		-v $(PWD)/data:/opt/wifiaio/data \
		--env-file .env \
		$(IMAGE_NAME)

docker-up: ## Start services via docker compose
	$(COMPOSE) up -d

docker-down: ## Stop services via docker compose
	$(COMPOSE) down

docker-logs: ## Tail docker compose logs
	$(COMPOSE) logs -f

docker-shell: ## Open shell in running container
	$(DOCKER) exec -it wifiaio /bin/bash

# ============================================================
# Cleanup
# ============================================================
clean: ## Remove build artifacts and caches
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info
	rm -rf .eggs/
	rm -rf __pycache__/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf .tox/
	rm -rf htmlcov/
	rm -rf .coverage
	rm -rf coverage.xml
	rm -rf *.db
	rm -rf *.sqlite

distclean: clean ## Full clean including virtual environment
	rm -rf $(VENV)/
	rm -rf logs/
	rm -rf captures/
	rm -rf output/

# ============================================================
# Utilities
# ============================================================
setup-env: ## Copy .env.example to .env
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "Created .env from .env.example — please review and update values."; \
	else \
		echo ".env already exists. Skipping."; \
	fi

version: ## Show current version
	@$(VENV_PYTHON) -c "import wifiaio; print(wifiaio.__version__)" 2>/dev/null || echo "1.0.0"
