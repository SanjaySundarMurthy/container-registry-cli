# container-registry-cli Makefile
# Common development commands

.PHONY: help install dev lint format test coverage typecheck clean build docker all

help:  ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

install:  ## Install package in production mode
	pip install .

dev:  ## Install package in development mode with all dependencies
	pip install -e ".[dev]"
	pip install pytest-cov mypy types-PyYAML pre-commit
	pre-commit install

lint:  ## Run ruff linter
	ruff check .

format:  ## Format code with ruff
	ruff format .
	ruff check . --fix

test:  ## Run tests
	pytest -v --tb=short

coverage:  ## Run tests with coverage report
	pytest -v --cov=container_registry_cli --cov-report=term-missing --cov-report=html
	@echo "HTML report: htmlcov/index.html"

typecheck:  ## Run mypy type checker
	mypy container_registry_cli/ --ignore-missing-imports

clean:  ## Remove build artifacts and caches
	rm -rf build/ dist/ *.egg-info/ .pytest_cache/ .ruff_cache/ .mypy_cache/
	rm -rf htmlcov/ .coverage coverage.xml
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

build:  ## Build distribution packages
	python -m build

docker:  ## Build Docker image
	docker build -t container-registry-cli:latest .

all: lint typecheck test  ## Run lint, typecheck, and tests
