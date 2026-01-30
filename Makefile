# OpsAgent Controller - Development Makefile

.PHONY: help install test lint format build deploy clean smoke-test readiness-test validate-deployment

# Default target
help:
	@echo "OpsAgent Controller - Available commands:"
	@echo "  install          Install development dependencies"
	@echo "  test             Run all tests"
	@echo "  test-unit        Run unit tests only"
	@echo "  test-cov         Run tests with coverage report"
	@echo "  smoke-test       Run smoke tests and readiness validation"
	@echo "  readiness-test   Run readiness validation against deployed infrastructure"
	@echo "  validate-deployment  Validate deployment with comprehensive tests"
	@echo "  lint             Run linting checks"
	@echo "  format           Format code with Black"
	@echo "  build            Build SAM application"
	@echo "  deploy           Deploy to sandbox environment"
	@echo "  local            Start local API server"
	@echo "  clean            Clean build artifacts"

# Development setup
install:
	pip install -r requirements-dev.txt

# Testing
test:
	pytest

test-unit:
	pytest -m unit

test-cov:
	pytest --cov=src --cov-report=html --cov-report=term

# Smoke tests and readiness validation
smoke-test:
	@echo "Running comprehensive smoke tests and readiness validation..."
	cd tests && python run_smoke_tests.py --suite all --verbose

readiness-test:
	@echo "Running readiness validation against deployed infrastructure..."
	cd tests && python run_smoke_tests.py --suite readiness --verbose

validate-deployment:
	@echo "Validating deployment with comprehensive test suite..."
	@echo "This will run smoke tests, readiness validation, and generate a report"
	cd tests && python run_smoke_tests.py --suite all --report-file ../deployment_validation_report.json
	@echo "Deployment validation complete. Check deployment_validation_report.json for details."

# Code quality
lint:
	flake8 src tests
	mypy src

format:
	black src tests

# SAM operations
build:
	cd infrastructure && sam build

deploy: build
	cd infrastructure && sam deploy --config-env sandbox

local: build
	cd infrastructure && sam local start-api

# Cleanup
clean:
	rm -rf .pytest_cache
	rm -rf htmlcov
	rm -rf .coverage
	rm -rf infrastructure/.aws-sam
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete