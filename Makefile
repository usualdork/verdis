# Verdis development tasks.
#
#   make test        the whole suite
#   make check       lint, types and tests
#   make sandbox     the base image the build and run stages use
#   make demo        triage the example report in a real sandbox

PYTHON ?= python3
VENV   ?= .venv
BIN     = $(VENV)/bin
PY      = $(BIN)/python
PIP     = $(BIN)/pip
PYTEST  = $(BIN)/pytest
RUFF    = $(BIN)/ruff
MYPY    = $(BIN)/mypy

IMAGE ?= ghcr.io/usualdork/verdis/base:latest
SANDBOX ?= docker
RUNTIME ?= podman

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

$(VENV):
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -e ".[dev]"

.PHONY: install
install: $(VENV)  ## set up the development environment

.PHONY: test
test: install  ## run the whole suite
	$(PYTEST) -q

.PHONY: test-fast
test-fast: install  ## run everything except the container-backed suites
	$(PYTEST) -q -m "not slow"

.PHONY: lint
lint: install  ## check the style
	$(RUFF) check src tests benchmark plugins action

.PHONY: format
format: install  ## fix the style
	$(RUFF) check --fix src tests benchmark plugins action

.PHONY: types
types: install  ## check the types
	$(MYPY) src

.PHONY: check
check: lint types test  ## everything the CI runs

.PHONY: coverage
coverage: install  ## the suite, with coverage
	$(PYTEST) -q --cov=verdis --cov-report=term-missing

.PHONY: sbom
sbom: install  ## write the software bill of materials
	$(PY) tools/sbom.py --out dist/sbom.json

.PHONY: schemas
schemas: install  ## regenerate the published JSON schemas
	$(PY) -m verdis.schemas.generate schemas/

.PHONY: sandbox
sandbox:  ## build the image the build and run stages use
	docker build -f docker/base.Dockerfile -t $(IMAGE) .

.PHONY: corpus
corpus: install  ## build the benchmark corpus
	$(PY) benchmark/corpus/build.py

.PHONY: corpus-check
corpus-check: install  ## check that every program behaves as the corpus claims
	$(PY) benchmark/corpus/verify.py --runtime $(RUNTIME)

.PHONY: benchmark
benchmark: corpus  ## build and run the benchmark
	$(PY) benchmark/run.py

.PHONY: benchmark-sandbox
benchmark-sandbox: sandbox corpus  ## run the benchmark inside a container
	VERDIS_WORK_DIR=$${VERDIS_WORK_DIR:-$$HOME/.cache/verdis} \
		$(PY) benchmark/run.py --sandbox $(SANDBOX)

.PHONY: docs
docs: install  ## serve the documentation
	$(BIN)/mkdocs serve

.PHONY: recording
recording: install  ## record the README's terminal run
	$(PY) tools/recording.py --out docs/assets/verdis-demo.svg

.PHONY: assets
assets: install  ## redraw the README and documentation artwork
	$(PY) tools/assets.py

.PHONY: clean
clean:  ## remove the build artefacts
	rm -rf dist build .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
