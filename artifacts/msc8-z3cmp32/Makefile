# Focused gate for the standalone comparator, usable before or after installation.
VEXTEST ?= /home/xor/vextest
PYTHON ?= $(VEXTEST)/.venv/bin/python
CHECK_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
SOURCES := $(addprefix $(CHECK_DIR),z3cmp32.py flat32_adapter.py flat32_catalog.py flat32_cfg.py flat32_region.py flat32_verdict.py)
TESTS := $(addprefix $(CHECK_DIR),test_z3cmp32.py test_proof_verdicts.py)

.PHONY: check lint typecheck test
check: lint typecheck test
lint:
	PYTHON_JIT=1 $(PYTHON) -m ruff check --config $(VEXTEST)/pyproject.toml --preview --extend-select C901,PLR0916 $(SOURCES) $(TESTS)
typecheck:
	PYTHON_JIT=1 $(PYTHON) -m pyright --project $(VEXTEST)/pyproject.toml --pythonpath $(PYTHON) $(SOURCES)
test:
	PYTHON_JIT=1 $(PYTHON) -m pytest $(TESTS) -n 7 --tb=short --durations=5 -q
