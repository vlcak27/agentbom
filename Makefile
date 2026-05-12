.PHONY: install lint test check demo clean

PYTHON ?= python3

install:
	$(PYTHON) -m pip install -e ".[dev]"

lint:
	$(PYTHON) -m ruff check .

test:
	$(PYTHON) -m pytest

check: lint test

demo:
	agentbom scan examples/research-agent --output-dir agentbom-report --html --mermaid --sarif --pretty

clean:
	rm -rf build dist .pytest_cache .ruff_cache agentbom-report
