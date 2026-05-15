.PHONY: install lint test check demo mcp-demo clean

PYTHON ?= python3
AGENTBOM ?= $(shell if [ -x .venv/bin/agentbom ]; then printf '.venv/bin/agentbom'; else printf 'agentbom'; fi)

install:
	$(PYTHON) -m pip install -e ".[dev]"

lint:
	$(PYTHON) -m ruff check .

test:
	$(PYTHON) -m pytest

check: lint test

demo:
	$(AGENTBOM) scan examples/research-agent --output-dir agentbom-report --html --mermaid --sarif --pretty

mcp-demo:
	$(AGENTBOM) scan examples/mcp-safe-agent --output-dir agentbom-report/mcp-safe --html --mermaid --sarif --pretty
	$(AGENTBOM) scan examples/mcp-risky-agent --output-dir agentbom-report/mcp-risky --html --mermaid --sarif --pretty
	$(AGENTBOM) scan examples/mcp-risky-agent --policy examples/policies/mcp-policy.yaml --output-dir agentbom-report/mcp-policy --html --mermaid --sarif --pretty

clean:
	rm -rf build dist .pytest_cache .ruff_cache agentbom-report
