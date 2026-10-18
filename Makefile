BIN ?= .venv/bin/
.PHONY: setup up seed demo test test-agent lint bench bench-engine bench-public

setup:
	uv sync --locked --all-extras

up:
	docker compose up -d --wait
seed:
	$(BIN)severance seed escalation_chain
demo:
	$(BIN)severance demo
test:
	$(BIN)pytest -q -m 'not agent'
test-agent:
	SEVERANCE_RUN_AGENT=1 $(BIN)pytest -q -m agent
lint:
	$(BIN)ruff check . && $(BIN)ruff format --check .
bench:
	$(BIN)severance benchmark
bench-engine:
	$(BIN)severance benchmark --llm-runs 0
bench-public:
	$(BIN)severance benchmark-public
