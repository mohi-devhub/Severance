BIN ?= .venv/bin/
.PHONY: setup up seed demo test test-agent lint bench bench-engine

setup:
	uv sync --locked --all-extras

up:
	docker compose up -d --wait
seed:
	$(BIN)bragent seed escalation_chain
demo:
	$(BIN)bragent demo
test:
	$(BIN)pytest -q -m 'not agent'
test-agent:
	BRAGENT_RUN_AGENT=1 $(BIN)pytest -q -m agent
lint:
	$(BIN)ruff check . && $(BIN)ruff format --check .
bench:
	$(BIN)bragent benchmark
bench-engine:
	$(BIN)bragent benchmark --llm-runs 0
