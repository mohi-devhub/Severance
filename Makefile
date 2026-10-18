BIN ?= .venv/bin/
.PHONY: up seed demo test lint bench

up:
	docker compose up -d
seed:
	$(BIN)bragent seed escalation_chain
demo:
	$(BIN)bragent demo
test:
	$(BIN)pytest -q
lint:
	$(BIN)ruff check . && $(BIN)ruff format --check .
bench:
	$(BIN)bragent benchmark
