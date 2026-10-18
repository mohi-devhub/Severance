.PHONY: up seed demo test lint bench

up:
	docker compose up -d
seed:
	bragent seed escalation_chain
demo:
	bragent demo
test:
	pytest -q
lint:
	ruff check . && ruff format --check .
bench:
	bragent benchmark
