.PHONY: help install dev test lint demo labs mcp clean vcan

help:                       ## show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

install:                    ## install runtime + all extras
	pip install -e ".[all]"

dev: install                ## install plus dev tooling and pre-commit
	pip install pytest ruff pre-commit
	pre-commit install || true

test:                       ## run the test suite (25 tests)
	pytest -q

lint:                       ## ruff: syntax / undefined names
	ruff check src tests examples --select=E9,F63,F7,F82

demo:                       ## run the scripted demo (record it for the README)
	python examples/demo.py

labs:                       ## run all five lab solvers
	python labs/uds-did-decrypt/solve.py
	python labs/delta-forge-patchchain/solve.py
	python labs/v2x-ecdsa-nonce/solve.py --gen 20 --reuse
	python labs/sentinel2-can-statemachine/solve.py
	python labs/seedkey-recover/solve.py

mcp:                        ## start the MCP server (stdio)
	vehsec mcp

vcan:                       ## Linux: bring up vcan0 + ICSim + UDSim
	bash scripts/setup_vcan.sh

clean:                      ## remove build/test artifacts
	rm -rf .pytest_cache .ruff_cache build dist *.egg-info
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
