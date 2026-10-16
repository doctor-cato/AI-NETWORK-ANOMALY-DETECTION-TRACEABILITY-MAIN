# Makefile — commands for this project
# Not all targets fully implement training; they reference existing code/scripts.

PYTHON := python
PIP := pip

.PHONY: all install check-env check-data run-baseline run-evaluate run-inference test format-check clean

all: install check-env

install:
	$(PIP) install -e .

check-env:
	$(PYTHON) -c "import pandas, numpy, sklearn; print('Env OK')"

check-data:
	$(PYTHON) scripts/validate_data.py

run-baseline:
	$(PYTHON) scripts/run_experiments.py --step baseline

run-evaluate:
	$(PYTHON) scripts/run_experiments.py --step evaluate

run-inference:
	$(PYTHON) scripts/run_experiments.py --step inference

test:
	$(PYTHON) -m pytest tests/ -q --tb=short

format-check:
	@echo "Formatting check planned; add ruff/black when configured"
	$(PYTHON) -m py_compile src/network_anomaly/config.py || exit 1

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete 2>/dev/null || true
