PYTHON ?= $(shell if [ -x venv/bin/python ]; then echo venv/bin/python; else echo python3; fi)

.PHONY: ruff pyright radon quality

ruff:
	$(PYTHON) -m ruff check --fix .

pyright:
	$(PYTHON) -m pyright

radon:
	$(PYTHON) -m radon cc ada.py database.py emulation_analyzer.py idc_engine.py mz_parser.py output_generator.py utils.py -n C -x F -s

quality: ruff pyright radon
