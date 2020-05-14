.PHONY: clean clean-test clean-pyc clean-build docs help test lint coverage
.DEFAULT_GOAL := help
define BROWSER_PYSCRIPT
import os, webbrowser, sys
try:
	from urllib import pathname2url
except:
	from urllib.request import pathname2url

webbrowser.open("file://" + pathname2url(os.path.abspath(sys.argv[1])))
endef
export BROWSER_PYSCRIPT

define PRINT_HELP_PYSCRIPT
import re, sys

for line in sys.stdin:
	match = re.match(r'^([a-zA-Z_-]+):.*?## (.*)$$', line)
	if match:
		target, help = match.groups()
		print("%-20s %s" % (target, help))
endef
export PRINT_HELP_PYSCRIPT
BROWSER := python3 -c "$$BROWSER_PYSCRIPT"

help:
	@python3 -c "$$PRINT_HELP_PYSCRIPT" < $(MAKEFILE_LIST)

clean: clean-build clean-pyc clean-test ## remove all build, test, coverage and Python artifacts


clean-build: ## remove build artifacts
	rm -rf build/
	rm -rf dist/
	rm -rf .eggs/
	find . -name '*.egg-info' -exec rm -fr {} +
	find . -name '*.egg' -exec rm -f {} +

clean-pyc: ## remove Python file artifacts
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +
	find . -name '__pycache__' -exec rm -fr {} +

clean-test: ## remove test and coverage artifacts
	rm -f .coverage
	rm -rf htmlcov/

lint: ## check style with flake8
	pycodestyle --max-line-length=120 neo3 

test: ## run tests quickly with the default Python
	python -m unittest discover -v -s tests/

coverage: ## check code coverage quickly with the default Python
	coverage run -m unittest discover -v -s tests/
	coverage report
	coverage html
	$(BROWSER) htmlcov/index.html

clean-docs:
	cd docs && $(MAKE) clean

docs: ## generate Sphinx HTML documentation, including API docs
	rm -rf docs/build/
	sphinx-build -b html docs/source/ docs/build/
	$(BROWSER) docs/build/index.html

type: ## perform static type checking using mypy
	mypy neo3/
