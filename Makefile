.PHONY: black build clean clean-test clean-pyc clean-build clean-docs docs docs-deploy help test coverage version-major version-minor version-patch
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

clean: clean-build clean-pyc clean-test clean-docs ## remove all build, test, coverage and Python artifacts


clean-build: ## remove build artifacts
	rm -rf build/
	rm -rf dist/
	rm -rf .eggs/
	find . -name '*.egg-info' -exec rm -fr {} +
	find . -name '*.egg' -exec rm -f {} +

clean-docs: ## clean the /docs/
	rm -rf docs/site/

clean-pyc: ## remove Python file artifacts
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +
	find . -name '__pycache__' -exec rm -fr {} +

clean-test: ## remove test and coverage artifacts
	rm -f .coverage
	rm -rf htmlcov/

test: ## run tests quickly with the default Python
	python -m unittest discover -v -s tests/

coverage: ## check code coverage quickly with the default Python
	coverage run -m unittest discover -v -s tests/
	coverage report
	coverage html
	$(BROWSER) htmlcov/index.html

docs: ## generate Sphinx HTML documentation, including API docs
	rm -rf docs/site/
	mkdocs build -f docs/mkdocs.yml
	$(BROWSER) docs/site/index.html

docs-deploy: ## manually deploy the docs to github pages
	aws s3 sync ./docs/site  s3://docs-coz/neo3/mamba --acl public-read

type: ## perform static type checking using mypy
	mypy neo3/

black: ## apply black formatting
	black neo3/ examples/ tests/

build: ## create source distribution and wheel
	python -m build

version-major: ## bump the major version prior to release, auto commits and tag
	bumpversion major

version-minor: ## bump the minor version prior to release, auto commits and tag
	bumpversion minor

version-patch: ## bump the patch version prior to release, auto commits and tag
	bumpversion patch
