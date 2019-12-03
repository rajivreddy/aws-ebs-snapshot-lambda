#!/usr/bin/env bash

.EXPORT_ALL_VARIABLES:

SHELL = /bin/bash
VENV ?= ./.aws-ebs-snapshot-lambda
PYTHON_OK := $(shell type -P python)
.SUFFIXES:

black:
	${VENV}/bin/black ./ebs-snapshot-lambda/

check_python:
	@echo '*********** Checking for Python installation ***********'
    ifeq ('$(PYTHON_OK)','')
	    $(error python interpreter: 'python' not found!)
    else
	    @echo Found Python
    endif
	@echo '*********** Checking for Python version ***********'
    ifneq ('$(PYTHON_REQUIRED)','$(PYTHON_VERSION)')
	    $(error incorrect version of python found: '${PYTHON_VERSION}'. Expected '${PYTHON_REQUIRED}'!)
    else
	    @echo Found Python ${PYTHON_REQUIRED}
    endif

setup: check_python
	@echo '**************** Creating virtualenv *******************'
	python -m venv $(VENV)
	${VENV}/bin/pip install --upgrade pip
	${VENV}/bin/pip install -r requirements.txt
	${VENV}/bin/pip install -r requirements-test.txt
	@echo '*************** Installation Complete ******************'

setup_git_hooks:
	@echo '****** Setting up git hooks ******'
	${VENV}/bin/pre-commit install

install: setup setup_git_hooks

typechecking: check_python
	${VENV}/bin/mypy ./ebs_snapshot_lambda/
	${VENV}/bin/mypy ./test/

security_checks:
	${VENV}/bin/safety check
	${VENV}/bin/bandit -r ./ebs-snapshot-lambda

clean:
	rm -rf ${VENV}

test: check_python
	find . -type f -name '*.pyc' -delete
	export PYTHONPATH="${PYTHONPATH}:`pwd`/" && ${VENV}/bin/pytest -v .