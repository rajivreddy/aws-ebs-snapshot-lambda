#!/usr/bin/env bash

.EXPORT_ALL_VARIABLES:

SHELL = /bin/bash
VENV ?= ./.aws-ebs-snapshot-lambda
PYTHON_VERSION := $(shell python -V | cut -d' ' -f2)
PYTHON_OK := $(shell type -P python)
PYTHON_REQUIRED = 3.7.3
.SUFFIXES:
BUCKET_NAME := mdtp-lambda-functions
ENVIRONMENTS := management sandbox development qa staging integration externaltest production
LAMBDA_NAME := aws-ebs-snapshot-lambda
LAMBDA_VERSION := $(shell cat .release-version)
LATEST_TAG := $(shell git tag --sort=v:refname \
	| grep -E "^[0-9]+\.[0-9]+\.[0-9]+" | tail -1 )
TAG_MAJOR_NUMBER := $(shell echo $(LATEST_TAG) | cut -f 1 -d '.' )
TAG_RELEASE_NUMBER := $(shell echo $(LATEST_TAG) | cut -f 2 -d '.' )
TAG_PATCH_NUMBER := $(shell echo $(LATEST_TAG) | cut -f 3 -d '.' )

bumpversion:
	echo "$(TAG_MAJOR_NUMBER).$(TAG_RELEASE_NUMBER).$$(( $(TAG_PATCH_NUMBER) + 1))" > .release-version

black:
	${VENV}/bin/black ./ebs_snapshot_lambda/
	${VENV}/bin/black ./test/

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

ci_build:
	docker run --user `id -u`:`id -g` -v `pwd`:/src --workdir /src python-build-env make clean setup test security_checks package

ci_docker_build:
	docker build -t python-build-env -f Dockerfile.jenkins .

ci_publish: publish

clean:
	rm -rf ${VENV}

install: setup setup_git_hooks

package: bumpversion
	cd ebs_snapshot_lambda && zip ../${LAMBDA_NAME}.zip ./aws_typings.py
	cd ebs_snapshot_lambda && zip ../${LAMBDA_NAME}.zip ./ebs_snapshot_lambda.py
	mkdir -p pip_lambda_packages
	pip install -t pip_lambda_packages -r requirements.txt
	cd pip_lambda_packages && zip -r ../${LAMBDA_NAME}.zip .
	openssl dgst -sha256 -binary ${LAMBDA_NAME}.zip | openssl enc -base64 > ${LAMBDA_NAME}.zip.base64sha256

publish:
	for env in ${ENVIRONMENTS}; do \
		aws s3 cp ${LAMBDA_NAME}.zip s3://${BUCKET_NAME}-$${env}/${LAMBDA_NAME}/${LAMBDA_NAME}.${LAMBDA_VERSION}.zip --acl=bucket-owner-full-control ;\
		aws s3 cp ${LAMBDA_NAME}.zip.base64sha256 s3://${BUCKET_NAME}-$${env}/${LAMBDA_NAME}/${LAMBDA_NAME}.${LAMBDA_VERSION}.zip.base64sha256 --content-type text/plain --acl=bucket-owner-full-control ;\
	done

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


security_checks:
	${VENV}/bin/safety check
	${VENV}/bin/bandit -r ./ebs_snapshot_lambda

test: check_python
	find . -type f -name '*.pyc' -delete
	export PYTHONPATH="${PYTHONPATH}:`pwd`/ebs_snapshot_lambda" && ${VENV}/bin/pytest -v .

typechecking: check_python
	${VENV}/bin/mypy ./ebs_snapshot_lambda/
	${VENV}/bin/mypy ./test/
