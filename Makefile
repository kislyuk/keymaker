SHELL=/bin/bash

env: requirements.txt
	virtualenv --python=python3 env
	source env/bin/activate; pip install --requirement=requirements.txt
	source env/bin/activate; pip list --outdated

lint:
	./setup.py flake8

test: env lint
	source env/bin/activate; ./setup.py test -v

release: lint docs
	python setup.py sdist upload -s -i D2069255

init_docs:
	cd docs; sphinx-quickstart

docs:
	$(MAKE) -C docs html

install:
	python3 ./setup.py install

.PHONY: test lint release docs
