env: setup.py
	virtualenv env
	env/bin/pip install .
	env/bin/pip list --outdated

lint:
	./setup.py flake8

test: env lint
	source env/bin/activate; ./setup.py test -v

init_docs:
	cd docs; sphinx-quickstart

docs:
	$(MAKE) -C docs html

install:
	python3 setup.py bdist_wheel
	pip3 install --upgrade dist/*.whl

.PHONY: test release docs lint

include common.mk
