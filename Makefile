version: keymaker/version.py
keymaker/version.py: setup.py
	echo "__version__ = '$$(python setup.py --version)'" > $@

test_deps:
	pip install .[test]

lint: test_deps
	./setup.py flake8

test: test_deps lint
	coverage run --source=$$(python setup.py --name) ./test/test.py

init_docs:
	cd docs; sphinx-quickstart

docs:
	$(MAKE) -C docs html

install: clean version
	pip install wheel
	python setup.py bdist_wheel
	pip install --upgrade dist/*.whl

clean:
	-rm -rf build dist
	-rm -rf *.egg-info

.PHONY: lint test test_deps docs install clean version keymaker/version.py

include common.mk
