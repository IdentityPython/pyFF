TOPDIR:=	$(abspath .)
SRCDIR=		$(TOPDIR)/src
SOURCE=		$(SRCDIR)/pyff

test:
	PYTHONPATH=$(SRCDIR) pytest

quick_test:
	PYFF_SKIP_SLOW_TESTS=1 PYTHONPATH=$(SRCDIR) pytest

test_coverage:
	python -m coverage erase
	python -m coverage run -m pytest --cov=src/pyff
	mv .coverage .coverage.1
	python -m coverage combine

reformat:
	ruff --format $(SOURCE)

typecheck:
	mypy --ignore-missing-imports $(SOURCE)
