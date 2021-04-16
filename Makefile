TOPDIR:=	$(abspath .)
SRCDIR=		$(TOPDIR)/src
SOURCE=		$(SRCDIR)/pyff

test:
	PYTHONPATH=$(SRCDIR) pytest

quick_test:
	PYFF_SKIP_SLOW_TESTS=1 PYTHONPATH=$(SRCDIR) pytest

test_coverage:
	coverage erase
	PYTHONPATH=$(SRCDIR) pytest --cov=src/pyff
	mv .coverage .coverage.1
	coverage combine

reformat:
	isort --line-width 120 --atomic --project eduid_scimapi --recursive $(SOURCE)
	black --line-length 120 --target-version py37 --skip-string-normalization $(SOURCE)

typecheck:
	mypy --ignore-missing-imports $(SOURCE)
