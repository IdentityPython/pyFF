from unittest import TestCase
from pyff.decorators import retry


class TestRetry(TestCase):

    def test_retry_nop(self):
        status = [False]

        @retry(None, delay=1, backoff=1)
        def runs_ok():
            status[0] = True
        runs_ok()
        assert(status[0])

    def test_retry_fail(self):
        status = [False]
        @retry(ValueError, delay=1, backoff=1)
        def fails():
            raise ValueError("nope")

        try:
            fails()
            assert False
        except ValueError, ex:
            pass
        assert(not status[0])
