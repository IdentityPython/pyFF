from StringIO import StringIO
import logging
from unittest import TestCase
from mock import patch
from pyff.decorators import retry, deprecated, cached


class Logger():
    def __init__(self):
        self.messages = []

    def warn(self, message):
        self.messages.append((logging.WARNING, message))


class TestRetry(TestCase):

    def test_retry_nop(self):
        status = [False]
        _logger = Logger()

        @retry(None, delay=1, backoff=1, logger=_logger)
        def runs_ok():
            status[0] = True
        runs_ok()
        assert(status[0])
        assert(len(_logger.messages) == 0)

    def test_retry_fail(self):
        status = [False]
        _logger = Logger()
        @retry(ValueError, delay=1, backoff=1, logger=_logger)
        def fails():
            raise ValueError("nope")

        try:
            fails()
            assert False
        except ValueError, ex:
            assert(len(_logger.messages) == 3)
            pass
        assert(not status[0])

    def test_retry_fail_stdout(self):
        status = [False]
        @retry(ValueError, delay=1, backoff=1, logger=None)
        def fails():
            raise ValueError("nope")

        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            try:
                fails()
                assert False
            except ValueError, ex:
                assert(len(mock_stdout.getvalue().split("\n")) == 4)
                pass
            assert(not status[0])


class TestDeprecated(TestCase):

    def test_deprecate(self):

        _logger = Logger()

        @deprecated(logger=_logger)
        def test():
            pass

        assert(len(_logger.messages) == 0)
        test()
        assert(len(_logger.messages) == 1)
        assert('Call to deprecated function' in _logger.messages[0][1])
        assert(_logger.messages[0][0] == logging.WARNING)

    def test_deprecate_stdout(self):

        @deprecated(logger=None)
        def old_stuff():
            pass

        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            old_stuff()
            assert('Call to deprecated function' in mock_stdout.getvalue())


class TestCached(TestCase):

    def setUp(self):
        self.counter = 0

    @cached(ttl=3600)  # long enough time for the test to run ... we hope
    def next_counter(self):
        self.counter += 1
        return self.counter

    def test_cached_simple(self):
        assert (self.counter == 0)
        assert (self.next_counter() == 1)
        assert (self.next_counter() == 1)
        assert (self.counter == 1)

    def test_cached_clear(self):
        assert (self.counter == 0)
        assert (self.next_counter() == 1)
        self.next_counter.clear()
        assert (self.counter == 1)
        assert (self.next_counter() == 2)