import logging
from unittest import TestCase
from pyff.decorators import retry, deprecated


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


class TestDeprecated(TestCase):
    def test_deprecate(self):

        class Logger():
            def __init__(self):
                self.messages = []

            def warn(self, message):
                self.messages.append((logging.WARNING, message))

        _logger = Logger()

        @deprecated(logger=_logger)
        def test():
            pass

        assert(len(_logger.messages) == 0)
        test()
        assert(len(_logger.messages) == 1)
        assert('Call to deprecated function' in _logger.messages[0][1])
        assert(_logger.messages[0][0] == logging.WARNING)