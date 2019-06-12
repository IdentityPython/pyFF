import logging
from six import StringIO
from unittest import TestCase
from mock import patch

from pyff.decorators import deprecated


class Logger():
    def __init__(self):
        self.messages = []

    def warn(self, message):
        self.messages.append((logging.WARNING, message))


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
