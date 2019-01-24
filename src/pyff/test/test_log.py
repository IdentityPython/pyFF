

import logging
from six import StringIO
from unittest import TestCase
from mock import patch
from pyff.logs import log, SysLogLibHandler


class TestLog(TestCase):

    def test_log_plain(self):
        try:
            logfile = StringIO()
            logger = logging.getLogger()
            old_handlers = []
            for hdl in logger.handlers:
                logger.removeHandler(hdl)
                old_handlers.append(hdl)
            test_handler = logging.StreamHandler(logfile)
            logger.addHandler(test_handler)
            logger.setLevel(logging.WARNING)

            log.info("info")
            log.warn("warn")
            log.warning("warning")
            log.error("error")
            log.critical("critical")
            log.debug("debug")

            lines = logfile.getvalue().split("\n")

            assert("info" not in lines)
            assert("warn" in lines)
            assert("warning" in lines)
            assert("critical" in lines)
            assert("error" in lines)
            assert("debug" not in lines)
        finally:
            logger.removeHandler(test_handler)
            for hdl in old_handlers:
                logger.addHandler(hdl)


class TestSyslog(TestCase):

    def setUp(self):
        self._syslog = StringIO()

    def dummy_syslog(self, code, msg):
        self._syslog.write("%d:%s\n" % (code, msg))

    def test_bad_syslog(self):
        try:
            bad_handler = SysLogLibHandler("SLARTIBARTIFAST")
            assert False
        except ValueError:
            pass

    def test_kern_syslog(self):
        kern = SysLogLibHandler(0)
        assert (kern is not None)
        assert (isinstance(kern, SysLogLibHandler))

    def test_log_syslog(self):
        with patch('syslog.syslog', new=self.dummy_syslog):
            try:
                logger = logging.getLogger()
                old_handlers = []
                for hdl in logger.handlers:
                    logger.removeHandler(hdl)
                    old_handlers.append(hdl)
                test_handler = SysLogLibHandler("USER")
                logger.addHandler(test_handler)
                logger.setLevel(logging.WARNING)

                log.info("info")
                log.warn("warn")
                log.warning("warning")
                log.error("error")
                log.critical("critical")
                log.debug("debug")

                lines = self._syslog.getvalue().split("\n")

                assert("info" not in lines)
                assert("12:warn" in lines)
                assert("12:warning" in lines)
                assert("10:critical" in lines)
                assert("11:error" in lines)
                assert("debug" not in lines)
            finally:
                logger.removeHandler(test_handler)
                for hdl in old_handlers:
                    logger.addHandler(hdl)
