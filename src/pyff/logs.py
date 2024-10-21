__author__ = 'leifj'

import logging
import os
import syslog
from typing import Any, Optional

import six


class PyFFLogger(object):
    def __init__(self, name=None):
        if name is None:
            name = __name__
        self._log = logging.getLogger(name)
        self._loggers = {
            logging.WARN: self._log.warning,
            logging.WARNING: self._log.warning,
            logging.CRITICAL: self._log.critical,
            logging.INFO: self._log.info,
            logging.DEBUG: self._log.debug,
            logging.ERROR: self._log.error,
        }

    def _l(self, severity, msg):
        if severity in self._loggers:
            self._loggers[severity](str(msg))
        else:
            raise ValueError("unknown severity %s" % severity)

    def warn(self, msg: str) -> Any:
        return self._l(logging.WARN, msg)

    def warning(self, msg: str) -> Any:
        return self._l(logging.WARN, msg)

    def info(self, msg: str) -> Any:
        return self._l(logging.INFO, msg)

    def error(self, msg: str) -> Any:
        return self._l(logging.ERROR, msg)

    def critical(self, msg: str) -> Any:
        return self._l(logging.CRITICAL, msg)

    def debug(self, msg: str) -> Any:
        return self._l(logging.DEBUG, msg)

    def isEnabledFor(self, lvl: Any) -> bool:
        return self._log.isEnabledFor(lvl)


def get_log(name: str) -> PyFFLogger:
    return PyFFLogger(name)


log = get_log('pyff')


def log_config_file(ini: Optional[str]) -> None:
    if ini is not None:
        import logging.config

        if not os.path.isabs(ini):
            ini = os.path.join(os.getcwd(), ini)
        if not os.path.exists(ini):
            raise ValueError("PYFF_LOGGING={} does not exist".format(ini))
        logging.config.fileConfig(ini)


log_config_file(os.getenv('PYFF_LOGGING'))

# http://www.aminus.org/blogs/index.php/2008/07/03/writing-high-efficiency-large-python-sys-1?blog=2
# blog post explicitly gives permission for use


class SysLogLibHandler(logging.Handler):
    """A logging handler that emits messages to syslog.syslog."""

    priority_map = {
        10: syslog.LOG_NOTICE,
        20: syslog.LOG_NOTICE,
        30: syslog.LOG_WARNING,
        40: syslog.LOG_ERR,
        50: syslog.LOG_CRIT,
        0: syslog.LOG_NOTICE,
    }

    def __init__(self, facility):

        if isinstance(facility, six.string_types):
            nf = getattr(syslog, "LOG_%s" % facility.upper(), None)
            if not isinstance(nf, int):
                raise ValueError('Invalid log facility: %s' % nf)
            self.facility = nf
        else:
            self.facility = facility
        logging.Handler.__init__(self)

    def emit(self, record):
        syslog.syslog(self.facility | self.priority_map[record.levelno], self.format(record))
