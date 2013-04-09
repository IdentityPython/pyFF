__author__ = 'leifj'

import cherrypy
import syslog
import logging


class PyFFLogger():
    def __init__(self):
        self._loggers = {logging.WARN: logging.warn,
                         logging.WARNING: logging.warn,
                         logging.CRITICAL: logging.critical,
                         logging.INFO: logging.info,
                         logging.DEBUG: logging.debug,
                         logging.ERROR: logging.error}

    def _l(self, severity, msg):
        if cherrypy.tree.apps.has_key(''):
            cherrypy.tree.apps[''].log("%s" % msg, severity=severity)
        else:
            self._loggers[severity]("%s" % msg)

    def warn(self, msg):
        return self._l(logging.WARN, msg)

    def info(self, msg):
        return self._l(logging.INFO, msg)

    def error(self, msg):
        return self._l(logging.ERROR, msg)

    def critical(self, msg):
        return self._l(logging.CRITICAL, msg)

    def debug(self, msg):
        return self._l(logging.DEBUG, msg)


log = PyFFLogger()

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

        if type(facility) is str or type(facility) is unicode:
            nf = getattr(syslog, "LOG_%s" % facility.upper(), None)
            if not isinstance(nf, int):
                raise ValueError('Invalid log level: %s' % nf)
            self.facility = nf
        else:
            self.facility = facility
        logging.Handler.__init__(self)

    def emit(self, record):
        syslog.syslog(self.facility | self.priority_map[record.levelno], self.format(record))