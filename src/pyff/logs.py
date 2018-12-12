__author__ = 'leifj'

import logging
import syslog
try:
    import cherrypy
except Exception as e:
    print("cherrypy logging disabled")
    cherrypy = None


def printable(s):
    if isinstance(s, unicode):
        return s.encode('utf8', errors='ignore').decode('utf8')
    elif isinstance(s, str):
        return s.decode("utf8", errors="ignore").encode('utf8')
    else:
        return repr(s)


class PyFFLogger(object):
    def __init__(self):
        self._loggers = {logging.WARN: logging.warn,
                         logging.WARNING: logging.warn,
                         logging.CRITICAL: logging.critical,
                         logging.INFO: logging.info,
                         logging.DEBUG: logging.debug,
                         logging.ERROR: logging.error}

    def _l(self, severity, msg):
        if cherrypy is not None and '' in cherrypy.tree.apps:
            cherrypy.tree.apps[''].log(printable(msg), severity=severity)
        elif severity in self._loggers:
            self._loggers[severity](printable(msg))
        else:
            raise ValueError("unknown severity %s" % severity)

    def warn(self, msg):
        return self._l(logging.WARN, msg)

    def warning(self, msg):
        return self._l(logging.WARN, msg)

    def info(self, msg):
        return self._l(logging.INFO, msg)

    def error(self, msg):
        return self._l(logging.ERROR, msg)

    def critical(self, msg):
        return self._l(logging.CRITICAL, msg)

    def debug(self, msg):
        return self._l(logging.DEBUG, msg)

    def isEnabledFor(self, lvl):
        return logging.getLogger(__name__).isEnabledFor(lvl)


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
                raise ValueError('Invalid log facility: %s' % nf)
            self.facility = nf
        else:
            self.facility = facility
        logging.Handler.__init__(self)

    def emit(self, record):
        syslog.syslog(self.facility | self.priority_map[record.levelno], self.format(record))
