__author__ = 'leifj'

import logging
import syslog
import six
import os

try:
    import cherrypy
except ImportError as e:
    print("cherrypy logging disabled")
    cherrypy = None


class PyFFLogger(object):
    def __init__(self, name=None):
        if name is None:
            name = __name__
        self._log = logging.getLogger(name)
        self._loggers = {logging.WARN: self._log.warn,
                         logging.WARNING: self._log.warn,
                         logging.CRITICAL: self._log.critical,
                         logging.INFO: self._log.info,
                         logging.DEBUG: self._log.debug,
                         logging.ERROR: self._log.error}

    def _l(self, severity, msg):
        if cherrypy is not None and '' in cherrypy.tree.apps:
            cherrypy.tree.apps[''].log(str(msg), severity=severity)
        elif severity in self._loggers:
            self._loggers[severity](str(msg))
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
        return self._log.isEnabledFor(lvl)


def get_log(name):
    return PyFFLogger(name)


log = get_log('pyff')


def log_config_file(ini):
    if ini is not None:
        import logging.config
        if not os.path.isabs(ini):
            ini = os.path.join(os.getcwd(), ini)
        if not os.path.exists(ini):
            raise ValueError("PYFF_LOGGING={} does not exist".format(ini))
        logging.config.fileConfig(ini)


log_config_file(os.getenv('PYFF_LOGGING', None))

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
