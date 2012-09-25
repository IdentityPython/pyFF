__author__ = 'leifj'

import cherrypy
import logging

class PyFFLogger():

    def __init__(self):
        print repr(logging)
        self._loggers = {logging.WARN: logging.warn,
                        logging.WARNING: logging.warn,
                        logging.CRITICAL: logging.critical,
                        logging.INFO: logging.info,
                        logging.DEBUG: logging.debug,
                        logging.ERROR: logging.error}

    def _l(self,severity,msg):
        if cherrypy.tree.apps.has_key(''):
            cherrypy.tree.apps[''].log("%s" % msg,severity=severity)
        else:
            self._loggers[severity]("%s" % msg)

    def warn(self,msg):
        return self._l(logging.WARN,msg)

    def info(self,msg):
        return self._l(logging.INFO,msg)

    def error(self,msg):
        return self._l(logging.ERROR,msg)

    def critical(self,msg):
        return self._l(logging.CRITICAL,msg)

    def debug(self,msg):
        return self._l(logging.DEBUG,msg)

log = PyFFLogger()