"""
An implementation of draft-lajoie-md-query

.. code-block:: bash

    Usage: pyffd <options> {pipeline-files}+

    -C|--no-caching
            Turn off caching
    -p <pidfile>
            Write a pidfile at the specified location
    -f
            Run in foreground
    -a
            Restart pyffd if any of the pipeline files change
    --log=<log> | -l<log>
            Set to either a file or syslog:<facility> (eg syslog:auth)
    --error-log=<log> | --access-log=<log>
            As --log but only affects the error or access log streams.
    --loglevel=<level>
            Set logging level
    -P<port>|--port=<port>
            Listen on the specified port
    -H<host>|--host=<host>
            Listen on the specified interface
    --frequency=<seconds>
            Wake up every <seconds> and run the update pipeline. By
            default the frequency is set to 600.
    -A<name:uri>|--alias=<name:uri>
            Add the mapping 'name: uri' to the toplevel URL alias
            table. This causes URLs on the form http://server/<name>/x
            to be processed as http://server/metadata/{uri}x. The
            default alias table is presented at http://server
    --dir=<dir>
            Chdir into <dir> after the server starts up.
    --proxy
            The service is running behind a proxy - respect the X-Forwarded-Host header.
    -m <module>|--modules=<module>
            Load a module

    {pipeline-files}+
            One or more pipeline files

"""

from __future__ import unicode_literals
from .constants import config, parse_options
from .logs import get_log
import importlib
import os
import gunicorn.app.base
from gunicorn.six import iteritems
from .wsgi import app
import multiprocessing

log = get_log(__name__)


class MDQApplication(gunicorn.app.base.BaseApplication):

    def init(self, parser, opts, args):
        super().init(self, parser, opts, args)

    def __init__(self, app, options=None):
        self.options = options or {}
        self.application = app
        super(MDQApplication, self).__init__()

    def load_config(self):
        cfg = dict([(key, value) for key, value in iteritems(self.options)
                    if key in self.cfg.settings and value is not None])
        for key, value in iteritems(cfg):
            self.cfg.set(key.lower(), value)

    def load(self):
        return self.application


def number_of_workers(cfg):
    return cfg.worker_pool_size or (multiprocessing.cpu_count() * 2) + 1


def main():
    """
    The (new) main entrypoint for the pyffd command.
    """
    args = parse_options("pyffd",
                         __doc__,
                         'hP:p:H:CfaA:l:Rm:',
                         ['help', 'loglevel=', 'log=', 'access-log=', 'error-log=',
                          'port=', 'host=', 'no-caching', 'autoreload', 'frequency=', 'module=',
                          'alias=', 'dir=', 'version', 'proxy', 'allow_shutdown'])

    for p in ('allow_shutdown', 'alias', 'proxy'):
        if getattr(config,p):
            log.warn("--{} has been deprecated and will be removed in the future".format(p))

    if config.base_dir:
        os.chdir(config.base_dir)

    config.modules.append('pyff.builtins')
    for mn in config.modules:
        importlib.import_module(mn)

    options = {
        'bind': '{}:{}'.format(config.host, config.port),
        'workers': number_of_workers(config),
        'loglevel': config.loglevel
    }

    error_facility = None
    if config.error_log is not None:
        if config.error_log.startswith('syslog:'):
            error_facility = config.error_log[7:]
            options['syslog_facility'] = error_facility
            options['syslog'] = True
        else:
            options['errorlog'] = config.error_log

    access_facility = None
    if config.access_log is not None:
        if config.access_log.startswith('syslog:'):
            access_facility = config.access_log[7:]
            options['syslog_facility'] = access_facility
            options['syslog'] = True
        else:
            if error_facility is not None:
                options['disable_redirect_access_to_syslog'] = True
            options['accesslog'] = config.access_log

    if access_facility != error_facility:
        log.warn("access log and error log syslog facility have to match for gunicorn")

    if config.pid_file:
        options['pidfile'] = config.pid_file

    if args:
        config.pipeline = args[0]

    MDQApplication(app, options).run()


if __name__ == "__main__":
    main()
