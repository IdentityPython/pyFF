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
    -m <module>|--modules=<module>
            Load a module

    {pipeline-files}+
            One or more pipeline files

"""

from __future__ import unicode_literals
from .constants import config, parse_options
from .logs import get_log
import importlib
import logging
import os
import gunicorn.app.base
from six import iteritems
from .api import mkapp
from .repo import MDRepository
import sys

log = get_log(__name__)


class MDQApplication(gunicorn.app.base.BaseApplication):

    def init(self, parser, opts, args):
        super().init(self, parser, opts, args)

    def __init__(self, options=None):
        self.options = options or {}
        super(MDQApplication, self).__init__()

    def load_config(self):
        cfg = dict([(key, value) for key, value in iteritems(self.options) if key in self.cfg.settings and value is not None])
        for key, value in iteritems(cfg):
            self.cfg.set(key.lower(), value)

    def load(self):
        return mkapp(config.pipeline, md=MDRepository())


def main():
    """
    The (new) main entrypoint for the pyffd command.
    """
    args = parse_options("pyffd",
                         __doc__,
                         'hP:p:H:CfaA:l:Rm:',
                         ['help', 'loglevel=', 'log=', 'access-log=', 'error-log=', 'logger=',
                          'port=', 'host=', 'bind_address=', 'no-caching', 'autoreload', 'frequency=', 'module=',
                          'alias=', 'dir=', 'version', 'proxy', 'allow_shutdown'])

    if config.base_dir:
        os.chdir(config.base_dir)

    options = {
        'bind': '{}:{}'.format(config.host, config.port),
        'workers': config.worker_pool_size,
        'loglevel': logging.getLevelName(config.loglevel).lower(),
        'preload_app': True,
        'daemon': config.daemonize,
        'capture_output': False,
        'timeout': config.worker_timeout,
        'worker_class': 'gthread',
        'worker_tmp_dir': '/dev/shm',
        'threads': config.threads
    }

    if config.pid_file:
        options['pidfile'] = config.pid_file

    if args:
        config.pipeline = args[0]

    loglevel_str = logging.getLevelName(config.loglevel).upper()

    if config.logger:
        options['logconfig'] = config.logger
    else:
        options['logconfig_dict'] = {
            'version': 1,
            'formatters': {
                'default': {
                    'format': '%(asctime)s %(levelname)s %(name)s %(message)s',
                    'datefmt': '%Y-%m-%d %H:%M:%S'
                }
            },
            'filters': {

            },
            'loggers': {
                'root': {
                    'handlers': ['console'],
                    'level': loglevel_str
                },
                'pyff': {
                    'handlers': ['console'],
                    'propagate': False,
                    'level': loglevel_str
                }
            },
            'handlers': {
                'console': {
                    'class': 'logging.StreamHandler',
                    'formatter': 'default',
                    'level': loglevel_str,
                    'stream': 'ext://sys.stderr'
                }
            }
        }

    if config.aliases is not None:
        config.aliases['metadata'] = 'entities'

    MDQApplication(options).run()


if __name__ == "__main__":
    main()
