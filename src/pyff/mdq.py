"""
pyFFd is the SAML metadata aggregator daemon

"""

from __future__ import unicode_literals

import os

import gunicorn.app.base
from six import iteritems

from pyff.api import mkapp
from pyff.constants import config, parse_options
from pyff.logs import get_log
from pyff.repo import MDRepository

log = get_log(__name__)


class MDQApplication(gunicorn.app.base.BaseApplication):
    def init(self, parser, opts, args):
        super().init(self, parser, opts, args)

    def __init__(self, options=None):
        self.options = options or {}
        super(MDQApplication, self).__init__()

    def load_config(self):
        cfg = dict(
            [(key, value) for key, value in iteritems(self.options) if key in self.cfg.settings and value is not None]
        )
        for key, value in iteritems(cfg):
            self.cfg.set(key.lower(), value)

    def load(self):
        return mkapp(config.pipeline, md=MDRepository())


def main():
    """
    The (new) main entrypoint for the pyffd command.
    """
    args = parse_options("pyffd", __doc__)

    if config.base_dir:
        os.chdir(config.base_dir)

    options = {
        'bind': '{}:{}'.format(config.host, config.port),
        'workers': config.worker_pool_size,
        'loglevel': config.loglevel,
        'preload_app': True,
        'daemon': config.daemonize,
        'capture_output': False,
        'timeout': config.worker_timeout,
        'worker_class': 'gthread',
        'worker_tmp_dir': '/dev/shm',
        'threads': config.threads,
    }

    if config.pid_file:
        options['pidfile'] = config.pid_file

    if args:
        config.pipeline = args[0]

    if config.logger:
        options['logconfig'] = config.logger
    else:
        options['logconfig_dict'] = {
            'version': 1,
            'formatters': {
                'default': {'format': '%(asctime)s %(levelname)s %(name)s %(message)s', 'datefmt': '%Y-%m-%d %H:%M:%S'}
            },
            'filters': {},
            'loggers': {
                'root': {'handlers': ['console'], 'level': config.loglevel},
                'pyff': {'handlers': ['console'], 'propagate': False, 'level': config.loglevel},
            },
            'handlers': {
                'console': {
                    'class': 'logging.StreamHandler',
                    'formatter': 'default',
                    'level': config.loglevel,
                    'stream': 'ext://sys.stderr',
                }
            },
        }

    if config.aliases is not None:
        config.aliases['metadata'] = 'entities'

    MDQApplication(options).run()


if __name__ == "__main__":
    main()
