from __future__ import print_function

"""
pyFF is the SAML metadata aggregator

Usage: [-h|--help]
       [-R]
       [--loglevel=<level>]
       [--logfile=<file>]
       [--version]
"""
import getopt
import importlib
import logging
import sys
import traceback

from . import __version__
from .mdrepo import MDRepository
from .pipes import plumbing
from .store import MemoryStore
from .constants import config


def main():
    """
    The main entrypoint for the pyFF cmdline tool.
    """

    opts = None
    args = None
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hRm', ['help', 'loglevel=', 'logfile=', 'version', 'module'])
    except getopt.error as msg:
        print(msg)
        print(__doc__)
        sys.exit(2)

    if config.store is None:
        config.store = MemoryStore()

    if config.loglevel is None:
        config.loglevel = logging.WARN

    if config.modules is None:
        config.modules = []

    for o, a in opts:
        if o in ('-h', '--help'):
            print(__doc__)
            sys.exit(0)
        elif o in '--loglevel':
            config.loglevel = getattr(logging, a.upper(), None)
            if not isinstance(config.loglevel, int):
                raise ValueError('Invalid log level: %s' % a)
        elif o in '--logfile':
            config.logfile = a
        elif o in '-R':
            from pyff.store import RedisStore
            config.store = RedisStore()
        elif o in ('-m', '--module'):
            config.modules.append(a)
        elif o in '--version':
            print("pyff version {}".format(__version__))
            sys.exit(0)

    log_args = {'level': config.loglevel}
    if config.logfile is not None:
        log_args['filename'] = config.logfile
    logging.basicConfig(**log_args)

    config.modules.append('pyff.builtins')
    for mn in config.modules:
        importlib.import_module(mn)

    try:
        md = MDRepository(store=config.store)
        for p in args:
            plumbing(p).process(md, state={'batch': True, 'stats': {}})
        sys.exit(0)
    except Exception as ex:
        if logging.getLogger().isEnabledFor(logging.DEBUG):
            traceback.print_exc()
        logging.error(ex)
        sys.exit(-1)


if __name__ == "__main__":  # pragma: no cover
    main()
