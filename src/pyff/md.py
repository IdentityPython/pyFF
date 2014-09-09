"""
pyFF is the SAML metadata aggregator

Usage: [-h|--help]
       [-R]
       [--loglevel=<level>]
       [--logfile=<file>]
       [--version]
"""
import sys
import getopt
import traceback
import logging

from .mdrepo import MDRepository
from .pipes import plumbing
from .store import MemoryStore
from . import __version__


def main():
    """
    The main entrypoint for the pyFF cmdline tool.
    """

    opts = None
    args = None
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hR', ['help', 'loglevel=', 'logfile=', 'version'])
    except getopt.error, msg:
        print msg
        print __doc__
        sys.exit(2)

    store = MemoryStore()
    loglevel = logging.WARN
    logfile = None
    for o, a in opts:
        if o in ('-h', '--help'):
            print __doc__
            sys.exit(0)
        elif o in '--loglevel':
            loglevel = getattr(logging, a.upper(), None)
            if not isinstance(loglevel, int):
                raise ValueError('Invalid log level: %s' % loglevel)
        elif o in '--logfile':
            logfile = a
        elif o in '-R':
            from pyff.store import RedisStore
            store = RedisStore()
        elif o in '--version':
            print "pyff version %s" % __version__
            sys.exit(0)

    log_args = {'level': loglevel}
    if logfile is not None:
        log_args['filename'] = logfile
    logging.basicConfig(**log_args)

    try:
        md = MDRepository(store=store)
        for p in args:
            plumbing(p).process(md, state={'batch': True, 'stats': {}})
        sys.exit(0)
    except Exception, ex:
        if logging.getLogger().isEnabledFor(logging.DEBUG):
            print "-" * 64
            traceback.print_exc()
            print "-" * 64
        logging.error(ex)
        sys.exit(-1)


if __name__ == "__main__":
    main()