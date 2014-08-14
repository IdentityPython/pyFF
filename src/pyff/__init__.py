"""
pyFF is a SAML metadata aggregator.
"""
from os import environ

import sys
import getopt
import pkg_resources
from pyff.mdrepo import MDRepository
from pyff.pipes import plumbing
import traceback
import logging
from pyff.store import MemoryStore, RedisStore

__version__ = pkg_resources.require("pyFF")[0].version


def interact(**kwargs):
    import code

    v = dict()
    v.update(globals())
    v.update(**kwargs)
    code.InteractiveConsole(locals=v).interact()


def main():
    """
    The main entrypoint for the pyFF cmdline tool.
    """
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hR', ['help', 'loglevel=', 'logfile=', 'version'])
    except getopt.error, msg:
        print msg
        print 'for help use --help'
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
            store = RedisStore()
        elif o in '--version':
            print "pyff version %s" % __version__
            sys.exit(0)
        else:
            raise ValueError("Unknown option '%s'" % o)

    hp = None
    if environ.get('MEMORY_DEBUG', None) is not None:
        try:
            from guppy import hpy
            hp = hpy()
            hp.setrelheap()
        except ImportError:
            pass

    md = MDRepository(store=store)

    log_args = {'level': loglevel}
    if logfile is not None:
        log_args['filename'] = logfile
    logging.basicConfig(**log_args)

    try:
        for p in args:
            plumbing(p).process(md, state={'batch': True, 'stats': {}})
        if hp is not None:
            h = hp.heap()
            interact(h=h, hp=hp, store=store, md=md)
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
