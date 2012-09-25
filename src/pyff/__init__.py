"""
pyFF is a SAML metadata aggregator.
"""

import sys
import getopt
from pyff.mdrepo import  MDRepository
from pyff.pipes import plumbing
import traceback
import logging

def main():
    """
    The main entrypoint for the pyFF cmdline tool.
    """
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'h', ['help', 'loglevel='])
    except getopt.error, msg:
        print msg
        print 'for help use --help'
        sys.exit(2)

    md=MDRepository()
    loglevel = logging.WARN
    logfile = None
    for o, a in opts:
        if o in ('-h', '--help'):
            print __doc__
            sys.exit(0)
        elif o in ('--loglevel'):
            loglevel = getattr(logging, a.upper(), None)
            if not isinstance(loglevel, int):
                raise ValueError('Invalid log level: %s' % loglevel)
        elif o in ('--logfile'):
            logfile = a

    log_args = {'level': loglevel}
    if logfile is not None:
        log_args['filename'] = logfile
    logging.basicConfig(**log_args)

    try:
        for p in args:
            plumbing(p).process(md,state={'batch': True})
        sys.exit(0)
    except Exception,ex:
        if logging.getLogger().isEnabledFor(logging.DEBUG):
            print "-" * 64
            traceback.print_exc()
            print "-" * 64
        logging.error(ex)
        sys.exit(-1)

if __name__ == "__main__":
    main()