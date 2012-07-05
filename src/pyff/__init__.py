import sys
import getopt
from pyff.mdrepo import  MDRepository
from pyff.pipes import plumbing
import logging

def main():
    """
    The main entrypoint for pyFF
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

    for p in args:
        plumbing(p).process(md)

if __name__ == "__main__":
    main()