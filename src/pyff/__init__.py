"""
pyFF is a SAML metadata aggregator. The processing model is a pipeline:

        -----------------                                       -----------------
        |               |                                       |               |
        |     remote    |                                       |    publish    |
        |               |                                       |               |
        -----------------                                       -----------------
                |                                                       ^
                |                                                       |
                |                                                       |
                |                 pyFF processing chaing                |
                |                                                       |
                |                                                       |
                |                                                       |
        -----------------           -----------------           -----------------
        |               |           |               |           |               |
        |    select     | --------> |     xslt      | --------> |     fork      |
        |               |           |               |           |               |
        -----------------           -----------------           -----------------

pyFF pipelines are represented using python objects and serialized as yaml files.

An example pipeline:

        - remote:
            - https://mds.edugain.org edugain.crt
        - select "/tmp/edugain!md:EntityDescriptor[md:IDPSSODescriptor]"
        - store:
            directory: /var/spool/edugain
        - certreport
        - publish:
            output: /tmp/edugain-annotated.xml

This pipline...

 - downloads the edugain metadata and validates the signature
 - selects the IdPs
 - splits the IdPs into EntityDescriptor pieces and saves each in a separate file
 - annotates metadata with certificate expiration information
 - saves the annotated metadata as a combined file

"""

import sys
import getopt
from pyff.mdrepo import  MDRepository
from pyff.pipes import plumbing
import logging
import traceback

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

    try:
        for p in args:
            plumbing(p).process(md)
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