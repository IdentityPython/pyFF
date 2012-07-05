import sys
import getopt
from pyff.mdrepo import  MDRepository
from pyff.pipes import plumbing

def main():
    """
    The main entrypoint for pyFF
    """
    try:
        opts, args = getopt.getopt(sys.argv[1:], "h", ["help"])
    except getopt.error, msg:
        print msg
        print "for help use --help"
        sys.exit(2)

    md=MDRepository()
    for o, a in opts:
        if o in ("-h", "--help"):
            print __doc__
            sys.exit(0)

    for p in args:
        plumbing(p).process(md)

if __name__ == "__main__":
    main()