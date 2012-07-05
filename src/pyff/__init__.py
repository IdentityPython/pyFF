import sys
import getopt
import os
from pyff.mdrepo import  MDRepository
from pyff.pipes import loader, plumbing

def process_old(fn,md):
    """
    Load a feed and process it
    """
    feed = import_feed(fn)
    name = feed.get('Name',fn)

    for u in feed.get('inputs',[]):
        if type(u) is dict:
            url = u.get('url',None)
            if url is not None and (url.startswith("http://") or url.startswith("https:") or url.startswith("ftp://")):
                md.load_url(url,md,verify=u.get('verify',None))
            else:
                raise Exception,"Unknown metadata input format: %s" % u
        elif os.path.isdir(u):
            md.load_dir(u,md)
        else:
            raise Exception,"Unknown metadata input: %s" % u

    t = md.entity_set(md,feed.get('entities',md.keys()),name,feed.get('cacheDuration',None),feed.get('validUntil',None))
    for ts in feed.get('pipeline',[]):
        pipe = loader.load_pipe(ts)
        ot = pipe.run(ts,t,feed=feed,name=name)
        if ts.get('break',False):
            break
        t = ot
    md[name] = t

def main():
    # parse command line options
    try:
        opts, args = getopt.getopt(sys.argv[1:], "h", ["help"])
    except getopt.error, msg:
        print msg
        print "for help use --help"
        sys.exit(2)
    # process options

    md=MDRepository()
    for o, a in opts:
        if o in ("-h", "--help"):
            print __doc__
            sys.exit(0)

    # process arguments

    for p in args:
        plumbing(p).process(md)

if __name__ == "__main__":
    main()