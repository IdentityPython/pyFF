from pyff import MDRepository

__author__ = 'leifj'

import urlparse
import logging
import eventlet
from eventlet.green import urllib2
from StringIO import StringIO

def _fetch(md,url,verify):
    logging.debug("open %s" % url)
    try:
        return (urllib2.urlopen(url).read(),verify)
    except Exception,ex:
        logging.error("%s: %s" % (url,ex))
        return (None,None)

def _load(md,pile,args):
    """
    Recursively spawn _fetch for all URLs. A line on the form file:fn is treated
    as a file of URLs - one per line.
    """
    for d in args:
        url = None
        verify = None
        if type(d) is str or type(d) is unicode:
            lst = d.split()
            d = None
            if len(lst) == 1:
                url = lst[0]
                if url.startswith("file:"):
                    with open(url.split(":")[1]) as fd:
                        _load(md,pile,[line.strip() for line in fd.readlines()])
            elif len(lst) > 1:
                url = lst[0]
                verify = lst[1]
        elif type(d) is dict and d.has_key('url'):
            url = d['url']
            verify = d.get('verify',None)

        if url is not None:
            logging.debug("spawning %s" % url)
            pile.spawn(_fetch,md,url,verify)

def run(md,t,name,args,id):
    pool = eventlet.GreenPool()
    pile = eventlet.GreenPile(pool)
    if type(args) is str or type(args) is unicode:
        args = [args]

    _load(md,pile,args)

    for r,verify in pile:
        if r is not None:
            md.parse_metadata(StringIO(r),verify)