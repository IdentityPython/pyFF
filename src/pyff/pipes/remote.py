from pyff import MDRepository

__author__ = 'leifj'

import urlparse
import logging
import eventlet
from eventlet.green import urllib2
from StringIO import StringIO

def _fetch(md,url,verify):
    logging.debug("open %s" % url)
    return (urllib2.urlopen(url).read(),verify)

def run(md,t,name,args,id):
    pool = eventlet.GreenPool()
    pile = eventlet.GreenPile(pool)
    for d in args:
        url = None
        verify = None
        if type(d) is str or type(d) is unicode:
            lst = d.split()
            d = None
            if len(lst) == 1:
                url = lst[0]
            elif len(lst) > 1:
                url = lst[0]
                verify = lst[1]
        elif type(d) is dict and d.has_key('url'):
            url = d['url']
            verify = d.get('verify',None)

        if url is not None:
            logging.debug("spawning %s" % url)
            pile.spawn(_fetch,md,url,verify)

    for r,verify in pile:
        md.parse_metadata(StringIO(r),verify)