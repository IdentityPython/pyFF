"""
samldiff

Usage: [-h|--help]
       [--loglevel=<level>]
       [--version]
       [uri1] [uri2]
"""
import logging
import sys
import traceback
from .samlmd import diff, iter_entities
from .store import MemoryStore
from .resource import Resource
from .constants import config, parse_options
from xmldiff.main import diff_trees
from xmldiff.formatting import DiffFormatter


def difftool():
    """
    diff two saml metadata sources
    """
    args = parse_options("samldiff", __doc__, 'hv', ['help', 'loglevel=', 'version'])
    log_args = {'level': config.loglevel}
    if config.logfile is not None:
        log_args['filename'] = config.logfile
    logging.basicConfig(**log_args)

    try:
        rm = Resource()
        r1 = Resource(args[0])
        r2 = Resource(args[1])
        rm.add(r1)
        rm.add(r2)
        store = MemoryStore()
        rm.reload(store=store)
        status = 0

        if r1.t.get('Name') != r2.t.get('Name'):
            status += 1
            print("Name differs: {} != {}".format(r1.t.get('Name'), r2.t.get('Name')))

        d1 = diff(r1.t, r2.t)
        if d1:
            print("Only in {}".format(r1.url))
            print("\n+".join(d1))
            status += 2

        d2 = diff(r2.t, r1.t)
        if d2:
            print("Only in {}".format(r2.url))
            print("\n+".join(d2))
            status += 4

        s1 = dict()
        s2 = dict()
        for e1 in iter_entities(r1.t):
            s1[e1.get('entityID')] = e1
        for e2 in iter_entities(r2.t):
            s2[e2.get('entityID')] = e2
        formatter = DiffFormatter()
        for eid in set(s1.keys()).intersection(s2.keys()):
            d = diff_trees(s1[eid],
                           s2[eid],
                           formatter=formatter,
                           diff_options=dict(uniqueattrs=["{urn:oasis:names:tc:SAML:2.0:metadata}entityID"]))
            if d:
                status += 8
                print(d)
        sys.exit(status)
    except Exception as ex:
        logging.debug(traceback.format_exc())
        logging.error(ex)
        sys.exit(-1)

