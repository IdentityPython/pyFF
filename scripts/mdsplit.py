"""
pyffsplit creates pipeline files for each EntityDescriptor in an aggregate, which then used to
create separate signed XML documents with an EntitiyDescriptor each.
TODO: Signing in the same process
"""
import argparse
import future
import logging
import lxml.etree as etree
import os
import re
import sys

import pyff
from pyff.mdrepo import MDRepository
from pyff.pipes import plumbing
from pyff.store import MemoryStore


class Pipeline:
    def __init__(self, keyfile, certfile, idprefix, cacheDuration, validUntil):
        self.keyfile = keyfile
        self.certfile = certfile
        self.idprefix = idprefix
        self.cacheDuration = cacheDuration
        self.validUntil = validUntil

    def get(self, infile, outfile):
        # sign a single entity descriptor
        pipeline = '''- load:
  - {0}
- select
- finalize:
    Name: {4}
    cacheDuration: {5}
    validUntil: {6}
- sign:
    key:  {2}
    cert: {3}
- publish:
    {1}
'''.format(infile,
           outfile,
           self.keyfile,
           self.certfile,
           self.idprefix,
           self.cacheDuration,
           self.validUntil)
        return pipeline

def entityid_to_filename(entityid):
    """
    Derive a filename from an entityID, removing dots and slashes
    :param entityid:
    :return: filename derived from entityID
    """
    x = re.sub(r'^https?://', '', entityid)
    r = ''
    upper = False

    in_path = False
    for i in range(0, len(x)):
        if x[i].isalpha() or x[i].isdigit():
            if upper:
                r += x[i].upper()
            else:
                r += x[i]
            upper = False
        elif not in_path and x[i] == '/':
            r += '_'
            in_path = True
        else:
            upper = True
    return r + '.xml'

# def simple_md(pipeline):
#     """ stupid copy of md:main -> replace this """
#     modules = []
#     modules.append('pyff.builtins')
#     store = MemoryStore()
#     md = MDRepository(store=store)
#     plumbing(pipeline).process(md, state={'batch': True, 'stats': {}})


def main():
    LOGLEVELS = {'CRITICAL': 50, 'ERROR': 40, 'WARNING': 30, 'INFO': 20, 'DEBUG': 10}
    XMLDECLARATION = '<?xml version="1.0" ?>'
    parser = argparse.ArgumentParser(description='Metadata Splitter')
    parser.add_argument('-c', '--certfile', dest='certfile', default='pyff_sign-cer.pem')
    parser.add_argument('-k', '--keyfile', dest='keyfile', default='pyff_sign-key.pem')
    parser.add_argument('-i', '--idprefix', dest='idprefix', default='ourfederation.example.com_')
    parser.add_argument('-C', '--cacheduration', dest='cacheduration', default='PT5H')
    parser.add_argument('-l', '--logfile', dest='logfile', default='pyffsplit.log')
    parser.add_argument('-L', '--loglevel', dest='loglevel', default='INFO', choices=LOGLEVELS.keys())
    parser.add_argument('-u', '--validuntil', dest='validuntil', default='P10D')
    parser.add_argument('input', type=argparse.FileType('r'), default=None,
             help='Metadata aggregate')
    parser.add_argument('outdir_unsigned', default=None)
    parser.add_argument('outdir_signed', default=None,
             help='Directory for files containing one EntityDescriptor each.')
    args = parser.parse_args()

    log_args = {'level': LOGLEVELS[args.loglevel]}
    log_args['filename'] = args.logfile
    logging.basicConfig(**log_args)
    logging.debug('Input file is ' + args.input.name)
    logging.debug('Input directory is ' + args.outdir_signed)

    root = etree.parse(args.input).getroot()
    if root.tag != '{urn:oasis:names:tc:SAML:2.0:metadata}EntitiesDescriptor':
        raise Exception('Root element must be EntitiesDescriptor')
    logging.debug('Root element is ' + root.tag)
    pipeline = Pipeline(args.keyfile, args.certfile,
                        args.idprefix, args.cacheduration, args.validuntil)
    for e in root.findall('{urn:oasis:names:tc:SAML:2.0:metadata}EntityDescriptor'):
        fn_temp = os.path.abspath(os.path.join(args.outdir_unsigned, entityid_to_filename(e.attrib['entityID'])))
        fn_out = os.path.abspath(os.path.join(args.outdir_signed, entityid_to_filename(e.attrib['entityID'])))
        logging.debug('writing unsigned EntitiyDescriptor ' + e.attrib['entityID'] + ' to ' + fn_temp)
        if not os.path.exists(os.path.dirname(fn_temp)):
            os.makedirs(os.path.dirname(fn_temp))
        with open(fn_temp, 'w') as f:
            f.write(XMLDECLARATION + etree.tostring(e))
        fn_pipeline = fn_temp + '.fd'
        with open(fn_pipeline, 'w') as f_pipeline:
            f_pipeline.write(pipeline.get(fn_temp, fn_out))
        #simple_md(fn_pipeline)


if __name__ == "__main__":  # pragma: no cover
    #print os.getcwd()
    main()