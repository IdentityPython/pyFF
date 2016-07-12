"""
pyffsplit creates pipeline files for each EntityDescriptor in an aggregate, which then used to
create separate signed XML documents with an EntitiyDescriptor each.
The input file is considered to be trusted, the signature is not verified.
TODO: Signing in the same process
"""

import logging
import lxml.etree as etree
import os
import re
import sys

from pyff.mdrepo import MDRepository
from pyff.pipes import plumbing
from pyff.store import MemoryStore

XMLDECLARATION = '<?xml version="1.0" ?>'


class Pipeline:
    def __init__(self, keyfile, certfile, cacheDuration, validUntil):
        self.keyfile = keyfile
        self.certfile = certfile
        self.cacheDuration = cacheDuration
        self.validUntil = validUntil

    def get(self, infile, outfile):
        # sign a single entity descriptor
        pipeline = '''- load:
  - {0}
- select
- finalize:
    cacheDuration: {4}
    validUntil: {5}
- sign:
    key:  {2}
    cert: {3}
- publish:
    {1}
'''.format(infile,
           outfile,
           self.keyfile,
           self.certfile,
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


def simple_md(pipeline):
    """ just a copy of md:main """
    modules = []
    modules.append('pyff.builtins')
    store = MemoryStore()
    md = MDRepository(store=store)
    plumbing(pipeline).process(md, state={'batch': True, 'stats': {}})


def process_entity_descriptor(ed, pipeline, args):
    fn_temp = os.path.abspath(os.path.join(args.outdir_unsigned,
                                           entityid_to_filename(ed.attrib['entityID'])))
    logging.debug('writing unsigned EntitiyDescriptor ' + ed.attrib['entityID'] + ' to ' + fn_temp)
    if args.cacheDuration is not None:
        ed.attrib['cacheDuration'] = args.cacheDuration
    if args.validUntil is not None:
        ed.attrib['validUntil'] = args.validUntil
    if not os.path.exists(os.path.dirname(fn_temp)):
        os.makedirs(os.path.dirname(fn_temp))
    with open(fn_temp, 'w') as f:
        f.write(XMLDECLARATION + '\n' + etree.tostring(ed))
    if not args.nosign:
        fn_out = os.path.abspath(os.path.join(args.outdir_signed,
                                              entityid_to_filename(ed.attrib['entityID'])))
        fn_pipeline = fn_temp + '.fd'
        with open(fn_pipeline, 'w') as f_pipeline:
            f_pipeline.write(pipeline.get(fn_temp, fn_out))
        simple_md(fn_pipeline)


def process_md_aggregate(args):
    """ process each ed; take validUntil and cacheDuration from root level """
    root = etree.parse(args.input).getroot()
    if root.tag != '{urn:oasis:names:tc:SAML:2.0:metadata}EntitiesDescriptor':
        raise Exception('Root element must be EntitiesDescriptor')
    if 'cacheDuration' in root.attrib and args.cacheDuration is None:
        args.cacheDuration = root.attrib['cacheDuration']
    if 'validUntil' in root.attrib and args.validUntil is None:
        args.validUntil = root.attrib['validUntil']
    alist = ''
    for a in root.attrib:
        alist += ' ' + a + '="' + root.attrib[a] + '"'
    logging.debug('Root element: ' + root.tag + alist)
    pipeline = Pipeline(args.keyfile, args.certfile, args.cacheDuration, args.validUntil)
    for ed in root.findall('{urn:oasis:names:tc:SAML:2.0:metadata}EntityDescriptor'):
        process_entity_descriptor(ed, pipeline, args)
