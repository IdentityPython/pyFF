from pyff.utils import dumptree, schema, resource_string
from pyff.mdrepo import NS
from pyff.pipes import Plumbing
from copy import deepcopy
import sys
import os
import re
import logging
import eventlet
import hashlib
from eventlet.green import urllib2
from StringIO import StringIO
from lxml import etree
import pyff.xmlsec as xmlsec

__author__ = 'leifj'

def dump(md,t,name,args,id):
    """
Print a representation of the entities set on stdout.
    """
    if t is not None:
        print dumptree(t)
    else:
        print "<EntitiesDescriptor xmlns=\"%s\"/>" % NS['md']

def end(md,t,name,args,id):
    """
Exit with optional error code and message
    """
    code = 0
    if args is not None:
        code = args.get('code',0)
        msg = args.get('message',None)
        if msg is None:
            print msg
    sys.exit(code)

def fork(md,t,name,args,id):
    """
    Make a copy of the working tree and process the arguments as a pipleline
    """
    if type(args) is str or type(args) is unicode:
        args = [args]
    nt = None
    if t is not None:
        nt = deepcopy(t)

    Plumbing(pipeline=args,id=id).process(md)

def info(md,t,name,args,id):
    """
    Dumps the selected entityIDs on stdout
    """
    if t is None:
        raise Exception,"Your plumbing is missing a select statement."

    for e in t.xpath("//md:EntityDescriptor",namespaces=NS):
        print e.get('entityID')
    return t

def local(md,t,name,args,id):
    if type(args) is str or type(args) is unicode:
        args = [args]
    for d in args:
        d = d.strip()
        m = re.match("(\S+)+\s+as\s+(\S+)")
        if m:
            if os.path.isdir(m.group(0)):
                md.load_dir(m.group(0),url=m.group(1))
        else:
            if os.path.isdir(d):
                md.load_dir(d)
    return t


def publish(md,t,name,args,id):
    """
    Publish the working tree.
    """
    schema().assertValid(t)
    output_file = args.get("output",None)
    if output_file is not None:
        out = output_file
        if os.path.isdir(output_file):
            out = "%s.xml" % os.path.join(output_file,id)
        with open(out,"w") as fo:
            fo.write(dumptree(t))
    return t

def _fetch(md,url,verify):
    logging.debug("open %s" % url)
    try:
        return (url,urllib2.urlopen(url).read(),verify,None)
    except Exception,ex:
        return (url,None,None,ex)

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

def remote(md,t,name,args,id):
    """
    Load a (set of) remote URLs
    """
    pool = eventlet.GreenPool()
    pile = eventlet.GreenPile(pool)
    if type(args) is str or type(args) is unicode:
        args = [args]

    _load(md,pile,args)

    for url,r,verify,ex in pile:
        if r is not None:
            logging.debug("url=%s: read %s bytes" % (url,len(r)))
            eids = md.parse_metadata(StringIO(r),key=verify,url=url)
            logging.info("url=%s: got %d entities" % (url,len(eids)))
        else:
            logging.error("url=%s: FAILED to load: %s" % (url,ex))

def select(md,t,name,args,id):
    """
    Select a working set of EntityDescriptor elements.
    """
    if args is None:
        args = md.keys()
    if type(args) is str or type(args) is unicode:
        args = [args]
    return md.entity_set(args,id)

def sign(md,t,name,args,id):
    """
    Return a signed tree
    """
    if t is None:
        raise Exception,"Your plumbing is missing a select statement."

    if not type(args) is dict:
        raise ValueError("Missing key and cert arguments to sign pipe")

    key_file = args.get('key',None)
    cert_file = args.get('cert',None)

    if key_file is None or cert_file is None:
        raise ValueError("Empty key and cert arguments to sign pipe")

    xmlsec.sign(t,key_file,cert_file)

    return t

def stats(md,t,name,args,id):
    """
    Display statistics about the current working set
    """
    print "---"
    print "total size:     %d" % len(md.keys())
    if t is not None:
        print "selected:       %d" % len(t.xpath("//md:EntityDescriptor",namespaces=NS))
        print "          idps: %d" % len(t.xpath("//md:EntityDescriptor[md:IDPSSODescriptor]",namespaces=NS))
        print "           sps: %d" % len(t.xpath("//md:EntityDescriptor[md:SPSSODescriptor]",namespaces=NS))
    print "---"

def store(md,t,name,args,id):
    """
    Split into EntityDescriptor-parts and save in directory/sha1(@entityID).xml
    """
    target_dir = args.pop('directory',None)
    if target_dir is not None:
        if not os.path.isdir(target_dir):
            os.makedirs(target_dir)
        if t is None:
            raise Exception,"Your plumbing is missing a select statement."
        for e in t.xpath("//md:EntityDescriptor",namespaces=NS):
            eid = e.get('entityID')
            if eid is None or len(eid) == 0:
                raise Exception,"Missing entityID in %s" % e
            m = hashlib.sha1()
            m.update(eid)
            d = m.hexdigest()
            with open("%s.xml" % os.path.join(target_dir,d),"w") as fn:
                fn.write(etree.tostring(e,encoding='UTF-8',xml_declaration=True,pretty_print=True))
    return t

def xslt(md,t,name,args,id):
    """
    Apply an XSLT stylesheet to the working set
    """
    stylesheet = args.pop('stylesheet',None)
    if stylesheet is not None:
        if t is None:
            raise Exception,"Your plumbing is missing a select statement."
        xslt = etree.fromstring(resource_string(stylesheet,"xslt"))
        transform = etree.XSLT(xslt)
        # this is to make sure the parameters are passed as xslt strings
        d = dict((k,"\'%s\'" % v) for (k,v) in args.items())
        ot = transform(t,**d)
        t = ot.getroot()
    return t

def validate(md,t,name,args,id):
    """
    Generate an exception unless the working tree validates. Validation is done automatically
    during publication and loading of metadata.
    """
    if t is not None:
        schema().assertValid(t)
