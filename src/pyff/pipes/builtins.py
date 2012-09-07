"""
Package that contains the basic set of pipes - functions that can be used to put together a processing pipeling for pyFF.
"""
from lxml.etree import DocumentInvalid

from pyff.utils import dumptree, schema, resource_string
from pyff.mdrepo import NS
from pyff.pipes import Plumbing, PipeException
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
import xmlsec
import base64
from datetime import datetime

__author__ = 'leifj'

def dump(md,t,name,args,id):
    """
Print a representation of the entities set on stdout. Useful for testing.
    """
    if t is not None:
        print dumptree(t)
    else:
        print "<EntitiesDescriptor xmlns=\"%s\"/>" % NS['md']

def end(md,t,name,args,id):
    """
Exit with optional error code and message.
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
    Make a copy of the working tree and process the arguments as a pipleline. This essentially resets the working
    tree and allows a new pipeline to run. Useful for producing multiple outputs from a single source.

    Examples:

    - select  # select all entities
    - fork:
        - certreport
        - publish:
             output: "/tmp/annotated.xml"
    - fork:
        - xslt:
             stylesheet: tidy.xml
        - publish:
             output: "/tmp/clean.xml"

    The second fork in this example is strictly speaking not necessary since the main pipeline is still active
    but it may help to structure your pipelines this way.
    """
    if type(args) is str or type(args) is unicode:
        args = [args]
    nt = None
    if t is not None:
        nt = deepcopy(t)

    Plumbing(pipeline=args,id=id).process(md)

def info(md,t,name,args,id):
    """
    Dumps the working document on stdout. Useful for testing.
    """
    if t is None:
        raise Exception,"Your plumbing is missing a select statement."

    for e in t.xpath("//md:EntityDescriptor",namespaces=NS):
        print e.get('entityID')
    return t

def local(md,t,name,args,id):
    """
    Load all entities found in a directory and optionally assign it to a name. When using 'remote' the validated
    stream is stored locally in the repository as the URI from which the stream was fetched. When using 'local' the
    name is the filename unless specified in the argument.

    Examples

    - local: /var/local-metadata

    or with a custom URI

    - local: /var/local-metadata as http://example.com/metadata.xml

    The name (URI) is used in select statements so that in the second example a select to find all SPs in /var/local-metadata
    would look like this:

    - local:
        - /var/local-metadata as http://example.com/metadata.xml
    - select:
        - http://example.com/metadata.xml!//md:EntityDescriptor[md:IDPSSODescriptor]
    """
    if type(args) is str or type(args) is unicode:
        args = [args]
    for d in args:
        d = d.strip()
        m = re.match("(\S+)+\s+as\s+(\S+)",d)
        if m:
            if os.path.isdir(m.group(0)):
                md.load_dir(m.group(0),url=m.group(1))
            else:
                raise ValueError("%s is not a directory" % m.group(0))
        else:
            if os.path.isdir(d):
                md.load_dir(d)
            else:
                raise ValueError("%s is not a directory" % d)
    return t


def publish(md,t,name,args,id):
    """
    Publish the working document. Publish takes one argument: a file where the document tree will be written.

    Examples:

    - publish: /tmp/idp.xml
    """
    try:
        schema().assertValid(t)
    except DocumentInvalid,ex:
        logging.error(ex.error_log)
        raise ValueError("XML schema validation failed")
    if args is None:
        raise ValueError("publish must specify output")

    if type(args) is str or type(args) is unicode:
        args = {"output": args}
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
        return url,urllib2.urlopen(url).read(),verify,None,datetime.now()
    except Exception,ex:
        return url,None,None,ex,datetime.now()

def _load(md,pile,args):
    """
    Recursively spawn _fetch for all URLs. A line on the form file:fn is treated as a file of URLs - one per line.
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
                    with open(url.partition(":")[2]) as fd:
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
    Load a (set of) remote URLs, validate (XSD) and optionally verify signature. Remote takes a list of pairs
    of a URI and an optional certificate or fingerprint for validation and loads those resources (validated)
    into the active repository.

    Examples:

    - remote:
        - http://md.swamid.se/md/swamid-2.0.xml 12:60:D7:09:6A:D9:C1:43:AD:31:88:14:3C:A8:C4:B7:33:8A:4F:CB

    Will download http://md.swamid.se/md/swamid-2.0.xml and validate the signature using a certificate (if found
    in the Signature-element that has sha1 fingerprint 12:60:D7:09:6A:D9:C1:43:AD:31:88:14:3C:A8:C4:B7:33:8A:4F:CB.
    """
    pool = eventlet.GreenPool()
    pile = eventlet.GreenPile(pool)
    if type(args) is str or type(args) is unicode:
        args = [args]

    _load(md,pile,args)

    for url,r,verify,ex,ts_start in pile:
        ts_end = datetime.now()
        if r is not None:
            logging.debug("url=%s: read %s bytes" % (url,len(r)))
            eids = md.parse_metadata(StringIO(r),key=verify,url=url)
            logging.info("url=%s: got %d entities" % (url,len(eids)))
        else:
            logging.error("url=%s: FAILED to load: %s" % (url,ex))

def select(md,t,name,args,id):
    """
    Select a set of EntityDescriptor elements as the working document. Select picks and expands elements (with
    optional filtering) from the active repository you setup using calls to 'local' and 'remote'.

    Select takes a list of selectors as argument. Each selector is on the form [<source>][!<filter]. An empty
    argument selects all entities

    Examples

    - select

    select all entities in the active repository.

    - select: /var/local-metadata

    select all entities found in the directory /var/local-metadata. You must have a call to local to load
    entities from this directory before select statement.

    - select: /var/local-metadata!//md:EntityDescriptor[md:IDPSSODescriptor]

    selects all IdPs from /var/local-metadata

    - select: !//md:EntityDescriptor[md:SPSSODescriptor]

    selects all SPs

    Select statements are not cumulative - a select followed by another select in the pipeline resets the
    working douments to the result of the second select.

    Most statements except local and remote depend on having a select somewhere in your pipeline and will
    stop the pipeline if the current working document is empty. For instance, running

    - select !//md:EntityDescriptor[md:SPSSODescriptor]
    - stats

    will terminate the pipeline at select if there are no SPs in the local repository. This is useful in
    combination with fork for handling multiple cases in your pipelines.
    """
    if args is None:
        args = md.keys()
    if type(args) is str or type(args) is unicode:
        args = [args]
    ot = md.entity_set(args,id)
    if ot is None:
        raise PipeException("empty select '%s' - stop" % ",".join(args))
    return ot

def pick(md,t,name,args,id):
    """
    Select a set of EntityDescriptor elements as a working document but don't validate it. Useful for testing. See
    'select' for more information about selecting the document.
    """
    if args is None:
        args = md.keys()
    if type(args) is str or type(args) is unicode:
        args = [args]
    return md.entity_set(args,id,validate=False)

def sign(md,t,name,args,id):
    """
    Sign the working document. The 'key' argument references either a PKCS#11 uri or the filename containing
    a PEM-encoded non-password protected private RSA key. The 'cert' argument may be empty in which case the
    cert is looked up using the PKCS#11 token, or may point to a file containing a PEM-encoded X.509 certificate.

    PKCS11 URI

    A pkcs11 URI has the form

        pkcs11://<absolute path to SO/DLL>[:slot]/<object label>[?pin=<pin>]


    The pin parameter can be used to point to an environment variable containing the pin: "env:<ENV variable>".
    By default pin is "env:PYKCS11PIN" which tells sign to use the pin found in the PYKCS11PIN environment
    variable. This is also the default for PyKCS11 which is used to communicate with the PKCS#11 module.

    Examples

    sign:
        key: pkcs11:///usr/lib/libsofthsm.so/signer

    This would sign the document using the key with label 'signer' in slot 0 of the /usr/lib/libsofthsm.so module.
    Note that you may need to run pyff with env PYKCS11PIN=<pin> .... for this to work. Consult the documentation
    of your PKCS#11 module to find out about any other configuration you may need.

    sign:
        key: signer.key
        cert: signer.crt

    This example signs the document using the plain key and cert found in the signer.key and signer.crt files.
    """
    if t is None:
        raise Exception,"Your plumbing is missing a select statement."

    if not type(args) is dict:
        raise ValueError("Missing key and cert arguments to sign pipe")

    key_file = args.get('key',None)
    cert_file = args.get('cert',None)

    if key_file is None:
        raise ValueError("Missing key argument for sign pipe")

    if cert_file is None:
        logging.info("Attempting to extract certificate from token...")

    xmlsec.sign(t,key_file,cert_file)

    return t

def stats(md,t,name,args,id):
    """
    Display statistics about the current working document. This doesn't change the working document in any way.
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
    Split the working document into EntityDescriptor-parts and save in directory/sha1(@entityID).xml. Note that
    this does not erase files that may already be in the directory. If you want a "clean" directory, remove it
    before you call store.
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
    Apply an XSLT stylesheet to the working document. The xslt pipe takes a set of keyword arguments. The only required
    argument is 'stylesheet' which identifies the xslt resource. This is looked up either in the package or as a
    user-supplied file. The rest of the keyword arguments are made available as string parameters to the XSLT transform.

    Examples

    xslt:
        sylesheet: foo.xsl
        x: foo
        y: bar
    """
    stylesheet = args.pop('stylesheet',None)
    if stylesheet is not None:
        if t is None:
            raise ValueError("Your plumbing is missing a select statement.")
        xslt = etree.fromstring(resource_string(stylesheet,"xslt"))
        transform = etree.XSLT(xslt)
        # this is to make sure the parameters are passed as xslt strings
        d = dict((k,"\'%s\'" % v) for (k,v) in args.items())
        ot = transform(t,**d)
        t = ot #.getroot()
    return t

def validate(md,t,name,args,id):
    """
    Generate an exception unless the working tree validates. Validation is done automatically
    during publication and loading of metadata so this call is seldom needed.
    """
    if t is not None:
        schema().assertValid(t)

def certreport(md,t,name,args,id):
    """
    Generate a report of the certificates (optionally limited by expiration time) found in the selection.

    Examples:

    - certreport

    - certreport:
         error_seconds: 0
         warning_seconds: 864000

    Remember that you need a 'publish' call after certreport in your pipeline to get useful output.
    """

    if t is None:
        raise ValueError("Your plumbing is missing a select statement.")

    print repr(args)

    if args is None:
        args = {}

    if type(args) is not dict:
        raise ValueError("usage: certreport {warning: 864000, error: 0}")

    error_seconds = int(args.get('error',"0"))
    warning_seconds = int(args.get('warning',"864000"))

    seen = {}
    for eid in t.xpath("//md:EntityDescriptor/@entityID",namespaces=NS):
        for cd in t.xpath("md:EntityDescriptor[@entityID='%s']//ds:X509Certificate" % eid,namespaces=NS):
            try:
                cert_pem = cd.text
                cert_der = base64.b64decode(cert_pem)
                m = hashlib.sha1()
                m.update(cert_der)
                fp = m.hexdigest()
                if not seen.get(fp,False):
                    seen[fp] = True
                    cdict = xmlsec.b642cert(cert_pem)
                    cert = cdict['cert']
                    et = datetime.strptime("%s" % cert.getNotAfter(),"%Y%m%d%H%M%SZ")
                    now = datetime.now()
                    dt = et - now
                    if dt.total_seconds() < error_seconds:
                        e = cd.getparent().getparent().getparent().getparent().getparent()
                        md.annotate(e,"certificate-error","certificate has expired","%s expired %s ago" % (cert.getSubject(),-dt))
                        logging.error("%s expired %s ago" % (eid,-dt))
                    elif dt.total_seconds() < warning_seconds:
                        e = cd.getparent().getparent().getparent().getparent().getparent()
                        md.annotate(e,"certificate-warning","certificate about to expire","%s expires in %s" % (cert.getSubject(),dt))
                        logging.warn("%s expires in %s" % (eid,dt))
            except Exception,ex:
                logging.error(ex)

