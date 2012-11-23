"""
Package that contains the basic set of pipes - functions that can be used to put together a processing pipeling for pyFF.
"""
import cherrypy
from iso8601 import iso8601
from lxml.etree import DocumentInvalid
from pyff.utils import dumptree, schema,safe_write, template, root, duration2timedelta, xslt_transform
from pyff.mdrepo import NS
from pyff.pipes import Plumbing, PipeException
from copy import deepcopy
import sys
import os
import re
from pyff.logs import log
import eventlet
import hashlib
from eventlet.green import urllib2
from StringIO import StringIO
import xmlsec
import base64
from datetime import datetime

__author__ = 'leifj'

def dump(req,*opts):
    """
    :param req: The request
    :param opts: Options (unused)
    :return: None

Print a representation of the entities set on stdout. Useful for testing.
    """
    if req.t is not None:
        print dumptree(req.t)
    else:
        print "<EntitiesDescriptor xmlns=\"%s\"/>" % NS['md']

def end(req,*opts):
    """
    :param req: The request
    :param opts: Options (unused)
    :return: None

Exit with optional error code and message.
    """
    code = 0
    if req.args is not None:
        code = req.args.get('code',0)
        msg = req.args.get('message',None)
        if msg is None:
            print msg
    sys.exit(code)

def fork(req,*opts):
    """
    :param req: The request
    :param opts: Options (unused)
    :return: None

Make a copy of the working tree and process the arguments as a pipleline. This essentially resets the working
tree and allows a new plumbing to run. Useful for producing multiple outputs from a single source.

**Examples**

.. code-block:: yaml

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

The second fork in this example is strictly speaking not necessary since the main plumbing is still active
but it may help to structure your plumbings this way.

Normally the result of the "inner" plumbing is disgarded - unless published or emit:ed to a calling client
in the case of the MDX server - but by adding 'merge' to the options with an optional 'merge strategy' the
behaviour can be changed to merge the result of the inner pipeline back to the parent working document.

The default merge strategy is 'replace_existing' which replaces each EntityDescriptor found in the resulting
document in the parent document (using the entityID as a pointer). Any python module path ('a.mod.u.le.callable')
ending in a callable is accepted. If the path doesn't contain a '.' then it is assumed to reference one of the
standard merge strategies in pyff.merge_strategies.

For instance the following block can be used to set an attribute on a single entity:

.. code-block: yaml

    - fork merge:
        - select: http://sp.example.com/shibboleth-sp
        - setattr:
            attribute: value


Note that unless you have a select statement before your fork merge you'll be merging into an empty
active document which with the default merge strategy of replace_existing will result in an empty
active document. To avoid this do a select before your fork, thus:

.. code-block: yaml

    - select
    - fork merge:
        - select: http://sp.example.com/shibboleth-sp
        - setattr:
            attribute: value


    """
    nt = None
    if req.t is not None:
        nt = deepcopy(req.t)

    ip = Plumbing(pipeline=req.args,id="%s.fork" % req.plumbing.id)
    ireq = Plumbing.Request(ip,req.md,nt)
    ip._process(ireq)

    if 'merge' in opts and ireq.t is not None and len(ireq.t) > 0:
        sn="pyff.merge_strategies.replace_existing"
        if opts[-1] != 'merge':
            sn = opts[-1]
        req.md.merge(req.t,ireq.t,strategy_name=sn)

def _any(lst,d):
    for x in lst:
        if d.has_key(x):
            return d[x]
    return False

def _break(req,*opts):
    """
    :param req: The request
    :param opts: Options (unused)
    :return: None

Break out of a pipeline. This sets the 'done' request property to True which
causes the pipeline to terminate at that point. The method name is '_break'
but the keyword is 'break' to avoid conflicting with python builtin methods.

**Examples**

.. code-block:: yaml

    - one
    - two
    - break
    - unreachable

    """
    req.done = True
    return req.t

def pipe(req,*opts):
    """
    :param req: The request
    :param opts: Options (unused)
    :return: None

Run the argument list as a pipleine. Unline fork does not copy the working document.
The done request property is reset to False after the pipeline has been processed.
This allows for a classical switch/case flow using the following construction:

.. code-block:: yaml

    - pipe:
        - when a:
            - one
            - break
        - when b:
            - two
            - break

In this case if 'a' is present in the request state, then 'one' will be executed and
the 'when b' condition will not be tested at all. Note that at the topmost level the
pipe is implicit and may be left out.

.. code-block:: yaml

- pipe:
    - one
    - two

is equivalent to

.. code-block:: yaml

- one
- two

    """
    ot = Plumbing(pipeline=req.args,id="%s.pipe" % req.plumbing.id)._process(req)
    req.done = False
    return ot

def when(req,condition,*values):
    """
    :param req: The request
    :param condition: The condition
    :param opts: More Options (unused)
    :return: None

Conditionally execute part of the pipeline. The inner pipeline is executed if the
condition is met using data present in the request state.

**Examples**

.. code-block: yaml

    - when foo
        - something
    - when bar bill
        - other

The condition operates on the state: if 'foo' is present in the state (with any value), then
the something branch is followed. If 'bar' is present in the state with the value 'bill' then
the other branch is followed.
    """
    log.debug("condition key: %s" % repr(condition))
    c = req.state.get(condition,None)
    log.debug("condition %s" % repr(c))
    if c is not None:
        if not values or _any(values,c):
            return Plumbing(pipeline=req.args,id="%s.when" % req.plumbing.id)._process(req)
    return req.t

def info(req,*opts):
    """
    :param req: The request
    :param opts: Options (unused)
    :return: None

Dumps the working document on stdout. Useful for testing.
    """
    if req.t is None:
        raise Exception,"Your plumbing is missing a select statement."

    for e in req.t.xpath("//md:EntityDescriptor",namespaces=NS):
        print e.get('entityID')
    return req.t

def publish(req,*opts):
    """
    :param req: The request
    :param opts: Options (unused)
    :return: None

Publish the working document. Publish takes one argument: a file where the document tree will be written.

**Examples**

.. code-block:: yaml

    - publish: /tmp/idp.xml
    """

    if req.t is None or not len(req.t):
        raise ValueError("Empty document submitted for publication")

    try:
        schema().assertValid(req.t)
    except DocumentInvalid,ex:
        log.error(ex.error_log)
        raise ValueError("XML schema validation failed")
    if req.args is None:
        raise ValueError("publish must specify output")

    output_file = None
    if type(req.args) is dict:
        output_file = req.args.get("output",None)
    else:
        output_file = req.args[0]
    if output_file is not None:
        output_file = output_file.strip()
        log.debug("publish %s" % output_file)
        resource_name = output_file
        m = re.match("(\S+)+\s+as\s+(\S+)",output_file)
        if m:
            output_file = m.group(1)
            resource_name = m.group(2)
        log.debug("output_file=%s, resource_name=%s" % (output_file,resource_name))
        out = output_file
        if os.path.isdir(output_file):
            out = "%s.xml" % os.path.join(output_file,req.id)
        safe_write(out,dumptree(req.t))
        req.md[resource_name] = req.t
    return req.t

def _fetch(md,url,verify):
    log.debug("open %s" % url)
    try:
        return url,urllib2.urlopen(url).read(),verify,None,datetime.now()
    except Exception,ex:
        return url,None,None,ex,datetime.now()

def remote(req,*opts):
    return load(req,opts)

def local(req,*opts):
    return load(req,opts)

def load(req,*opts):
    """
    :param req: The request
    :param opts: Options (unused)
    :return: None

General-purpose resource fetcher. Supports both remote and local resources. Fetching remote resources
is done using threads.
    """
    remote = []
    for x in req.args:
        x = x.strip()
        log.debug("load %s" % x)
        m = re.match("(\S+)\s+as\s+(\S+)",x)
        id = None
        if m:
            x = m.group(1)
            id = m.group(2)
        r = x.split()
        assert len(r) in [1,2], ValueError("Usage: load: resource [as url] [verification]")
        verify = None
        url = r[0]
        if len(r) == 2:
            verify = r[1]

        if "://" in url:
            log.debug("remote %s %s %s" % (url,verify,id))
            remote.append((url,verify,id))
        elif os.path.exists(url):
            if os.path.isdir(url):
                log.debug("local directory %s %s %s" % (url,verify,id))
                req.md.load_dir(url,url=id)
            elif os.path.isfile(url):
                log.debug("local file %s %s %s" % (url,verify,id))
                remote.append(("file://%s" % url,verify,id))
            else:
                raise ValueError("Unknown file type for load: %s" % r[0])
        else:
            raise ValueError("Don't know how to load '%s' as %s verified by %s" % (url,id,verify))

    opts = dict(opts)
    opts.setdefault('timeout',30)
    opts.setdefault('qsize',5)
    stats = dict()
    opts.setdefault('stats',stats)
    req.md.fetch_metadata(remote,**opts)
    req.state['stats']['Metadata URLs'] = stats

def select(req,*opts):
    """
    :param req: The request
    :param opts: Options (unused)
    :return: returns the result of the operation as a working document

Select a set of EntityDescriptor elements as the working document. Select picks and expands elements (with
optional filtering) from the active repository you setup using calls to 'local' and 'remote'.

Select takes a list of selectors as argument. Each selector is on the form [<source>][!<filter]. An empty
argument selects all entities

**Examples**

.. code-block:: yaml

    - select

This would select all entities in the active repository.

.. code-block:: yaml

    - select: /var/local-metadata

This would select all entities found in the directory /var/local-metadata. You must have a call to local to load
entities from this directory before select statement.

.. code-block:: yaml

    - select: /var/local-metadata!//md:EntityDescriptor[md:IDPSSODescriptor]

This would selects all IdPs from /var/local-metadata

.. code-block:: yaml

    - select: !//md:EntityDescriptor[md:SPSSODescriptor]

This would select all SPs

Select statements are not cumulative - a select followed by another select in the plumbing resets the
working douments to the result of the second select.

Most statements except local and remote depend on having a select somewhere in your plumbing and will
stop the plumbing if the current working document is empty. For instance, running

.. code-block:: yaml

    - select !//md:EntityDescriptor[md:SPSSODescriptor]
    - stats

This would terminate the plumbing at select if there are no SPs in the local repository. This is useful in
combination with fork for handling multiple cases in your plumbings.
    """
    args = req.args
    if args is None:
        args = [req.state.get('select',None)]
    if args is None:
        args = req.md.keys()
    ot = req.md.entity_set(args,req.plumbing.id)
    if ot is None:
        raise PipeException("empty select '%s' - stop" % ",".join(args))
    return ot

def pick(req,*opts):
    """
    :param req: The request
    :param opts: Options (unused)
    :return: returns the result of the operation as a working document

Select a set of EntityDescriptor elements as a working document but don't validate it. Useful for testing. See
'select' for more information about selecting the document.
    """
    args = req.args
    if args is None:
        args = req.md.keys()
    ot = req.md.entity_set(args,req.plumbing.id,validate=False)
    if ot is None:
        raise PipeException("empty select '%s' - stop" % ",".join(args))
    return ot

def first(req,*opts):
    """
    :param req: The request
    :param opts: Options (unused)
    :return: returns the first entity descriptor if the working document only contains one

    Sometimes (eg when running an MDX pipeline) it is usually expected that if a single EntityDescriptor
    is being returned then the outer EntitiesDescriptor is stripped. This method does exactly that:
    """
    nent = len(req.t.findall("//{%s}EntityDescriptor" % NS['md']))
    if nent == 1:
        return req.t.find("//{%s}EntityDescriptor" % NS['md'])
    else:
        return req.t


def sign(req,*opts):
    """
    :param req: The request
    :param opts: Options (unused)
    :return: returns the signed working document

Sign the working document. The 'key' argument references either a PKCS#11 uri or the filename containing
a PEM-encoded non-password protected private RSA key. The 'cert' argument may be empty in which case the
cert is looked up using the PKCS#11 token, or may point to a file containing a PEM-encoded X.509 certificate.

**PKCS11 URIs**

A pkcs11 URI has the form

.. code-block:: xml

    pkcs11://<absolute path to SO/DLL>[:slot]/<object label>[?pin=<pin>]

The pin parameter can be used to point to an environment variable containing the pin: "env:<ENV variable>".
By default pin is "env:PYKCS11PIN" which tells sign to use the pin found in the PYKCS11PIN environment
variable. This is also the default for PyKCS11 which is used to communicate with the PKCS#11 module.

**Examples**

.. code-block:: yaml

    - sign:
        key: pkcs11:///usr/lib/libsofthsm.so/signer

This would sign the document using the key with label 'signer' in slot 0 of the /usr/lib/libsofthsm.so module.
Note that you may need to run pyff with env PYKCS11PIN=<pin> .... for this to work. Consult the documentation
of your PKCS#11 module to find out about any other configuration you may need.

.. code-block:: yaml

    - sign:
        key: signer.key
        cert: signer.crt

This example signs the document using the plain key and cert found in the signer.key and signer.crt files.
    """
    if req.t is None:
        raise Exception,"Your plumbing is missing a select statement."

    if not type(req.args) is dict:
        raise ValueError("Missing key and cert arguments to sign pipe")

    key_file = req.args.get('key',None)
    cert_file = req.args.get('cert',None)

    if key_file is None:
        raise ValueError("Missing key argument for sign pipe")

    if cert_file is None:
        log.info("Attempting to extract certificate from token...")

    xmlsec.sign(req.t,key_file,cert_file)

    return req.t

def stats(req,*opts):
    """
    :param req: The request
    :param opts: Options (unused)
    :return: always returns the unmodified working document

Display statistics about the current working document. This doesn't change the working document in any way.
    """
    print "---"
    print "total size:     %d" % len(req.md.keys())
    if req.t is not None:
        print "selected:       %d" % len(req.t.xpath("//md:EntityDescriptor",namespaces=NS))
        print "          idps: %d" % len(req.t.xpath("//md:EntityDescriptor[md:IDPSSODescriptor]",namespaces=NS))
        print "           sps: %d" % len(req.t.xpath("//md:EntityDescriptor[md:SPSSODescriptor]",namespaces=NS))
    print "---"
    return req.t

def store(req,*opts):
    """
    :param req: The request
    :param opts: Options (unused)
    :return: always returns the unmodified working document
    
Split the working document into EntityDescriptor-parts and save in directory/sha1(@entityID).xml. Note that
this does not erase files that may already be in the directory. If you want a "clean" directory, remove it
before you call store.
    """

    if not req.args:
        raise ValueError("store requires an argument")

    target_dir = None
    if type(req.args) is dict:
        target_dir = req.args.get('directory',None)
    else:
        target_dir = req.args[0]

    if target_dir is not None:
        if not os.path.isdir(target_dir):
            os.makedirs(target_dir)
        if req.t is None:
            raise Exception,"Your plumbing is missing a select statement."
        for e in req.t.xpath("//md:EntityDescriptor",namespaces=NS):
            eid = e.get('entityID')
            if eid is None or len(eid) == 0:
                raise Exception,"Missing entityID in %s" % e
            m = hashlib.sha1()
            m.update(eid)
            d = m.hexdigest()
            safe_write("%s.xml" % os.path.join(target_dir,d),dumptree(e,pretty_print=True))
    return req.t

def xslt(req,*opts):
    """
    :param req: The request
    :param opts: Options (unused)
    :return: the transformation result

Apply an XSLT stylesheet to the working document. The xslt pipe takes a set of keyword arguments. The only required
argument is 'stylesheet' which identifies the xslt resource. This is looked up either in the package or as a
user-supplied file. The rest of the keyword arguments are made available as string parameters to the XSLT transform.

**Examples**

.. code-block:: yaml

    - xslt:
        sylesheet: foo.xsl
        x: foo
        y: bar
    """
    stylesheet = req.args.get('stylesheet',None)
    if stylesheet is None:
        raise ValueError("xslt requires stylesheet")

    if req.t is None:
        raise ValueError("Your plumbing is missing a select statement.")

    params = dict((k,"\'%s\'" % v) for (k,v) in req.args.items())
    del params['stylesheet']
    ot = xslt_transform(req.t,stylesheet,params)
    #log.debug(ot)
    return ot

def validate(req,*opts):
    """
    :param req: The request
    :param opts: Options - the template name
    :return: The unmodified tree

Generate an exception unless the working tree validates. Validation is done automatically
during publication and loading of metadata so this call is seldom needed.
    """
    if req.t is not None:
        schema().assertValid(req.t)

    return req.t

def page(req,*opts):
    """
    :param req: The request
    :param opts: Options - the template name
    :return: HTML

Uses the template specified (defaults to "index.html") to generate an html page. Useful for responding to index
requests. The template is provided the following context:

    :param http: The cherrypy request
    :param pyff: The pyFF request

This method can only be used to produce text/html.

**Examples**

.. code-block:: yaml

    - when request /foo:
        - page foo.html:
            - param1: value1
            - param2: value2
    """
    req.state['headers']['Content-Type'] = 'text/html'
    ctx = {
        'http': cherrypy.request,
        'pyff': req
    }
    tmpl = "index.html"
    if len(opts) > 0:
        tmpl = opts[0]
    return template(tmpl).render(**ctx)

def redirect(req,*opts):
    """
    :param req: The request
    :param opts: Options (not used)
    :return: does not return - raises a cherrypy redrect exception

Return a 301

**Examples**

.. code-block:: yaml

    - when request /:
        - redirect: /md/
        - break
    """
    raise cherrypy.HTTPRedirect(req.args[0])

def certreport(req,*opts):
    """
    :param req: The request
    :param opts: Options (not used)
    :return: always returns the unmodified working document

Generate a report of the certificates (optionally limited by expiration time) found in the selection.

**Examples**

.. code-block:: yaml

    - certreport
    - certreport:
         error_seconds: 0
         warning_seconds: 864000

Remember that you need a 'publish' call after certreport in your plumbing to get useful output.
    """

    if req.t is None:
        raise ValueError("Your plumbing is missing a select statement.")

    if not req.args:
        req.args = {}

    if type(req.args) is not dict:
        raise ValueError("usage: certreport {warning: 864000, error: 0}")

    error_seconds = int(req.args.get('error',"0"))
    warning_seconds = int(req.args.get('warning',"864000"))

    seen = {}
    for eid in req.t.xpath("//md:EntityDescriptor/@entityID",namespaces=NS):
        for cd in req.t.xpath("md:EntityDescriptor[@entityID='%s']//ds:X509Certificate" % eid,namespaces=NS):
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
                        req.md.annotate(e,"certificate-error","certificate has expired","%s expired %s ago" % (cert.getSubject(),-dt))
                        log.error("%s expired %s ago" % (eid,-dt))
                    elif dt.total_seconds() < warning_seconds:
                        e = cd.getparent().getparent().getparent().getparent().getparent()
                        req.md.annotate(e,"certificate-warning","certificate about to expire","%s expires in %s" % (cert.getSubject(),dt))
                        log.warn("%s expires in %s" % (eid,dt))
            except Exception,ex:
                log.error(ex)

def emit(req,ctype="application/xml",*opts):
    """
    :param req: The request
    :param opts: Options (not used)
    :return: unicode

Renders the working tree as text and sets the digest of the tree as the ETag.
If the tree has already been rendered as text by an earlier step the text is
returned as utf-8 encoded unicode.

**Examples**

.. code-block:: yaml

    - emit application/xml
    """

    d = req.t
    log.debug("before getroot (%s) %s" % (type(d),repr(d)))
    if hasattr(d,'getroot') and hasattr(d.getroot,'__call__'):
        nd = d.getroot()
        if nd is None:
            d = str(d)
        else:
            d = nd
    log.debug("after getroot (%s) %s" % (type(d),repr(d)))
    if hasattr(d,'tag'):
        log.debug("has tag")
        d = dumptree(d)
    log.debug("after dumptree (%s) %s" % (type(d),repr(d)))

    if d is not None:
        m = hashlib.sha1()
        m.update(d)
        req.state['headers']['ETag'] = m.hexdigest()
    else:
        raise ValueError("Empty")

    req.state['headers']['Content-Type'] = ctype
    return unicode(d.decode('utf-8')).encode("utf-8")

def signcerts(req,*opts):
    """
    :param req: The request
    :param opts: Options (not used)
    :return: always returns the unmodified working document

This logs (INFO) the fingerprints of the signing certs found in the current working tree. Useful for testing.

**Examples**

.. code-block:: yaml

    - signcerts
    """
    if req.t is None:
        raise ValueError("Your plumbing is missing a select statement.")
    for fp,pem in xmlsec.CertDict(req.t).iteritems():
        log.info("found signing cert with fingerprint %s" % fp)
    return req.t

def finalize(req,*opts):
    """
    :param req: The request
    :param opts: Options (not used)
    :return: returns the working document with @Name, @cacheDuration and @validUntil set

This method sets Name, cacheDuration and validUntil on the toplevel EntitiesDescriptor element
of the working document. Unless explicit provided the @Name is set from the request URI if the
pipeline is executed in the pyFF server. The @cacheDuration element must be a valid xsd
duration (eg PT5H for 5 hrs) and @validUntil can be either an absolute ISO 8601 time
string or (more comonly) a relative time on the form

.. code-block:: none

    \+?([0-9]+d)?\s*([0-9]+h)?\s*([0-9]+m)?\s*([0-9]+s)?


For instance +45d 2m results in a time delta of 45 days and 2 minutes. The '+' sign is optional.

If operating on a single EntityDescriptor then @Name is ignored (cf first).

**Examples**

.. code-block:: yaml

    - finalize:
        cacheDuration: PT8H
        validUntil: +10d
    """
    if req.t is None:
        raise ValueError("Your plumbing is missing a select statement.")

    e = root(req.t)
    if e.tag == "{%s}EntitiesDescriptor" % NS['md']:
        name = req.args.get('name',None)
        if name is None or not len(name):
            name = req.args.get('Name',None)
        if name is None or not len(name):
            name = req.state.get('url',None)
        if name is None or not len(name):
            name = e.get('Name',None)
        if name is not None and len(name):
            e.set('Name',name)

    validUntil = req.args.get('validUntil',e.get('validUntil',None))
    if validUntil is not None and len(validUntil) > 0:
        offset = duration2timedelta(validUntil)
        if offset is not None:
            dt = datetime.now()+offset
            e.set('validUntil',dt.isoformat())
        elif validUntil is not None:
            dt = iso8601.parse_date(validUntil)
            offset = dt - datetime.now()
        # set a reasonable default: 50% of the validity
        # we replace this below if we have cacheDuration set
        req.state['cache'] = int(offset.total_seconds() / 50)

    cacheDuration = req.args.get('cacheDuration',e.get('cacheDuration',None))
    if cacheDuration is not None and len(cacheDuration) > 0:
        offset = duration2timedelta(cacheDuration)
        if offset is None:
            raise ValueError("Unable to parse %s as xs:duration" % cacheDuration)

        e.set('cacheDuration',cacheDuration)
        req.state['cache'] = int(offset.total_seconds())

    return req.t

def setattr(req,*opts):
    """
    :param req: The request
    :param opts: Options (not used)
    :return: A modified working document

Transforms the working document by setting the specified attribute on all of the EntityDescriptor
elements of the active document.

    **Examples**

.. code-block:: yaml

    - setattr:
        attr1: value1
        attr2: value2
        ...

Normally this would be combined with the 'merge' feature of fork to add attributes to the working
document for later processing.
    """
    for e in req.t.findall(".//{%s}EntityDescriptor" % NS['md']):
        #log.debug("setting %s on %s" % (req.args,e.get('entityID')))
        req.md.set_entity_attributes(e,req.args)
