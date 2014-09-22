"""Package that contains the basic set of pipes - functions that can be used to put together a processing pipeling
for pyFF.
"""
from distutils.util import strtobool
import traceback
from iso8601 import iso8601
from lxml.etree import DocumentInvalid
from .decorators import deprecated
from .utils import total_seconds, dumptree, safe_write, root, duration2timedelta, xslt_transform, \
    iter_entities, validate_document
from .constants import NS
from .pipes import Plumbing, PipeException, PipelineCallback, pipe
from copy import deepcopy
import sys
import os
import re
from .logs import log
import hashlib
import xmlsec
import base64
from datetime import datetime

__author__ = 'leifj'

FILESPEC_REGEX = "([^ \t\n\r\f\v]+)\s+as\s+([^ \t\n\r\f\v]+)"


@pipe
def dump(req, *opts):
    """
Print a representation of the entities set on stdout. Useful for testing.

:param req: The request
:param opts: Options (unused)
:return: None
    """
    if req.t is not None:
        print dumptree(req.t)
    else:
        print "<EntitiesDescriptor xmlns=\"%s\"/>" % NS['md']

@pipe
def end(req, *opts):
    """
Exit with optional error code and message.

:param req: The request
:param opts: Options (unused)
:return: None

**Examples**

.. code-block:: yaml

    - end
    - unreachable

**Warning** This is very bad if used with pyffd - the server will stop running. If you just want to
break out of the pipeline, use break instead.

    """
    code = 0
    if req.args is not None:
        code = req.args.get('code', 0)
        msg = req.args.get('message', None)
        if msg is not None:
            print msg
    sys.exit(code)


@pipe
def fork(req, *opts):
    """
Make a copy of the working tree and process the arguments as a pipleline. This essentially resets the working
tree and allows a new plumbing to run. Useful for producing multiple outputs from a single source.

:param req: The request
:param opts: Options (unused)
:return: None

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

**Merging**

Normally the result of the "inner" plumbing is disgarded - unless published or emit:ed to a calling client
in the case of the MDX server - but by adding 'merge' to the options with an optional 'merge strategy' the
behaviour can be changed to merge the result of the inner pipeline back to the parent working document.

The default merge strategy is 'replace_existing' which replaces each EntityDescriptor found in the resulting
document in the parent document (using the entityID as a pointer). Any python module path ('a.mod.u.le.callable')
ending in a callable is accepted. If the path doesn't contain a '.' then it is assumed to reference one of the
standard merge strategies in pyff.merge_strategies.

For instance the following block can be used to set an attribute on a single entity:

.. code-block:: yaml

    - fork merge:
        - select: http://sp.example.com/shibboleth-sp
        - setattr:
            attribute: value


Note that unless you have a select statement before your fork merge you'll be merging into an empty
active document which with the default merge strategy of replace_existing will result in an empty
active document. To avoid this do a select before your fork, thus:

.. code-block:: yaml

    - select
    - fork merge:
        - select: http://sp.example.com/shibboleth-sp
        - setattr:
            attribute: value

    """
    nt = None
    if req.t is not None:
        nt = deepcopy(req.t)

    ip = Plumbing(pipeline=req.args, pid="%s.fork" % req.plumbing.pid)
    #ip.process(req.md,t=nt)
    ireq = Plumbing.Request(ip, req.md, nt)
    ip._process(ireq)

    if 'merge' in opts and ireq.t is not None and len(ireq.t) > 0:
        sn = "pyff.merge_strategies.replace_existing"
        if opts[-1] != 'merge':
            sn = opts[-1]
        req.md.merge(req.t, ireq.t, strategy_name=sn)


@pipe(name='any')
def _any(lst, d):
    for x in lst:
        if x in d:
            if type(d) == dict:
                return d[x]
            else:
                return True
    return False


@pipe(name='break')
def _break(req, *opts):
    """
Break out of a pipeline.

:param req: The request
:param opts: Options (unused)
:return: None

This sets the 'done' request property to True which causes the pipeline to terminate at that point. The method name
is '_break' but the keyword is 'break' to avoid conflicting with python builtin methods.

**Examples**

.. code-block:: yaml

    - one
    - two
    - break
    - unreachable

    """
    req.done = True
    return req.t


@pipe(name='pipe')
def _pipe(req, *opts):
    """
Run the argument list as a pipleine.

:param req: The request
:param opts: Options (unused)
:return: None

Unlike fork, pipe does not copy the working document but instead operates on the current active document. The done
request property is reset to False after the pipeline has been processed. This allows for a classical switch/case
flow using the following construction:

.. code-block:: yaml

    - pipe:
        - when a:
            - one
            - break
        - when b:
            - two
            - break

In this case if 'a' is present in the request state, then 'one' will be executed and the 'when b' condition will not
be tested at all. Note that at the topmost level the pipe is implicit and may be left out.

.. code-block:: yaml

    - pipe:
        - one
        - two

is equivalent to

.. code-block:: yaml

    - one
    - two

    """
    #req.process(Plumbing(pipeline=req.args, pid="%s.pipe" % req.plumbing.pid))
    ot = Plumbing(pipeline=req.args, pid="%s.pipe" % req.plumbing.id)._process(req)
    req.done = False
    return ot


@pipe
def when(req, condition, *values):
    """
Conditionally execute part of the pipeline.

:param req: The request
:param condition: The condition key
:param values: The condition values
:param opts: More Options (unused)
:return: None

The inner pipeline is executed if the at least one of the condition values is present for the specified key in
the request state.

**Examples**

.. code-block:: yaml

    - when foo
        - something
    - when bar bill
        - other

The condition operates on the state: if 'foo' is present in the state (with any value), then the something branch is
followed. If 'bar' is present in the state with the value 'bill' then the other branch is followed.
    """
    #log.debug("condition key: %s" % repr(condition))
    c = req.state.get(condition, None)
    #log.debug("condition %s" % repr(c))
    if c is not None:
        if not values or _any(values, c):
            return Plumbing(pipeline=req.args, pid="%s.when" % req.plumbing.id)._process(req)
    return req.t


@pipe
def info(req, *opts):
    """
Dumps the working document on stdout. Useful for testing.

:param req: The request
:param opts: Options (unused)
:return: None

    """
    if req.t is None:
        raise PipeException("Your pipeline is missing a select statement.")

    for e in req.t.xpath("//md:EntityDescriptor", namespaces=NS, smart_strings=False):
        print e.get('entityID')
    return req.t


@pipe
def publish(req, *opts):
    """
Publish the working document in XML form.

:param req: The request
:param opts: Options (unused)
:return: None

 Publish takes one argument: path to a file where the document tree will be written.

**Examples**

.. code-block:: yaml

    - publish: /tmp/idp.xml
    """

    if req.t is None:
        raise PipeException("Empty document submitted for publication")

    if req.args is None:
        raise PipeException("publish must specify output")

    try:
        validate_document(req.t)
    except DocumentInvalid, ex:
        log.error(ex.error_log)
        raise PipeException("XML schema validation failed")

    output_file = None
    if type(req.args) is dict:
        output_file = req.args.get("output", None)
    else:
        output_file = req.args[0]
    if output_file is not None:
        output_file = output_file.strip()
        log.debug("publish %s" % output_file)
        resource_name = output_file
        m = re.match(FILESPEC_REGEX, output_file)
        if m:
            output_file = m.group(1)
            resource_name = m.group(2)
        log.debug("output_file=%s, resource_name=%s" % (output_file, resource_name))
        out = output_file
        if os.path.isdir(output_file):
            out = "%s.xml" % os.path.join(output_file, req.id)
        safe_write(out, dumptree(req.t))
        req.md.store.update(req.t, tid=resource_name)  # TODO maybe this is not the right thing to do anymore
    return req.t

@pipe
@deprecated
def remote(req, *opts):
    """Deprecated. Calls :py:mod:`pyff.pipes.builtins.load`.
    """
    return load(req, opts)

@pipe
@deprecated
def local(req, *opts):
    """Deprecated. Calls :py:mod:`pyff.pipes.builtins.load`.
    """
    return load(req, opts)

@pipe
@deprecated
def _fetch(req, *opts):
    return load(req, *opts)

@pipe
def load(req, *opts):
    """
General-purpose resource fetcher.

    :param opts:
    :param req: The request
    :param opts: Options: [qsize <5>] [timeout <30>] [validate <True*|False>]
    :return: None

Supports both remote and local resources. Fetching remote resources is done in parallell using threads.
    """
    opts = dict(zip(opts[::2], opts[1::2]))
    opts.setdefault('timeout', 120)
    opts.setdefault('max_workers', 5)
    opts.setdefault('validate', "True")
    opts['validate'] = bool(strtobool(opts['validate']))
    stats = dict()
    opts.setdefault('stats', stats)

    remote = []
    for x in req.args:
        x = x.strip()
        log.debug("load parsing '%s'" % x)
        r = x.split()

        assert len(r) in range(1, 7), PipeException("Usage: load resource [as url] [[verify] verification] [via pipeline]")

        url = r.pop(0)
        params = dict()

        while len(r) > 0:
            elt = r.pop(0)
            if elt in ("as", "verify", "via"):
                if len(r) > 0:
                    params[elt] = r.pop(0)
                else:
                    raise PipeException("Usage: load resource [as url] [[verify] verification] [via pipeline]")
            else:
                params['verify'] = elt

        for elt in ("as", "verify", "via"):
            params.setdefault(elt, None)

        post = None
        if params['via'] is not None:
            post = PipelineCallback(params['via'], req, stats)

        if "://" in url:
            log.debug("load %s verify %s as %s via %s" % (url, params['verify'], params['as'], params['via']))
            remote.append((url, params['verify'], params['as'], post))
        elif os.path.exists(url):
            if os.path.isdir(url):
                log.debug("directory %s verify %s as %s via %s" % (url, params['verify'], params['as'], params['via']))
                req.md.load_dir(url, url=params['as'], validate=opts['validate'], post=post)
            elif os.path.isfile(url):
                log.debug("file %s verify %s as %s via %s" % (url, params['verify'], params['as'], params['via']))
                remote.append(("file://%s" % url, params['verify'], params['as'], post))
            else:
                log.error("Unknown file type for load: '%s'" % url)
        else:
            log.error("Don't know how to load '%s' as %s verify %s via %s" %
                      (url, params['as'], params['verify'], params['via']))

    req.md.fetch_metadata(remote, **opts)
    req.state['stats']['Metadata URLs'] = stats


def _select_args(req):
    args = req.args
    if log.isDebugEnabled():
        log.debug("selecting using args: %s" % args)
    if args is None and 'select' in req.state:
        args = [req.state.get('select')]
    if args is None:
        args = req.md.store.collections()
    if args is None or not args:
        args = req.md.store.lookup('entities')
    if args is None or not args:
        args = []

    return args

@pipe
def select(req, *opts):
    """
Select a set of EntityDescriptor elements as the working document.

:param req: The request
:param opts: Options - used for select alias
:return: returns the result of the operation as a working document

Select picks and expands elements (with optional filtering) from the active repository you setup using calls
to :py:mod:`pyff.pipes.builtins.load`. See :py:mod:`pyff.mdrepo.MDRepository.lookup` for a description of the syntax for
selectors.

**Examples**

.. code-block:: yaml

    - select

This would select all entities in the active repository.

.. code-block:: yaml

    - select: "/var/local-metadata"

This would select all entities found in the directory /var/local-metadata. You must have a call to local to load
entities from this directory before select statement.

.. code-block:: yaml

    - select: "/var/local-metadata!//md:EntityDescriptor[md:IDPSSODescriptor]"

This would selects all IdPs from /var/local-metadata

.. code-block:: yaml

    - select: "!//md:EntityDescriptor[md:SPSSODescriptor]"

This would select all SPs

Select statements are not cumulative - a select followed by another select in the plumbing resets the
working douments to the result of the second select.

Most statements except local and remote depend on having a select somewhere in your plumbing and will
stop the plumbing if the current working document is empty. For instance, running

.. code-block:: yaml

    - select: "!//md:EntityDescriptor[md:SPSSODescriptor]"

would terminate the plumbing at select if there are no SPs in the local repository. This is useful in
combination with fork for handling multiple cases in your plumbings.

The 'as' keyword allows a select to be stored as an alias in the local repository. For instance

.. code-block:: yaml

    - select as foo-2.0: "!//md:EntityDescriptor[md:IDPSSODescriptor]""

would allow you to use /foo-2.0.json to refer to the JSON-version of all IdPs in the current repository.
Note that you should not include an extension in your "as foo-bla-something" since that would make your
alias invisible for anything except the corresponding mime type.
    """
    args = _select_args(req)
    name = req.plumbing.id
    alias = False
    if len(opts) > 0:
        if opts[0] != 'as' and len(opts) == 1:
            name = opts[0]
            alias = True
        if opts[0] == 'as' and len(opts) == 2:
            name = opts[1]
            alias = True

    ot = req.md.entity_set(args, name)
    if ot is None:
        raise PipeException("empty select - stop")

    if alias:
        req.md.import_metadata(ot, name)

    return ot

@pipe
def pick(req, *opts):
    """
Select a set of EntityDescriptor elements as a working document but don't validate it.

:param req: The request
:param opts: Options (unused)
:return: returns the result of the operation as a working document

Useful for testing. See py:mod:`pyff.pipes.builtins.pick` for more information about selecting the document.
    """
    args = _select_args(req)
    ot = req.md.entity_set(args, req.plumbing.id, validate=False)
    if ot is None:
        raise PipeException("empty select '%s' - stop" % ",".join(args))
    return ot

@pipe
def first(req, *opts):
    """
If the working document is a single EntityDescriptor, strip the outer EntitiesDescriptor element and return it.

:param req: The request
:param opts: Options (unused)
:return: returns the first entity descriptor if the working document only contains one

Sometimes (eg when running an MDX pipeline) it is usually expected that if a single EntityDescriptor is being returned
then the outer EntitiesDescriptor is stripped. This method does exactly that:
    """
    if req.t is None:
        raise PipeException("Your pipeline is missing a select statement.")

    gone = object()  # sentinel
    entities = iter_entities(req.t)
    one = next(entities, gone)
    if one is gone:
        return req.t  # empty tree - return it as is

    two = next(entities, gone)  # one EntityDescriptor in tree - return just that one
    if two is gone:
        return one

    return req.t

@pipe
def sign(req, *opts):
    """
Sign the working document.

:param req: The request
:param opts: Options (unused)
:return: returns the signed working document

Sign expects a single dict with at least a 'key' key and optionally a 'cert' key. The 'key' argument references
either a PKCS#11 uri or the filename containing a PEM-encoded non-password protected private RSA key.
The 'cert' argument may be empty in which case the cert is looked up using the PKCS#11 token, or may point
to a file containing a PEM-encoded X.509 certificate.

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
        raise PipeException("Your pipeline is missing a select statement.")

    if not type(req.args) is dict:
        raise PipeException("Missing key and cert arguments to sign pipe")

    key_file = req.args.get('key', None)
    cert_file = req.args.get('cert', None)

    if key_file is None:
        raise PipeException("Missing key argument for sign pipe")

    if cert_file is None:
        log.info("Attempting to extract certificate from token...")

    opts = dict()
    relt = root(req.t)
    idattr = relt.get('ID')
    if idattr:
        opts['reference_uri'] = "#%s" % idattr
    xmlsec.sign(req.t, key_file, cert_file, **opts)

    return req.t


@pipe
def stats(req, *opts):
    """
Display statistics about the current working document.

:param req: The request
:param opts: Options (unused)
:return: always returns the unmodified working document

**Examples**

.. code-block:: yaml

    - stats

    """
    print "---"
    print "total size:     %d" % req.md.store.size()
    if not hasattr(req.t, 'xpath'):
        raise PipeException("Unable to call stats on non-XML")

    if req.t is not None:
        print "selected:       %d" % len(req.t.xpath("//md:EntityDescriptor", namespaces=NS))
        print "          idps: %d" % len(req.t.xpath("//md:EntityDescriptor[md:IDPSSODescriptor]", namespaces=NS))
        print "           sps: %d" % len(req.t.xpath("//md:EntityDescriptor[md:SPSSODescriptor]", namespaces=NS))
    print "---"
    return req.t

@pipe
def store(req, *opts):
    """
Save the working document as separate files

:param req: The request
:param opts: Options (unused)
:return: always returns the unmodified working document
    
Split the working document into EntityDescriptor-parts and save in directory/sha1(@entityID).xml. Note that
this does not erase files that may already be in the directory. If you want a "clean" directory, remove it
before you call store.
    """
    if req.t is None:
        raise PipeException("Your pipeline is missing a select statement.")

    if not req.args:
        raise PipeException("store requires an argument")

    target_dir = None
    if type(req.args) is dict:
        target_dir = req.args.get('directory', None)
    else:
        target_dir = req.args[0]

    if target_dir is not None:
        if not os.path.isdir(target_dir):
            os.makedirs(target_dir)
        for e in iter_entities(req.t):
            eid = e.get('entityID')
            if eid is None or len(eid) == 0:
                raise PipeException("Missing entityID in %s" % e)
            m = hashlib.sha1()
            m.update(eid)
            d = m.hexdigest()
            safe_write("%s.xml" % os.path.join(target_dir, d), dumptree(e, pretty_print=True))
    return req.t

@pipe
def xslt(req, *opts):
    """
Transform the working document using an XSLT file.

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
    if req.t is None:
        raise PipeException("Your plumbing is missing a select statement.")

    stylesheet = req.args.get('stylesheet', None)
    if stylesheet is None:
        raise PipeException("xslt requires stylesheet")

    params = dict((k, "\'%s\'" % v) for (k, v) in req.args.items())
    del params['stylesheet']
    try:
        return xslt_transform(req.t, stylesheet, params)
        #log.debug(ot)
    except Exception, ex:
        traceback.print_exc(ex)
        raise ex

@pipe
def validate(req, *opts):
    """
Validate the working document

:param req: The request
:param opts: Not used
:return: The unmodified tree

Generate an exception unless the working tree validates. Validation is done automatically during publication and
loading of metadata so this call is seldom needed.
    """
    if req.t is not None:
        validate_document(req.t)

    return req.t

@pipe
def certreport(req, *opts):
    """
Generate a report of the certificates (optionally limited by expiration time or key size) found in the selection.

:param req: The request
:param opts: Options (not used)
:return: always returns the unmodified working document

**Examples**

.. code-block:: yaml

    - certreport:
         error_seconds: 0
         warning_seconds: 864000
         error_bits: 1024
         warning_bits: 2048

For key size checking this will report keys with a size *less* than the size specified, defaulting to errors
for keys smaller than 1024 bits and warnings for keys smaller than 2048 bits. It should be understood as the
minimum key size for each report level, as such everything below will create report entries.

Remember that you need a 'publish' or 'emit' call after certreport in your plumbing to get useful output. PyFF
ships with a couple of xslt transforms that are useful for turning metadata with certreport annotation into
HTML.
    """

    if req.t is None:
        raise PipeException("Your pipeline is missing a select statement.")

    if not req.args:
        req.args = {}

    if type(req.args) is not dict:
        raise PipeException("usage: certreport {warning: 864000, error: 0}")

    error_seconds = int(req.args.get('error_seconds', "0"))
    warning_seconds = int(req.args.get('warning_seconds', "864000"))
    error_bits = int(req.args.get('error_bits', "1024"))
    warning_bits = int(req.args.get('warning_bits', "2048"))

    seen = {}
    for eid in req.t.xpath("//md:EntityDescriptor/@entityID",
                           namespaces=NS,
                           smart_strings=False):
        for cd in req.t.xpath("md:EntityDescriptor[@entityID='%s']//ds:X509Certificate" % eid,
                              namespaces=NS,
                              smart_strings=False):
            try:
                cert_pem = cd.text
                cert_der = base64.b64decode(cert_pem)
                m = hashlib.sha1()
                m.update(cert_der)
                fp = m.hexdigest()
                if not seen.get(fp, False):
                    seen[fp] = True
                    cdict = xmlsec.utils.b642cert(cert_pem)
                    keysize = cdict['modulus'].bit_length()
                    cert = cdict['cert']
                    if keysize < error_bits:
                        e = cd.getparent().getparent().getparent().getparent().getparent()
                        req.md.annotate(e,
                                        "certificate-error",
                                        "keysize too small",
                                        "%s has keysize of %s bits (less than %s)" % (cert.getSubject(),
                                                                                      keysize,
                                                                                      error_bits))
                        log.error("%s has keysize of %s" % (eid, keysize))
                    elif keysize < warning_bits:
                        e = cd.getparent().getparent().getparent().getparent().getparent()
                        req.md.annotate(e,
                                        "certificate-warning",
                                        "keysize small",
                                        "%s has keysize of %s bits (less than %s)" % (cert.getSubject(),
                                                                                      keysize,
                                                                                      warning_bits))
                        log.warn("%s has keysize of %s" % (eid, keysize))
                    et = datetime.strptime("%s" % cert.getNotAfter(), "%y%m%d%H%M%SZ")
                    now = datetime.now()
                    dt = et - now
                    if total_seconds(dt) < error_seconds:
                        e = cd.getparent().getparent().getparent().getparent().getparent()
                        req.md.annotate(e,
                                        "certificate-error",
                                        "certificate has expired",
                                        "%s expired %s ago" % (cert.getSubject(), -dt))
                        log.error("%s expired %s ago" % (eid, -dt))
                    elif total_seconds(dt) < warning_seconds:
                        e = cd.getparent().getparent().getparent().getparent().getparent()
                        req.md.annotate(e,
                                        "certificate-warning",
                                        "certificate about to expire",
                                        "%s expires in %s" % (cert.getSubject(), dt))
                        log.warn("%s expires in %s" % (eid, dt))
            except Exception, ex:
                log.error(ex)

@pipe
def emit(req, ctype="application/xml", *opts):
    """
Returns a UTF-8 encoded representation of the working tree.

:param req: The request
:param ctype: The mimetype of the response.
:param opts: Options (not used)
:return: unicode data

Renders the working tree as text and sets the digest of the tree as the ETag. If the tree has already been rendered as
text by an earlier step the text is returned as utf-8 encoded unicode. The mimetype (ctype) will be set in the
Content-Type HTTP response header.

**Examples**

.. code-block:: yaml

    - emit application/xml:
    - break
    """
    if req.t is None:
        raise PipeException("Your pipeline is missing a select statement.")

    d = req.t
    if hasattr(d, 'getroot') and hasattr(d.getroot, '__call__'):
        nd = d.getroot()
        if nd is None:
            d = str(d)
        else:
            d = nd

    if hasattr(d, 'tag'):
        d = dumptree(d)

    if d is not None:
        m = hashlib.sha1()
        m.update(d)
        req.state['headers']['ETag'] = m.hexdigest()
    else:
        raise PipeException("Empty")

    req.state['headers']['Content-Type'] = ctype
    return unicode(d.decode('utf-8')).encode("utf-8")

@pipe
def signcerts(req, *opts):
    """
Logs the fingerprints of the signing certs found in the current working tree.

:param req: The request
:param opts: Options (not used)
:return: always returns the unmodified working document

Useful for testing.

**Examples**

.. code-block:: yaml

    - signcerts
    """
    if req.t is None:
        raise PipeException("Your pipeline is missing a select statement.")

    for fp, pem in xmlsec.CertDict(req.t).iteritems():
        log.info("found signing cert with fingerprint %s" % fp)
    return req.t

@pipe
def finalize(req, *opts):
    """
Prepares the working document for publication/rendering.

:param req: The request
:param opts: Options (not used)
:return: returns the working document with @Name, @cacheDuration and @validUntil set

Set Name, ID, cacheDuration and validUntil on the toplevel EntitiesDescriptor element of the working document. Unless
explicit provided the @Name is set from the request URI if the pipeline is executed in the pyFF server. The @ID is set
to a string representing the current date/time and will be prefixed with the string provided, which defaults to '_'. The
@cacheDuration element must be a valid xsd duration (eg PT5H for 5 hrs) and @validUntil can be either an absolute
ISO 8601 time string or (more comonly) a relative time on the form

.. code-block:: none

    \+?([0-9]+d)?\s*([0-9]+h)?\s*([0-9]+m)?\s*([0-9]+s)?


For instance +45d 2m results in a time delta of 45 days and 2 minutes. The '+' sign is optional.

If operating on a single EntityDescriptor then @Name is ignored (cf :py:mod:`pyff.pipes.builtins.first`).

**Examples**

.. code-block:: yaml

    - finalize:
        cacheDuration: PT8H
        validUntil: +10d
        ID: pyff
    """
    if req.t is None:
        raise PipeException("Your plumbing is missing a select statement.")

    e = root(req.t)
    if e.tag == "{%s}EntitiesDescriptor" % NS['md']:
        name = req.args.get('name', None)
        if name is None or not len(name):
            name = req.args.get('Name', None)
        if name is None or not len(name):
            name = req.state.get('url', None)
        if name is None or not len(name):
            name = e.get('Name', None)
        if name is not None and len(name):
            e.set('Name', name)

    now = datetime.utcnow()

    idprefix = req.args.get('ID', '_')
    if not e.get('ID'):
        e.set('ID', now.strftime(idprefix + "%Y%m%dT%H%M%SZ"))

    valid_until = str(req.args.get('validUntil', e.get('validUntil', None)))
    if valid_until is not None and len(valid_until) > 0:
        offset = duration2timedelta(valid_until)
        if offset is not None:
            dt = now + offset
            e.set('validUntil', dt.strftime("%Y-%m-%dT%H:%M:%SZ"))
        elif valid_until is not None:
            try:
                dt = iso8601.parse_date(valid_until)
                dt = dt.replace(tzinfo=None) # make dt "naive" (tz-unaware)
                offset = dt - now
                e.set('validUntil', dt.strftime("%Y-%m-%dT%H:%M:%SZ"))
            except ValueError, ex:
                log.error("Unable to parse validUntil: %s (%s)" % (valid_until, ex))

            # set a reasonable default: 50% of the validity
        # we replace this below if we have cacheDuration set
        req.state['cache'] = int(total_seconds(offset) / 50)

    cache_duration = req.args.get('cacheDuration', e.get('cacheDuration', None))
    if cache_duration is not None and len(cache_duration) > 0:
        offset = duration2timedelta(cache_duration)
        if offset is None:
            raise PipeException("Unable to parse %s as xs:duration" % cache_duration)

        e.set('cacheDuration', cache_duration)
        req.state['cache'] = int(total_seconds(offset))

    return req.t

@pipe(name='setattr')
def _setattr(req, *opts):
    """
Sets entity attributes on the working document

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
    if req.t is None:
        raise PipeException("Your pipeline is missing a select statement.")

    for e in iter_entities(req.t):
        #log.debug("setting %s on %s" % (req.args,e.get('entityID')))
        req.md.set_entity_attributes(e, req.args)
