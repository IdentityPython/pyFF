"""
These are the built-in "pipes" - functions that can be used to put together a processing pipeling for pyFF.
"""

import base64
import hashlib
import json
import sys
import traceback
from copy import deepcopy
from datetime import datetime
from distutils.util import strtobool
import operator
import os
import re
import xmlsec
from iso8601 import iso8601
from lxml.etree import DocumentInvalid
from .constants import NS
from .decorators import deprecated
from .logs import get_log
from .pipes import Plumbing, PipeException, PipelineCallback, pipe
from .utils import total_seconds, dumptree, safe_write, root, with_tree, duration2timedelta, xslt_transform, \
    validate_document, hash_id
from .samlmd import sort_entities, iter_entities, annotate_entity, set_entity_attributes, \
    discojson_t, set_pubinfo, set_reginfo, find_in_document, entitiesdescriptor, set_nodecountry, resolve_entities
from six.moves.urllib_parse import urlparse
from .exceptions import MetadataException
import six
import ipaddr
from pyff.pipes import registry


__author__ = 'leifj'

FILESPEC_REGEX = "([^ \t\n\r\f\v]+)\s+as\s+([^ \t\n\r\f\v]+)"
log = get_log(__name__)


@pipe
def dump(req, *opts):
    """
    Print a representation of the entities set on stdout. Useful for testing.

    :param req: The request
    :param opts: Options (unused)
    :return: None

    """
    if req.t is not None:
        print(dumptree(req.t))
    else:
        print("<EntitiesDescriptor xmlns=\"{}\"/>".format(NS['md']))


@pipe(name="print")
def _print_t(req, *opts):
    """

    Print whatever is in the active tree without transformation

    :param req: The request
    :param opts: Options (unused)
    :return: None

    """
    fn = req.args.get('output', None)
    if fn is not None:
        safe_write(fn, req.t)
    else:
        print(req.t)

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
            print(msg)
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
    document in the parent document (using the entityID as a pointer). Any python module path ('a.mod.u.le:callable')
    ending in a callable is accepted. If the path doesn't contain a ':' then it is assumed to reference one of the
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
    ireq = Plumbing.Request(ip, req.md, t=nt, scheduler=req.scheduler)
    ip.iprocess(ireq)

    if req.t is not None and ireq.t is not None and len(root(ireq.t)) > 0:
        if 'merge' in opts:
            sn = "pyff.merge_strategies:replace_existing"
            if opts[-1] != 'merge':
                sn = opts[-1]
            req.md.store.merge(req.t, ireq.t, strategy_name=sn)

    return req.t


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
    ot = Plumbing(pipeline=req.args, pid="%s.pipe" % req.plumbing.id).iprocess(req)
    req.done = False
    return ot


@pipe
def when(req, condition, *values):
    """
    Conditionally execute part of the pipeline.

    :param req: The request
    :param condition: The condition key
    :param values: The condition values
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
    c = req.state.get(condition, None)
    if c is not None and (not values or _any(values, c)):
        return Plumbing(pipeline=req.args, pid="%s.when" % req.plumbing.id).iprocess(req)
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
        print(e.get('entityID'))
    return req.t


@pipe
def sort(req, *opts):
    """
    Sorts the working entities by the value returned by the given xpath.
    By default, entities are sorted by 'entityID' when the 'order_by [xpath]' option is omitted and
    otherwise as second criteria.
    Entities where no value exists for a given xpath are sorted last.

    :param req: The request
    :param opts: Options: <order_by [xpath]> (see bellow)
    :return: None

    Options are put directly after "sort". E.g:

    .. code-block:: yaml

        - sort order_by [xpath]

    **Options**
    - order_by [xpath] : xpath expression selecting to the value used for sorting the entities.
    """
    if req.t is None:
        raise PipeException("Unable to sort empty document.")

    opts = dict(list(zip(opts[0:1], [" ".join(opts[1:])])))
    opts.setdefault('order_by', None)
    sort_entities(req.t, opts['order_by'])

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
    except DocumentInvalid as ex:
        log.error(ex.error_log)
        raise PipeException("XML schema validation failed")

    output_file = None
    if type(req.args) is dict:
        output_file = req.args.get("output", None)
    else:
        output_file = req.args[0]
    if output_file is not None:
        output_file = output_file.strip()
        resource_name = output_file
        m = re.match(FILESPEC_REGEX, output_file)
        if m:
            output_file = m.group(1)
            resource_name = m.group(2)
        out = output_file
        if os.path.isdir(output_file):
            out = "{}.xml".format(os.path.join(output_file, req.id))

        data = dumptree(req.t)

        safe_write(out, data)
        req.store.update(req.t, tid=resource_name)  # TODO maybe this is not the right thing to do anymore
    return req.t


@pipe
@deprecated(reason="stats subsystem was removed")
def loadstats(req, *opts):
    """
    Log (INFO) information about the result of the last call to load

    :param req: The request
    :param opts: Options: (none)
    :return: None

    """
    log.info("pyff loadstats has been deprecated")


@pipe
@deprecated(reason="replaced with load")
def remote(req, *opts):
    """
    Deprecated. Calls :py:mod:`pyff.pipes.builtins.load`.
    """
    return load(req, opts)


@pipe
@deprecated(reason="replaced with load")
def local(req, *opts):
    """
    Deprecated. Calls :py:mod:`pyff.pipes.builtins.load`.
    """
    return load(req, opts)


@pipe
@deprecated(reason="replaced with load")
def _fetch(req, *opts):
    return load(req, *opts)


@pipe
def load(req, *opts):
    """
    General-purpose resource fetcher.

        :param req: The request
        :param opts: Options: See "Options" below
        :return: None

    Supports both remote and local resources. Fetching remote resources is done in parallel using threads.

    Note: When downloading remote files over HTTPS the TLS server certificate is not validated.
    Note: Default behaviour is to ignore metadata files or entities in MD files that cannot be loaded

    Options are put directly after "load". E.g:

    .. code-block:: yaml

        - load fail_on_error True filter_invalid False:
          - http://example.com/some_remote_metadata.xml
          - local_file.xml
          - /opt/directory_containing_md_files/

    **Options**
    Defaults are marked with (*)
    - max_workers <5> : Number of parallel threads to use for loading MD files
    - timeout <120> : Socket timeout when downloading files
    - validate <True*|False> : When true downloaded metadata files are validated (schema validation)
    - fail_on_error <True|False*> : Control whether an error during download, parsing or (optional)validatation of a MD file
                                    does not abort processing of the pipeline. When true a failure aborts and causes pyff
                                    to exit with a non zero exit code. Otherwise errors are logged but ignored.
    - filter_invalid <True*|False> : Controls validation behaviour. When true Entities that fail validation are filtered
                                     I.e. are not loaded. When false the entire metadata file is either loaded, or not.
                                     fail_on_error controls whether failure to validating the entire MD file will abort
                                     processing of the pipeline.
    """
    opts = dict(list(zip(opts[::2], opts[1::2])))
    opts.setdefault('timeout', 120)
    opts.setdefault('max_workers', 5)
    opts.setdefault('validate', "True")
    opts.setdefault('fail_on_error', "False")
    opts.setdefault('filter_invalid', "True")
    opts['validate'] = bool(strtobool(opts['validate']))
    opts['fail_on_error'] = bool(strtobool(opts['fail_on_error']))
    opts['filter_invalid'] = bool(strtobool(opts['filter_invalid']))

    remotes = []
    for x in req.args:
        x = x.strip()
        log.debug("load parsing '%s'" % x)
        r = x.split()

        assert len(r) in range(1, 8), PipeException(
            "Usage: load resource [as url] [[verify] verification] [via pipeline] [cleanup pipeline]")

        url = r.pop(0)
        params = {"via": [], "cleanup": [], "verify": None, "as": url}

        while len(r) > 0:
            elt = r.pop(0)
            if elt in ("as", "verify", "via", "cleanup"):
                if len(r) > 0:
                    if elt in ("via", "cleanup"):
                        params[elt].append(r.pop(0))
                    else:
                        params[elt] = r.pop(0)
                else:
                    raise PipeException(
                        "Usage: load resource [as url] [[verify] verification] [via pipeline]* [cleanup pipeline]*")
            else:
                params['verify'] = elt

        if params['via'] is not None:
            params['via'] = [PipelineCallback(pipe, req, store=req.md.store) for pipe in params['via']]

        if params['cleanup'] is not None:
            params['cleanup'] = [PipelineCallback(pipe, req, store=req.md.store) for pipe in params['cleanup']]

        params.update(opts)

        req.md.rm.add_child(url, **params)

    log.debug("Refreshing all resources")
    req.md.rm.reload(fail_on_error=bool(opts['fail_on_error']))


def _select_args(req):
    args = req.args
    if args is None and 'select' in req.state:
        args = [req.state.get('select')]
    if args is None:
        args = req.store.collections()
    if args is None or not args:
        args = req.store.lookup('entities')
    if args is None or not args:
        args = []

    log.debug("selecting using args: %s" % args)

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

        - select as /foo-2.0: "!//md:EntityDescriptor[md:IDPSSODescriptor]"

    would allow you to use /foo-2.0.json to refer to the JSON-version of all IdPs in the current repository.
    Note that you should not include an extension in your "as foo-bla-something" since that would make your
    alias invisible for anything except the corresponding mime type.
    """
    args = _select_args(req)
    name = req.plumbing.id
    if len(opts) > 0:
        if opts[0] != 'as' and len(opts) == 1:
            name = opts[0]
        if opts[0] == 'as' and len(opts) == 2:
            name = opts[1]

    entities = resolve_entities(args, lookup_fn=req.md.store.select)

    if req.state.get('match', None):  # TODO - allow this to be passed in via normal arguments

        match = req.state['match']

        if isinstance(match, six.string_types):
            query = [match.lower()]

        def _strings(elt):
            lst = []
            for attr in ['{%s}DisplayName' % NS['mdui'],
                         '{%s}ServiceName' % NS['md'],
                         '{%s}OrganizationDisplayName' % NS['md'],
                         '{%s}OrganizationName' % NS['md'],
                         '{%s}Keywords' % NS['mdui'],
                         '{%s}Scope' % NS['shibmd']]:
                lst.extend([s.text for s in elt.iter(attr)])
            lst.append(elt.get('entityID'))
            return [item for item in lst if item is not None]

        def _ip_networks(elt):
            return [ipaddr.IPNetwork(x.text) for x in elt.iter('{%s}IPHint' % NS['mdui'])]

        def _match(q, elt):
            q = q.strip()
            if ':' in q or '.' in q:
                try:
                    nets = _ip_networks(elt)
                    for net in nets:
                        if ':' in q and ipaddr.IPv6Address(q) in net:
                            return net
                        if '.' in q and ipaddr.IPv4Address(q) in net:
                            return net
                except ValueError:
                    pass

            if q is not None and len(q) > 0:
                tokens = _strings(elt)
                for tstr in tokens:
                    for tpart in tstr.split():
                        if tpart.lower().startswith(q):
                            return tstr
            return None

        log.debug("matching {} in {} entities".format(match, len(entities)))
        entities = list(filter(lambda e: _match(match, e) is not None, entities))
        log.debug("returning {} entities after match".format(len(entities)))

    ot = entitiesdescriptor(entities, name)
    if ot is None:
        raise PipeException("empty select - stop")

    if req.plumbing.id != name:
        log.debug("storing synthentic collection {}".format(name))
        req.store.update(ot, name)

    return ot


@pipe(name="filter")
def _filter(req, *opts):
    """

    Refines the working document by applying a filter. The filter expression is a subset of the
    select semantics and syntax:

    .. code-block:: yaml

        - filter:
            - "!//md:EntityDescriptor[md:SPSSODescriptor]"
            - "https://idp.example.com/shibboleth"

    This would select all SPs and any entity with entityID "https://idp.example.com/shibboleth"
    from the current working document and return as the new working document. Filter also supports
    the "as <alias>" construction from select allowing new synthetic collections to be created
    from filtered documents.

    """

    if req.t is None:
        raise PipeException("Unable to filter on an empty document - use select first")

    alias = False
    if len(opts) > 0:
        if opts[0] != 'as' and len(opts) == 1:
            name = opts[0]
            alias = True
        if opts[0] == 'as' and len(opts) == 2:
            name = opts[1]
            alias = True

    name = req.plumbing.id
    args = req.args
    if args is None or not args:
        args = []

    ot = entitiesdescriptor(args, name, lookup_fn=lambda member: find_in_document(req.t, member), copy=False)
    if alias:
        req.store.update(ot, name)

    req.t = None

    if ot is None:
        raise PipeException("empty filter - stop")

    # print "filter returns %s" % [e for e in iter_entities(ot)]
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
    ot = entitiesdescriptor(args, req.plumbing.id, lookup_fn=req.md.store.lookup, validate=False)
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


@pipe(name='discojson')
def _discojson(req, *opts):
    """

    Return a discojuice-compatible json representation of the tree

    .. code-block:: yaml
      discojson:

    If the config.load_icons directive is set the icons will be returned from a (possibly persistent) local
    cache & converted to data: URIs

    :param req: The request
    :param opts: Options (unusued)
    :return: returns a JSON array

    """

    if req.t is None:
        raise PipeException("Your pipeline is missing a select statement.")

    res = discojson_t(req.t, icon_store=req.md.icon_store)
    res.sort(key=operator.itemgetter('title'))

    return json.dumps(res)


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
    if req.t is None:
        raise PipeException("Your pipeline is missing a select statement.")

    print("---")
    print("total size:     {:d}".format(req.store.size()))
    if not hasattr(req.t, 'xpath'):
        raise PipeException("Unable to call stats on non-XML")

    if req.t is not None:
        print("selected:       {:d}".format(len(req.t.xpath("//md:EntityDescriptor", namespaces=NS))))
        print("          idps: {:d}".format(
            len(req.t.xpath("//md:EntityDescriptor[md:IDPSSODescriptor]", namespaces=NS))))
        print(
            "           sps: {:d}".format(len(req.t.xpath("//md:EntityDescriptor[md:SPSSODescriptor]", namespaces=NS))))
    print("---")
    return req.t


@pipe
def summary(req, *opts):
    """

    Display a summary of the repository
    :param req:
    :param opts:
    :return:

    """
    if req.t is None:
        raise PipeException("Your pipeline is missing a select statement.")

    return dict(size=req.store.size())


@pipe(name='store')
def _store(req, *opts):
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
            fn = hash_id(e, prefix=False)
            safe_write("%s.xml" % os.path.join(target_dir, fn), dumptree(e, pretty_print=True))
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

    params = dict((k, "\'%s\'" % v) for (k, v) in list(req.args.items()))
    del params['stylesheet']
    try:
        return xslt_transform(req.t, stylesheet, params)
    except Exception as ex:
        log.debug(traceback.format_exc())
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
def prune(req, *opts):
    """

    Prune the active tree, removing all elements matching

    :param req: The request
    :param opts: Not used
    :return: The tree with all specified elements removed


    ** Examples**
    .. code-block:: yaml

        - prune:
            - .//{http://www.w3.org/2000/09/xmldsig#}Signature

    This example would drop all Signature elements. Note the use of namespaces.

    .. code-block:: yaml

        - prune:
            - .//{http://www.w3.org/2000/09/xmldsig#}Signature[1]

    This example would drop the first Signature element only.

    """

    if req.t is None:
        raise PipeException("Your pipeline is missing a select statement.")

    for path in req.args:
        for part in req.t.iterfind(path):
            parent = part.getparent()
            if parent is not None:
                parent.remove(part)
            else:  # we just removed the top-level element - return empty tree
                return None

    return req.t


@pipe
def check_xml_namespaces(req, *opts):
    """

    :param req: The request
    :param opts: Options (not used)
    :return: always returns the unmodified working document or throws an exception if checks fail

    """
    if req.t is None:
        raise PipeException("Your pipeline is missing a select statement.")

    def _verify(elt):
        if isinstance(elt.tag, six.string_types):
            for prefix, uri in list(elt.nsmap.items()):
                if not uri.startswith('urn:'):
                    u = urlparse(uri)
                    if u.scheme not in ('http', 'https'):
                        raise MetadataException(
                            "Namespace URIs must be be http(s) URIs ('{}' declared on {})".format(uri, elt.tag))

    with_tree(root(req.t), _verify)
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
                    entity_elt = cd.getparent().getparent().getparent().getparent().getparent()
                    seen[fp] = True
                    cdict = xmlsec.utils.b642cert(cert_pem)
                    keysize = cdict['modulus'].bit_length()
                    cert = cdict['cert']
                    if keysize < error_bits:
                        annotate_entity(entity_elt,
                                        "certificate-error",
                                        "keysize too small",
                                        "%s has keysize of %s bits (less than %s)" % (cert.getSubject(),
                                                                                      keysize,
                                                                                      error_bits))
                        log.error("%s has keysize of %s" % (eid, keysize))
                    elif keysize < warning_bits:
                        annotate_entity(entity_elt,
                                        "certificate-warning",
                                        "keysize small",
                                        "%s has keysize of %s bits (less than %s)" % (cert.getSubject(),
                                                                                      keysize,
                                                                                      warning_bits))
                        log.warn("%s has keysize of %s" % (eid, keysize))

                    notafter = cert.getNotAfter()
                    if notafter is None:
                        annotate_entity(entity_elt,
                                        "certificate-error",
                                        "certificate has no expiration time",
                                        "%s has no expiration time" % cert.getSubject())
                    else:
                        try:
                            et = datetime.strptime("%s" % notafter, "%y%m%d%H%M%SZ")
                            now = datetime.now()
                            dt = et - now
                            if total_seconds(dt) < error_seconds:
                                annotate_entity(entity_elt,
                                                "certificate-error",
                                                "certificate has expired",
                                                "%s expired %s ago" % (cert.getSubject(), -dt))
                                log.error("%s expired %s ago" % (eid, -dt))
                            elif total_seconds(dt) < warning_seconds:
                                annotate_entity(entity_elt,
                                                "certificate-warning",
                                                "certificate about to expire",
                                                "%s expires in %s" % (cert.getSubject(), dt))
                                log.warn("%s expires in %s" % (eid, dt))
                        except ValueError as ex:
                            annotate_entity(entity_elt,
                                            "certificate-error",
                                            "certificate has unknown expiration time",
                                            "%s unknown expiration time %s" % (cert.getSubject(), notafter))

                    req.store.update(entity_elt)
            except Exception as ex:
                log.debug(traceback.format_exc())
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
        if not isinstance(d, six.binary_type):
            d = d.encode("utf-8")
        m.update(d)
        req.state['headers']['ETag'] = m.hexdigest()
    else:
        raise PipeException("Empty")

    req.state['headers']['Content-Type'] = ctype
    if six.PY2:
        d = six.u(d)
    return d


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

    for fp, pem in list(xmlsec.crypto.CertDict(req.t).items()):
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
        if name is None or 0 == len(name):
            name = req.args.get('Name', None)
        if name is None or 0 == len(name):
            name = req.state.get('url', None)
            if name and 'baseURL' in req.args:

                try:
                    name_url = urlparse(name)
                    base_url = urlparse(req.args.get('baseURL'))
                    name = "{}://{}{}".format(base_url.scheme, base_url.netloc, name_url.path)
                    log.debug("-------- using Name: %s" % name)
                except ValueError as ex:
                    log.debug(ex)
                    name = None
        if name is None or 0 == len(name):
            name = e.get('Name', None)

        if name:
            e.set('Name', name)

    now = datetime.utcnow()

    mdid = req.args.get('ID', 'prefix _')
    if re.match('(\s)*prefix(\s)*', mdid):
        prefix = re.sub('^(\s)*prefix(\s)*', '', mdid)
        _id = now.strftime(prefix + "%Y%m%dT%H%M%SZ")
    else:
        _id = mdid

    if not e.get('ID'):
        e.set('ID', _id)

    valid_until = str(req.args.get('validUntil', e.get('validUntil', None)))
    if valid_until is not None and len(valid_until) > 0:
        offset = duration2timedelta(valid_until)
        if offset is not None:
            dt = now + offset
            e.set('validUntil', dt.strftime("%Y-%m-%dT%H:%M:%SZ"))
        elif valid_until is not None:
            try:
                dt = iso8601.parse_date(valid_until)
                dt = dt.replace(tzinfo=None)  # make dt "naive" (tz-unaware)
                offset = dt - now
                e.set('validUntil', dt.strftime("%Y-%m-%dT%H:%M:%SZ"))
            except ValueError as ex:
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


@pipe(name='reginfo')
def _reginfo(req, *opts):
    """

    Sets registration info extension on EntityDescription element

    :param req: The request
    :param opts: Options (not used)
    :return: A modified working document

    Transforms the working document by setting the specified attribute on all of the EntityDescriptor
    elements of the active document.

    **Examples**

    .. code-block:: yaml

        - reginfo:
           [policy:
                <lang>: <registration policy URL>]
           authority: <registrationAuthority URL>

    """
    if req.t is None:
        raise PipeException("Your pipeline is missing a select statement.")

    for e in iter_entities(req.t):
        set_reginfo(e, **req.args)

    return req.t


@pipe(name='pubinfo')
def _pubinfo(req, *opts):
    """

    Sets publication info extension on EntityDescription element

    :param req: The request
    :param opts: Options (not used)
    :return: A modified working document

    Transforms the working document by setting the specified attribute on all of the EntityDescriptor
    elements of the active document.

    **Examples**

    .. code-block:: yaml

        - pubinfo:
           publisher: <publisher URL>

    """
    if req.t is None:
        raise PipeException("Your pipeline is missing a select statement.")

    set_pubinfo(root(req.t), **req.args)

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
        # log.debug("setting %s on %s" % (req.args,e.get('entityID')))
        set_entity_attributes(e, req.args)
        req.store.update(e)

    return req.t


@pipe(name='nodecountry')
def _nodecountry(req, *opts):
    """

    Sets eidas:NodeCountry

    :param req: The request
    :param opts: Options (not used)
    :return: A modified working document

    Transforms the working document by setting NodeCountry

    **Examples**

    .. code-block:: yaml

        - nodecountry:
            country: XX

    Normally this would be combined with the 'merge' feature of fork or in a cleanup pipline to add attributes to
    the working document for later processing.

    """
    if req.t is None:
        raise PipeException("Your pipeline is missing a select statement.")

    for e in iter_entities(req.t):
        if req.args is not None and 'country' in req.args:
            set_nodecountry(e, country_code=req.args['country'])
            req.store.update(e)
        else:
            log.error("No country found in arguments to nodecountry")

    return req.t


__all__ = [fn.__name__ for fn in registry.values()]