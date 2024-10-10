"""
These are the built-in "pipes" - functions that can be used to put together a processing pipeling for pyFF.
"""

import base64
import hashlib
import json
import operator
import os
import re
import sys
import traceback
from copy import deepcopy
from datetime import datetime
from io import BytesIO
from str2bool import str2bool
from typing import Dict, Optional

import ipaddress
import six
import xmlsec
from lxml import etree
from lxml.etree import DocumentInvalid
from six.moves.urllib_parse import quote_plus, urlparse

from pyff.constants import NS
from pyff.decorators import deprecated
from pyff.exceptions import MetadataException
from pyff.logs import get_log
from pyff.pipes import PipeException, PipelineCallback, Plumbing, pipe, registry
from pyff.samlmd import (
    annotate_entity,
    discojson_sp_t,
    discojson_sp_attr_t,
    discojson_t,
    entitiesdescriptor,
    find_in_document,
    iter_entities,
    resolve_entities,
    set_entity_attributes,
    set_nodecountry,
    set_pubinfo,
    set_reginfo,
    sort_entities,
)
from pyff.utils import (
    datetime2iso,
    dumptree,
    duration2timedelta,
    hash_id,
    iso2datetime,
    parse_xml,
    root,
    safe_write,
    total_seconds,
    utc_now,
    validate_document,
    with_tree,
    xslt_transform,
)

__author__ = 'leifj'

FILESPEC_REGEX = r'([^ \t\n\r\f\v]+)\s+as\s+([^ \t\n\r\f\v]+)'
log = get_log(__name__)


@pipe
def dump(req: Plumbing.Request, *opts):
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


@pipe(name="map")
def _map(req: Plumbing.Request, *opts):
    """

    loop over the entities in a selection

    :param req:
    :param opts:
    :return: None

    **Examples**

    .. code-block:: yaml

        - map:
           - ...statements...

    Executes a set of statements in parallell (using a thread pool).

    """

    def _p(e):
        entity_id = e.get('entityID')
        ip = Plumbing(pipeline=req.args, pid="{}.each[{}]".format(req.plumbing.pid, entity_id))
        ireq = Plumbing.Request(ip, req.md, t=e, scheduler=req.scheduler)
        ireq.set_id(entity_id)
        ireq.set_parent(req)
        return ip.iprocess(ireq)

    from multiprocessing.pool import ThreadPool

    pool = ThreadPool()
    result = pool.map(_p, iter_entities(req.t), chunksize=10)
    log.info("processed {} entities".format(len(result)))


@pipe(name="then")
def _then(req: Plumbing.Request, *opts):
    """
    Call a named 'when' clause and return - akin to macro invocations for pyFF
    """
    for cb in [PipelineCallback(p, req, store=req.md.store) for p in opts]:
        req.t = cb(req.t)
    return req.t


@pipe(name="log_entity")
def _log_entity(req: Plumbing.Request, *opts):
    """
    log the request id as it is processed (typically the entity_id)
    """
    log.info(str(req.id))
    return req.t


@pipe(name="print")
def _print_t(req: Plumbing.Request, *opts):
    """

    Print whatever is in the active tree without transformation

    :param req: The request
    :param opts: Options (unused)
    :return: None

    **Examples**

    .. code-block:: yaml

        - print
           output: "somewhere.foo"

    """
    fn = None
    if isinstance(req.args, dict):
        fn = req.args.get('output', None)
    if fn is not None:
        safe_write(fn, req.t)
    else:
        print(req.t)


@pipe
def end(req: Plumbing.Request, *opts):
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
    if isinstance(req.args, dict):
        code = req.args.get('code', 0)
        msg = req.args.get('message', None)
        if msg is not None:
            print(msg)
    sys.exit(code)


@pipe
def fork(req: Plumbing.Request, *opts):
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

    **parsecopy**

    Due to a hard to find bug, fork which uses deepcopy can lose some namespaces. The parsecopy argument is a workaround.
    It uses a brute force serialisation and deserialisation to get around the bug. 

    .. code-block:: yaml

        - select  # select all entities
        - fork parsecopy:
            - certreport
            - publish:
                 output: "/tmp/annotated.xml"
        - fork:
            - xslt:
                 stylesheet: tidy.xml
            - publish:
                 output: "/tmp/clean.xml"
    """
    nt = None
    if req.t is not None:
        if 'parsecopy' in opts:
            nt = root(parse_xml(BytesIO(dumptree(req.t))))
        else:
            nt = deepcopy(req.t)

    if not isinstance(req.args, list):
        raise ValueError('Non-list arguments to "fork" not allowed')

    ip = Plumbing(pipeline=req.args, pid=f'{req.plumbing.pid}.fork')
    ireq = Plumbing.Request(ip, req.md, t=nt, scheduler=req.scheduler)
    ireq.set_id(req.id)
    ireq.set_parent(req)
    ip.iprocess(ireq)

    if req.t is not None and ireq.t is not None and len(root(ireq.t)) > 0:
        if 'merge' in opts:
            sn = "pyff.merge_strategies:replace_existing"
            if opts[-1] != 'merge':
                sn = opts[-1]
            req.md.store.merge(req.t, ireq.t, strategy_name=sn)

    return req.t


@deprecated(reason="any pipeline has been replace by other behaviour")
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
def _break(req: Plumbing.Request, *opts):
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
def _pipe(req: Plumbing.Request, *opts):
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
    if not isinstance(req.args, list):
        raise ValueError('Non-list arguments to "pipe" not allowed')

    ot = Plumbing(pipeline=req.args, pid=f'{req.plumbing.id}.pipe').iprocess(req)
    req.done = False
    return ot


@pipe
def when(req: Plumbing.Request, condition: str, *values):
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
    if c is None:
        log.debug(f'Condition {repr(condition)} not present in state {req.state}')
    if c is not None and (not values or _any(values, c)):
        if not isinstance(req.args, list):
            raise ValueError('Non-list arguments to "when" not allowed')

        return Plumbing(pipeline=req.args, pid="%s.when" % req.plumbing.id).iprocess(req)
    return req.t


@pipe
def info(req: Plumbing.Request, *opts):
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
def sort(req: Plumbing.Request, *opts):
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

    _opts: Dict[str, Optional[str]] = dict(list(zip(opts[0:1], [" ".join(opts[1:])])))
    if 'order_by' not in _opts:
        _opts['order_by'] = None
    sort_entities(req.t, _opts['order_by'])

    return req.t


@pipe
def publish(req: Plumbing.Request, *opts):
    """
    Publish the working document in XML form.

    :param req: The request
    :param opts: Options (unused)
    :return: None

     Publish takes one argument: path to a file where the document tree will be written.

    **Examples**

    .. code-block:: yaml

        - publish: /tmp/idp.xml

    The full set of options with their corresponding defaults:

    .. code-block:: yaml

        - publish:
             output: output
             raw: false
             pretty_print: false
             urlencode_filenames: false
             hash_link: false
             update_store: true
             ext: .xml

    If output is an existing directory, publish will write the working tree to a filename in the directory
    based on the @entityID or @Name attribute. Unless 'raw' is set to true the working tree will be serialized
    to a string before writing, with minimal formatting if 'pretty_print' is true (see 'indent' action for more
    extensive control). If true, 'hash_link' will generate a symlink based on the hash id (sha1) for
    compatibility with MDQ. Unless false, 'update_store' will cause the the current store to be updated with
    the published artifact. Setting 'ext' allows control over the file extension.
    """

    if req.t is None:
        raise PipeException("Empty document submitted for publication")

    if req.args is None:
        raise PipeException("Publish must at least specify output")

    if not isinstance(req.args, dict):
        req.args = dict(output=req.args[0])

    for t in ('raw', 'pretty_print', 'update_store', 'hash_link', 'urlencode_filenames'):
        if t in req.args and type(req.args[t]) is not bool:
            req.args[t] = str2bool(str(req.args[t]))

    req.args.setdefault('ext', '.xml')
    req.args.setdefault('output_file', 'output')
    req.args.setdefault('raw', False)
    req.args.setdefault('pretty_print', False)
    req.args.setdefault('update_store', True)
    req.args.setdefault('hash_link', False)
    req.args.setdefault('urlencode_filenames', False)

    output_file = req.args.get("output", None)

    if not req.args.get('raw'):
        try:
            validate_document(req.t)
        except DocumentInvalid as ex:
            log.error(ex.error_log)
            raise PipeException("XML schema validation failed")

    def _nop(x):
        return x

    enc = _nop
    if req.args.get('urlencode_filenames'):
        enc = quote_plus

    if output_file is not None:
        output_file = output_file.strip()
        resource_name = output_file
        m = re.match(FILESPEC_REGEX, output_file)
        if m:
            output_file = m.group(1)
            resource_name = m.group(2)
        out = output_file
        data = req.t
        if not req.args.get('raw'):
            data = dumptree(req.t, pretty_print=req.args.get('pretty_print'))

        if os.path.isdir(output_file):
            file_name = "{}{}".format(enc(req.id), req.args.get('ext'))
            out = os.path.join(output_file, file_name)
            safe_write(out, data, mkdirs=True)
            if req.args.get('hash_link'):
                link_name = "{}{}".format(enc(hash_id(req.id)), req.args.get('ext'))
                link_path = os.path.join(output_file, link_name)
                if os.path.exists(link_path):
                    os.unlink(link_path)
                os.symlink(file_name, link_path)
        else:
            safe_write(out, data, mkdirs=True)

        if req.args.get('update_store'):
            req.store.update(req.t, tid=resource_name)  # TODO maybe this is not the right thing to do anymore
    return req.t


@pipe
@deprecated(reason="stats subsystem was removed")
def loadstats(req: Plumbing.Request, *opts):
    """
    Log (INFO) information about the result of the last call to load

    :param req: The request
    :param opts: Options: (none)
    :return: None

    """
    log.info("pyff loadstats has been deprecated")


@pipe
@deprecated(reason="replaced with load")
def remote(req: Plumbing.Request, *opts):
    """
    Deprecated. Calls :py:mod:`pyff.pipes.builtins.load`.
    """
    return load(req, opts)


@pipe
@deprecated(reason="replaced with load")
def local(req: Plumbing.Request, *opts):
    """
    Deprecated. Calls :py:mod:`pyff.pipes.builtins.load`.
    """
    return load(req, opts)


@pipe
@deprecated(reason="replaced with load")
def _fetch(req: Plumbing.Request, *opts):
    return load(req, *opts)


@pipe
def load(req: Plumbing.Request, *opts):
    """
    General-purpose resource fetcher.

        :param req: The request
        :param _opts: Options: See "Options" below
        :return: None

    Supports both remote and local resources. Fetching remote resources is done in parallel using threads.

    Note: When downloading remote files over HTTPS the TLS server certificate is not validated by default
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
    - fail_on_error <True|False*> : Control whether an error during download, parsing or (optional)validation of a MD file
                                    does not abort processing of the pipeline. When true a failure aborts and causes pyff
                                    to exit with a non zero exit code. Otherwise errors are logged but ignored.
    - filter_invalid <True*|False> : Controls validation behaviour. When true Entities that fail validation are filtered
                                     I.e. are not loaded. When false the entire metadata file is either loaded, or not.
                                     fail_on_error controls whether failure to validating the entire MD file will abort
                                     processing of the pipeline.
    - verify_tls <True|False*>     : Controls the validation of the host's TLS certificate on fetching the resources
    """
    _opts = dict(list(zip(opts[::2], opts[1::2])))
    _opts.setdefault('timeout', 120)
    _opts.setdefault('max_workers', 5)
    _opts.setdefault('validate', "True")
    _opts.setdefault('fail_on_error', "False")
    _opts.setdefault('filter_invalid', "True")
    _opts.setdefault('verify_tls', "False")
    _opts['validate'] = bool(str2bool(_opts['validate']))
    _opts['fail_on_error'] = bool(str2bool(_opts['fail_on_error']))
    _opts['filter_invalid'] = bool(str2bool(_opts['filter_invalid']))
    _opts['verify_tls'] = bool(str2bool(_opts['verify_tls']))

    if not isinstance(req.args, list):
        raise ValueError('Non-list args to "load" not allowed')

    for x in req.args:
        x = x.strip()
        log.debug(f"load parsing '{x}'")
        r = x.split()

        assert len(r) in range(1, 8), PipeException(
            "Usage: load resource [as url] [[verify] verification] [via pipeline] [cleanup pipeline]"
        )

        url = r.pop(0)

        # Copy parent node opts as a starting point
        child_opts = req.md.rm.opts.copy(update={"via": [], "cleanup": [], "verify": None, "alias": url})

        while len(r) > 0:
            elt = r.pop(0)
            if elt in ("as", "verify", "via", "cleanup"):
                # These elements have an argument
                if len(r) > 0:
                    value = r.pop(0)
                    if elt == "as":
                        child_opts.alias = value
                    elif elt == "verify":
                        child_opts.verify = value
                    elif elt == "via":
                        child_opts.via.append(PipelineCallback(value, req, store=req.md.store))
                    elif elt == "cleanup":
                        child_opts.cleanup.append(PipelineCallback(value, req, store=req.md.store))
                    else:
                        raise ValueError(f'Unhandled resource option {elt}')
                else:
                    raise PipeException(
                        "Usage: load resource [as url] [[verify] verification] [via pipeline]* [cleanup pipeline]*"
                    )
            else:
                child_opts.verify = elt

        # override anything in child_opts with what is in opts
        child_opts = child_opts.copy(update=_opts)

        req.md.rm.add_child(url, child_opts)

    log.debug("Refreshing all resources")
    req.md.rm.reload(fail_on_error=bool(_opts['fail_on_error']))


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

    log.info("selecting using args: %s" % args)

    return args


@pipe
def select(req: Plumbing.Request, *opts):
    """
    Select a set of EntityDescriptor elements as the working document.

    :param req: The request
    :param opts: Options - see Options below
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
    working documents to the result of the second select.

    Most statements except local and remote depend on having a select somewhere in your plumbing and will
    stop the plumbing if the current working document is empty. For instance, running

    .. code-block:: yaml

        - select: "!//md:EntityDescriptor[md:SPSSODescriptor]"

    would terminate the plumbing at select if there are no SPs in the local repository. This is useful in
    combination with fork for handling multiple cases in your plumbings.

    Options are put directly after "select". E.g:

    .. code-block:: yaml

        - select as /foo-2.0 dedup True: "!//md:EntityDescriptor[md:IDPSSODescriptor]"

    **Options**
    Defaults are marked with (*)
    - as <name> : The 'as' keyword allows a select to be stored as an alias in the local repository. For instance

        .. code-block:: yaml

            - select as /foo-2.0: "!//md:EntityDescriptor[md:IDPSSODescriptor]"

        would allow you to use /foo-2.0.json to refer to the JSON-version of all IdPs in the current repository.
        Note that you should not include an extension in your "as foo-bla-something" since that would make your
        alias invisible for anything except the corresponding mime type.

    - dedup <True*|False> : Whether to deduplicate the results by entityID.

        Note: When select is used after a load pipe with more than one source, if dedup is set to True
        and there are entity properties that may differ from one source to another, these will be squashed
        rather than merged.
    """
    opt_names = ('as', 'dedup')
    if len(opts) % 2 == 0:
        _opts = dict(list(zip(opts[::2], opts[1::2])))
    else:
        _opts = {}
        for i in range(0, len(opts), 2):
            if opts[i] in opt_names:
                _opts[opts[i]] = opts[i + 1]
            else:
                _opts['as'] = opts[i]
                if i + 1 < len(opts):
                    more_opts = opts[i + 1:]
                    _opts.update(dict(list(zip(more_opts[::2], more_opts[1::2]))))
                    break

    _opts.setdefault('dedup', "True")
    _opts.setdefault('name', req.plumbing.id)
    _opts['dedup'] = bool(str2bool(_opts['dedup']))

    args = _select_args(req)
    name = _opts['name']
    dedup = _opts['dedup']

    if len(opts) > 0:
        if opts[0] != 'as' and len(opts) == 1:
            name = opts[0]
        if opts[0] == 'as' and len(opts) == 2:
            name = opts[1]

    entities = resolve_entities(args, lookup_fn=req.md.store.select, dedup=dedup)

    if req.state.get('match', None):  # TODO - allow this to be passed in via normal arguments

        match = req.state['match']

        if isinstance(match, six.string_types):
            query = [match.lower()]

        def _strings(elt):
            lst = []
            for attr in [
                '{%s}DisplayName' % NS['mdui'],
                '{%s}ServiceName' % NS['md'],
                '{%s}OrganizationDisplayName' % NS['md'],
                '{%s}OrganizationName' % NS['md'],
                '{%s}Keywords' % NS['mdui'],
                '{%s}Scope' % NS['shibmd'],
            ]:
                lst.extend([s.text for s in elt.iter(attr)])
            lst.append(elt.get('entityID'))
            return [item for item in lst if item is not None]

        def _ip_networks(elt):
            return [ipaddress.ip_network(x.text) for x in elt.iter('{%s}IPHint' % NS['mdui'])]

        def _match(q, elt):
            q = q.strip()
            if ':' in q or '.' in q:
                try:
                    nets = _ip_networks(elt)
                    for net in nets:
                        if ipaddress.ip_adress(q) in net:
                            return net
                except ValueError:
                    pass

            if q is not None and len(q) > 0:
                tokens = _strings(elt)
                p = re.compile(r'\b{}'.format(q), re.IGNORECASE)
                for tstr in tokens:
                    if p.search(tstr):
                        return tstr
            return None

        log.debug("matching {} in {} entities".format(match, len(entities)))
        entities = list(filter(lambda e: _match(match, e) is not None, entities))
        log.debug("returning {} entities after match".format(len(entities)))

    ot = entitiesdescriptor(entities, name)
    if ot is None:
        raise PipeException("empty select - stop")

    if req.plumbing.id != name:
        log.debug("storing synthetic collection {}".format(name))
        req.store.update(ot, name)

    return ot


@pipe(name="filter")
def _filter(req: Plumbing.Request, *opts):
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
def pick(req: Plumbing.Request, *opts):
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
def first(req: Plumbing.Request, *opts):
    """

    If the working document is a single EntityDescriptor, strip the outer EntitiesDescriptor element and return it.

    :param req: The request
    :param opts: Options (unused)
    :return: returns the first entity descriptor if the working document only contains one

    Sometimes (eg when running an MDX pipeline) it is usually expected that if a single EntityDescriptor is being returned
    then the outer EntitiesDescriptor is stripped. This method does exactly that.

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
def _discojson(req: Plumbing.Request, *opts):
    """

    Return a discojuice-compatible json representation of the tree

    .. code-block:: yaml
      discojson:

    If the config.load_icons directive is set the icons will be returned from a (possibly persistent) local
    cache & converted to data: URIs

    :param req: The request
    :param opts: Options (unused)
    :return: returns a JSON array

    """

    if req.t is None:
        raise PipeException("Your pipeline is missing a select statement.")

    res = discojson_t(req.t, req.md.rm, icon_store=req.md.icon_store)
    res.sort(key=operator.itemgetter('title'))

    return json.dumps(res)


@pipe(name='discojson_sp')
def _discojson_sp(req, *opts):
    """

    Return a json representation of the trust information

    .. code-block:: yaml
      discojson_sp:

    The returned json doc will have the following structure.

    The root is a dictionary, in which the keys are the entityID's
    of the SP entities that have trust information in their metadata,
    and the values are a representation of that trust information.

    For the XML structure of the trust information see the XML Schema
    in this repo at `/src/pyff/schema/saml-metadata-trustinfo-v1.0.xsd`.

    For each SP with trust information, the representation of
    that information is as follows.

    If there are MetadataSource elements, there will be a key
    'extra_md' pointing to a dictionary of the metadata from those additional
    sources, with entityIDs as keys and entities (with the format provided by
    the discojson function above) as values.

    Then there will be a key 'profiles' pointing to a dictionary
    in which the keys are the names of the trust profiles, and the values
    are json representations of those trust profiles.

    Each trust profile will have the following keys.

    If the trust profile includes a FallbackHandler element, there will
    be a key 'fallback_handler' pointing to a dict with 2 keys, 'profile'
    which by default is 'href', and handler which is a string, commonly a URL.

    Then there will be an 'entity' key pointing to a list of representations of
    individual trusted/untrusted entities, each of them a dictionary, with 2 keys:
    'entity_id' pointing to a string with the entityID, and 'include',
    pointing to a boolean.

    Finally there will be a key 'entities' pointing to a list of representations
    of groups of trusted/untrusted entities, each of them a dictionary with 3 keys:
    a 'match' key pointing to the property of the entities by which they will be selected,
    by default 'registrationAuthority', a key 'select' with the value that will be used
    to select the 'match' property, and 'include', pointing to a boolean.

    :param req: The request
    :param opts: Options (unusued)
    :return: returns a JSON doc

    """

    if req.t is None:
        raise PipeException("Your pipeline is missing a select statement.")

    res = discojson_sp_t(req)

    return json.dumps(res)


@pipe(name='discojson_sp_attr')
def _discojson_sp_attr(req, *opts):
    """

    Return a json representation of the trust information

    .. code-block:: yaml
      discojson_sp_attr:

    SP Entities can carry trust information as a base64 encoded json blob
    as an entity attribute with name `https://refeds.org/entity-selection-profile`.
    The schema of this json is the same as the one produced above from XML
    with the pipe `discojson_sp`, and published at:

    https://github.com/TheIdentitySelector/thiss-mdq/blob/master/trustinfo.schema.json

    :param req: The request
    :param opts: Options (unusued)
    :return: returns a JSON doc

    """

    if req.t is None:
        raise PipeException("Your pipeline is missing a select statement.")

    res = discojson_sp_attr_t(req)

    return json.dumps(res)


@pipe
def sign(req: Plumbing.Request, *_opts):
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

    if not isinstance(req.args, dict):
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
        opts['reference_uri'] = f'#{idattr}'
    xmlsec.sign(req.t, key_file, cert_file, **opts)

    return req.t


@pipe
def stats(req: Plumbing.Request, *opts):
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
        print(
            "          idps: {:d}".format(len(req.t.xpath("//md:EntityDescriptor[md:IDPSSODescriptor]", namespaces=NS)))
        )
        print(
            "           sps: {:d}".format(len(req.t.xpath("//md:EntityDescriptor[md:SPSSODescriptor]", namespaces=NS)))
        )
    print("---")
    return req.t


@pipe
def summary(req: Plumbing.Request, *opts):
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
def _store(req: Plumbing.Request, *opts):
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

    if isinstance(req.args, dict):
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
def xslt(req: Plumbing.Request, *opts):
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

    if not isinstance(req.args, dict):
        raise ValueError('Non-dict args to "xslt" not allowed')

    stylesheet = req.args.get('stylesheet', None)
    if stylesheet is None:
        raise PipeException("xslt requires stylesheet")

    params = dict((k, "\'%s\'" % v) for (k, v) in list(req.args.items()))
    del params['stylesheet']
    try:
        return root(xslt_transform(req.t, stylesheet, params))
    except Exception as ex:
        log.debug(traceback.format_exc())
        raise ex

@pipe
def indent(req: Plumbing.Request, *opts):
    """

    Transform the working document using proper indentation. Requires lxml >= 4.5

    :param req: The request
    :param opts: Options (unused)
    :return: the transformation result

    Indent the working document.

    **Examples**

    .. code-block:: yaml

        - indent:
            space: '    '

    """
    if req.t is None:
        raise PipeException("Your plumbing is missing a select statement.")

    if not req.args:
        req.args = {}

    if not isinstance(req.args, dict):
        raise PipeException("usage: indent {space: '    '}")

    space = req.args.get('space', '  ')

    if callable(getattr(etree, 'indent', None)):
        return etree.indent(req.t, space=space)
    else:
        raise PipeException("lxml version >= 4.5 required.")


@pipe
def validate(req: Plumbing.Request, *opts):
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
def prune(req: Plumbing.Request, *opts):
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

    if not isinstance(req.args, list):
        raise ValueError('Non-list args to "prune" not allowed')

    for path in req.args:
        for part in req.t.iterfind(path):
            parent = part.getparent()
            if parent is not None:
                parent.remove(part)
            else:  # we just removed the top-level element - return empty tree
                return None

    return req.t


@pipe
def check_xml_namespaces(req: Plumbing.Request, *opts):
    """
    Ensure that all namespaces are http or httpd scheme URLs.

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
                            "Namespace URIs must be be http(s) URIs ('{}' declared on {})".format(uri, elt.tag)
                        )

    with_tree(root(req.t), _verify)
    return req.t


@pipe
def drop_xsi_type(req: Plumbing.Request, *opts):
    """
    Remove all xsi namespaces from the tree.

    :param req: The request
    :param opts: Options (not used)
    :return: drop all xsi:type declarations

    """
    if req.t is None:
        raise PipeException("Your pipeline is missing a select statement.")

    def _drop_xsi_type(elt):
        try:
            del elt.attrib["{%s}type" % NS["xsi"]]
        except Exception as ex:
            pass

    with_tree(root(req.t), _drop_xsi_type)
    return req.t


@pipe
def certreport(req: Plumbing.Request, *opts):
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

    if not isinstance(req.args, dict):
        raise PipeException("usage: certreport {warning: 864000, error: 0}")

    error_seconds = int(req.args.get('error_seconds', "0"))
    warning_seconds = int(req.args.get('warning_seconds', "864000"))
    error_bits = int(req.args.get('error_bits', "1024"))
    warning_bits = int(req.args.get('warning_bits', "2048"))

    seen: Dict[str, bool] = {}
    for eid in req.t.xpath("//md:EntityDescriptor/@entityID", namespaces=NS, smart_strings=False):
        for cd in req.t.xpath(
            "md:EntityDescriptor[@entityID='%s']//ds:X509Certificate" % eid, namespaces=NS, smart_strings=False
        ):
            try:
                cert_pem = cd.text
                cert_der = base64.b64decode(cert_pem)
                m = hashlib.sha1()
                m.update(cert_der)
                fp = m.hexdigest()
                if fp not in seen:
                    seen[fp] = True
                    entity_elt = cd.getparent().getparent().getparent().getparent().getparent()
                    cdict = xmlsec.utils.b642cert(cert_pem)
                    keysize = cdict['modulus'].bit_length()
                    cert = cdict['cert']
                    if keysize < error_bits:
                        annotate_entity(
                            entity_elt,
                            "certificate-error",
                            "keysize too small",
                            "%s has keysize of %s bits (less than %s)" % (cert.getSubject(), keysize, error_bits),
                        )
                        log.error("%s has keysize of %s" % (eid, keysize))
                    elif keysize < warning_bits:
                        annotate_entity(
                            entity_elt,
                            "certificate-warning",
                            "keysize small",
                            "%s has keysize of %s bits (less than %s)" % (cert.getSubject(), keysize, warning_bits),
                        )
                        log.warning("%s has keysize of %s" % (eid, keysize))

                    notafter = cert.getNotAfter()
                    if notafter is None:
                        annotate_entity(
                            entity_elt,
                            "certificate-error",
                            "certificate has no expiration time",
                            "%s has no expiration time" % cert.getSubject(),
                        )
                    else:
                        try:
                            et = datetime.strptime("%s" % notafter, "%y%m%d%H%M%SZ")
                            now = datetime.now()
                            dt = et - now
                            if total_seconds(dt) < error_seconds:
                                annotate_entity(
                                    entity_elt,
                                    "certificate-error",
                                    "certificate has expired",
                                    "%s expired %s ago" % (cert.getSubject(), -dt),
                                )
                                log.error("%s expired %s ago" % (eid, -dt))
                            elif total_seconds(dt) < warning_seconds:
                                annotate_entity(
                                    entity_elt,
                                    "certificate-warning",
                                    "certificate about to expire",
                                    "%s expires in %s" % (cert.getSubject(), dt),
                                )
                                log.warning("%s expires in %s" % (eid, dt))
                        except ValueError as ex:
                            annotate_entity(
                                entity_elt,
                                "certificate-error",
                                "certificate has unknown expiration time",
                                "%s unknown expiration time %s" % (cert.getSubject(), notafter),
                            )

                    req.store.update(entity_elt)
            except Exception as ex:
                log.debug(traceback.format_exc())
                log.error(f'Got exception while creating certreport: {ex}')


@pipe
def emit(req: Plumbing.Request, ctype="application/xml", *opts):
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
def signcerts(req: Plumbing.Request, *opts):
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
def finalize(req: Plumbing.Request, *opts):
    """
    Prepares the working document for publication/rendering.

    :param req: The request
    :param opts: Options (not used)
    :return: returns the working document with @Name, @cacheDuration and @validUntil set

    Set Name, ID, cacheDuration and validUntil on the toplevel EntitiesDescriptor element of the working document.
    Unless explicitly provided the @Name is set from the request URI if the pipeline is executed in the pyFF server. The
    @ID is set to a string representing the current date/time and will be prefixed with the string provided, which
    defaults to '_'. The @cacheDuration element must be a valid xsd duration (eg PT5H for 5 hrs) and @validUntil can
    be either an absolute ISO 8601 time string or (more commonly) a relative time in the form

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

    if not isinstance(req.args, dict):
        raise ValueError('Non-dict args to "finalize" not allowed')

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
                    # TODO: Investigate this error, which is probably correct:
                    #       error: On Python 3 '{}'.format(b'abc') produces "b'abc'", not 'abc';
                    #       use '{!r}'.format(b'abc') if this is desired behavior
                    name = "{}://{}{}".format(base_url.scheme, base_url.netloc, name_url.path)  # type: ignore
                    log.debug("-------- using Name: %s" % name)
                except ValueError as ex:
                    log.debug(f'Got an exception while finalizing: {ex}')
                    name = None
        if name is None or 0 == len(name):
            name = e.get('Name', None)

        if name:
            e.set('Name', name)

    now = utc_now()

    mdid = req.args.get('ID', 'prefix _')
    if re.match(r'(\s)*prefix(\s)*', mdid):
        prefix = re.sub(r'^(\s)*prefix(\s)*', '', mdid)
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
            e.set('validUntil', datetime2iso(dt))
        elif valid_until is not None:
            # TODO: if validUntil was not present, valid_until will be the string 'None' here - never the literal None
            try:
                dt = iso2datetime(valid_until)
                offset = dt - now
                e.set('validUntil', datetime2iso(dt))
            except ValueError as ex:
                log.error("Unable to parse validUntil: %s (%s)" % (valid_until, ex))

        # set a reasonable default: 50% of the validity
        # we replace this below if we have cacheDuration set
        # TODO: offset can be None here, if validUntil is not a valid duration or ISO date
        #       What is the right action to take then?
        if offset:
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
def _reginfo(req: Plumbing.Request, *opts):
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

    if not isinstance(req.args, dict):
        raise ValueError('Non-dict args to "reginfo" not allowed')

    for e in iter_entities(req.t):
        set_reginfo(e, **req.args)

    return req.t


@pipe(name='pubinfo')
def _pubinfo(req: Plumbing.Request, *opts):
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

    if not isinstance(req.args, dict):
        raise ValueError('Non-dict args to "pubinfo" not allowed')

    set_pubinfo(root(req.t), **req.args)

    return req.t


@pipe(name='setattr')
def _setattr(req: Plumbing.Request, *opts):
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
def _nodecountry(req: Plumbing.Request, *opts):
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

    if not isinstance(req.args, dict):
        raise ValueError('Non-dict args to "nodecountry" not allowed')

    for e in iter_entities(req.t):
        if req.args is not None and 'country' in req.args:
            set_nodecountry(e, country_code=req.args['country'])
            req.store.update(e)
        else:
            log.error("No country found in arguments to nodecountry")

    return req.t


__all__ = [fn.__name__ for fn in registry.values()]
