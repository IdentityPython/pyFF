import importlib
import threading
from datetime import datetime, timedelta
from json import dumps
from typing import Any, Dict, Generator, Iterable, List, Mapping, Optional, Tuple

import pkg_resources
import pyramid.httpexceptions as exc
import pytz
import requests
from accept_types import AcceptableType
from cachetools import TTLCache
from lxml import etree
from pyramid.config import Configurator
from pyramid.events import NewRequest
from pyramid.request import Request
from pyramid.response import Response
from six import b
from six.moves.urllib_parse import quote_plus

from pyff.constants import config
from pyff.exceptions import ResourceException
from pyff.logs import get_log
from pyff.pipes import plumbing
from pyff.repo import MDRepository
from pyff.resource import Resource
from pyff.samlmd import entity_display_name
from pyff.utils import b2u, dumptree, hash_id, json_serializer, utc_now

log = get_log(__name__)


class NoCache(object):
    """ Dummy implementation for when caching isn't enabled """

    def __init__(self) -> None:
        pass

    def __getitem__(self, item: Any) -> None:
        return None

    def __setitem__(self, instance: Any, value: Any) -> Any:
        return value


def robots_handler(request: Request) -> Response:
    """
    Implements robots.txt

    :param request: the HTTP request
    :return: robots.txt
    """
    return Response(
        """
User-agent: *
Disallow: /
"""
    )


def status_handler(request: Request) -> Response:
    """
    Implements the /api/status endpoint

    :param request: the HTTP request
    :return: JSON status
    """
    d = {}
    for r in request.registry.md.rm:
        if 'Validation Errors' in r.info and r.info['Validation Errors']:
            d[r.url] = r.info['Validation Errors']
    _status = dict(
        version=pkg_resources.require("pyFF")[0].version,
        invalids=d,
        icon_store=dict(size=request.registry.md.icon_store.size()),
        jobs=[dict(id=j.id, next_run_time=j.next_run_time) for j in request.registry.scheduler.get_jobs()],
        threads=[t.name for t in threading.enumerate()],
        store=dict(size=request.registry.md.store.size()),
    )
    response = Response(dumps(_status, default=json_serializer))
    response.headers['Content-Type'] = 'application/json'
    return response


class MediaAccept(object):
    def __init__(self, accept: str):
        self._type = AcceptableType(accept)

    def has_key(self, key: Any) -> bool:  # Literal[True]:
        return True

    def get(self, item: Any) -> Any:
        return self._type.matches(item)

    def __contains__(self, item: Any) -> Any:
        return self._type.matches(item)

    def __str__(self) -> str:
        return str(self._type)


xml_types = ('text/xml', 'application/xml', 'application/samlmetadata+xml')


def _is_xml_type(accepter: MediaAccept) -> bool:
    return any([x in accepter for x in xml_types])


def _is_xml(data: Any) -> bool:
    return isinstance(data, (etree._Element, etree._ElementTree))


def _fmt(data: Any, accepter: MediaAccept) -> Tuple[str, str]:
    """
    Format data according to the accepted content type of the requester.
    Return data as string (either XML or json) and a content-type.
    """
    if data is None or len(data) == 0:
        return "", 'text/plain'
    if _is_xml(data) and _is_xml_type(accepter):
        return dumptree(data), 'application/samlmetadata+xml'
    if isinstance(data, (dict, list)) and accepter.get('application/json'):
        return dumps(data, default=json_serializer), 'application/json'

    raise exc.exception_response(406)


def call(entry: str) -> None:
    url = f'{config.base_url}/api/call/{entry}'
    log.debug(f'Calling API endpoint at {url}')
    resp = requests.post(url)
    if resp.status_code >= 300:
        log.error(f'POST request to API endpoint at {url} failed: {resp.status_code} {resp.reason}')
    return None


def request_handler(request: Request) -> Response:
    """
    The main GET request handler for pyFF. Implements caching and forwards the request to process_handler

    :param request: the HTTP request object
    :return: the data to send to the client
    """
    key = request.path_qs
    r = None
    try:
        r = request.registry.cache[key]
    except KeyError:
        pass
    if r is None:
        r = process_handler(request)
        request.registry.cache[key] = r
    return r


def process_handler(request: Request) -> Response:
    """
    The main request handler for pyFF. Implements API call hooks and content negotiation.

    :param request: the HTTP request object
    :return: the data to send to the client
    """
    _ctypes = {'xml': 'application/samlmetadata+xml;application/xml;text/xml', 'json': 'application/json'}

    def _d(x: Optional[str], do_split: bool = True) -> Tuple[Optional[str], Optional[str]]:
        """ Split a path into a base component and an extension. """
        if x is not None:
            x = x.strip()

        if x is None or len(x) == 0:
            return None, None

        if '.' in x:
            (pth, dot, extn) = x.rpartition('.')
            assert dot == '.'
            if extn in _ctypes:
                return pth, extn

        return x, None

    log.debug(f'Processing request: {request}')

    if request.matchdict is None:
        raise exc.exception_response(400)

    if request.body:
        try:
            request.matchdict.update(request.json_body)
        except ValueError as ex:
            pass

    entry = request.matchdict.get('entry', 'request')
    path_elem = list(request.matchdict.get('path', []))
    match = request.params.get('q', request.params.get('query', None))

    # Enable matching on scope.
    match = match.split('@').pop() if match and not match.endswith('@') else match
    log.debug("match={}".format(match))

    if not path_elem:
        path_elem = ['entities']

    alias = path_elem.pop(0)
    path = '/'.join(path_elem)

    # Ugly workaround bc WSGI drops double-slashes.
    path = path.replace(':/', '://')

    msg = "handling entry={}, alias={}, path={}"
    log.debug(msg.format(entry, alias, path))

    pfx = None
    if 'entities' not in alias:
        pfx = request.registry.aliases.get(alias, None)
        if pfx is None:
            log.debug("alias {} not found - passing to storage lookup".format(alias))
            path=alias #treat as path

    # content_negotiation_policy is one of three values:
    # 1. extension - current default, inspect the path and if it ends in
    #    an extension, e.g. .xml or .json, always strip off the extension to
    #    get the entityID and if no accept header or a wildcard header, then
    #    use the extension to determine the return Content-Type.
    #
    # 2. adaptive - only if no accept header or if a wildcard, then inspect
    #    the path and if it ends in an extension strip off the extension to
    #    get the entityID and use the extension to determine the return
    #    Content-Type.
    #
    # 3. header - future default, do not inspect the path for an extension and
    #    use only the Accept header to determine the return Content-Type.
    policy = config.content_negotiation_policy

    # TODO - sometimes the client sends > 1 accept header value with ','.
    accept = str(request.accept).split(',')[0]
    valid_accept = accept and not ('application/*' in accept or 'text/*' in accept or '*/*' in accept)

    new_path: Optional[str] = path
    path_no_extension, extension = _d(new_path, True)
    accept_from_extension = accept
    if extension:
        accept_from_extension = _ctypes.get(extension, accept)

    if policy == 'extension':
        new_path = path_no_extension
        if not valid_accept:
            accept = accept_from_extension
    elif policy == 'adaptive':
        if not valid_accept:
            new_path = path_no_extension
            accept = accept_from_extension

    if not accept:
        log.warning('Could not determine accepted response type')
        raise exc.exception_response(400)

    q: Optional[str]
    if pfx and new_path:
        q = f'{{{pfx}}}{new_path}'
        new_path = f'/{alias}/{new_path}'
    else:
        q = new_path

    try:
        accepter = MediaAccept(accept)
        for p in request.registry.plumbings:
            state = {
                entry: True,
                'headers': {'Content-Type': None},
                'accept': accepter,
                'url': request.current_route_url(),
                'select': q,
                'match': match.lower() if match else match,
                'path': new_path,
                'stats': {},
            }

            r = p.process(request.registry.md, state=state, raise_exceptions=True, scheduler=request.registry.scheduler)
            log.debug(f'Plumbing process result: {r}')
            if r is None:
                r = []

            response = Response()
            _headers = state.get('headers', {})
            response.headers.update(_headers)
            ctype = _headers.get('Content-Type', None)
            if not ctype:
                r, t = _fmt(r, accepter)
                ctype = t

            response.text = b2u(r)
            response.size = len(r)
            response.content_type = ctype
            cache_ttl = int(state.get('cache', 0))
            response.expires = datetime.now() + timedelta(seconds=cache_ttl)
            return response
    except ResourceException as ex:
        import traceback

        log.debug(traceback.format_exc())
        log.warning(f'Exception from processing pipeline: {ex}')
        raise exc.exception_response(409)
    except BaseException as ex:
        import traceback

        log.debug(traceback.format_exc())
        log.error(f'Exception from processing pipeline: {ex}')
        raise exc.exception_response(500)

    if request.method == 'GET':
        raise exc.exception_response(404)


def webfinger_handler(request: Request) -> Response:
    """An implementation the webfinger protocol
    (http://tools.ietf.org/html/draft-ietf-appsawg-webfinger-12)
    in order to provide information about up and downstream metadata available at
    this pyFF instance.

    Example:

    .. code-block:: bash

    # curl http://my.org/.well-known/webfinger?resource=http://my.org

    This should result in a JSON structure that looks something like this:

    .. code-block:: json

    {
     "expires": "2013-04-13T17:40:42.188549",
     "links": [
     {
      "href": "http://reep.refeds.org:8080/role/sp.xml",
      "rel": "urn:oasis:names:tc:SAML:2.0:metadata"
      },
     {
      "href": "http://reep.refeds.org:8080/role/sp.json",
      "rel": "disco-json"
      }
     ],
     "subject": "http://reep.refeds.org:8080"
    }

    Depending on which version of pyFF you're running and the configuration you
    may also see downstream metadata listed using the 'role' attribute to the link
    elements.
    """

    resource = request.params.get('resource', None)
    rel = request.params.get('rel', None)

    if resource is None:
        resource = request.host_url

    jrd: Dict[str, Any] = dict()
    dt = datetime.now() + timedelta(hours=1)
    jrd['expires'] = dt.isoformat()
    jrd['subject'] = request.host_url
    links: List[Dict[str, Any]] = list()
    jrd['links'] = links

    _dflt_rels = {
        'urn:oasis:names:tc:SAML:2.0:metadata': ['.xml', 'application/xml'],
        'disco-json': ['.json', 'application/json'],
    }

    if rel is None or len(rel) == 0:
        rel = _dflt_rels.keys()
    else:
        rel = [rel]

    def _links(url: str, title: Any = None) -> None:
        if url.startswith('/'):
            url = url.lstrip('/')
        for r in rel:
            suffix = ""
            if not url.endswith('/'):
                suffix = _dflt_rels[r][0]
            links.append(dict(rel=r, type=_dflt_rels[r][1], href='%s/%s%s' % (request.host_url, url, suffix)))

    _links('/entities/')
    for a in request.registry.md.store.collections():
        if a is not None and '://' not in a:
            _links(a)

    for entity in request.registry.md.store.lookup('entities'):
        entity_display = entity_display_name(entity)
        _links("/entities/%s" % hash_id(entity.get('entityID')), title=entity_display)

    aliases = request.registry.aliases
    for a in aliases.keys():
        for v in request.registry.md.store.attribute(aliases[a]):
            _links('%s/%s' % (a, quote_plus(v)))

    response = Response(dumps(jrd, default=json_serializer))
    response.headers['Content-Type'] = 'application/json'

    return response


def resources_handler(request: Request) -> Response:
    """
    Implements the /api/resources endpoint

    :param request: the HTTP request
    :return: a JSON representation of the set of resources currently loaded by the server
    """

    def _infos(resources: Iterable[Resource]) -> List[Mapping[str, Any]]:
        return [_info(r) for r in resources if r.info.state is not None]

    def _info(r: Resource) -> Mapping[str, Any]:
        nfo = r.info.to_dict()
        nfo['Valid'] = r.is_valid()
        nfo['Parser'] = r.last_parser
        if r.last_seen is not None:
            nfo['Last Seen'] = r.last_seen
        if len(r.children) > 0:
            nfo['Children'] = _infos(r.children)

        return nfo

    response = Response(dumps(_infos(request.registry.md.rm.children), default=json_serializer))
    response.headers['Content-Type'] = 'application/json'

    return response


def pipeline_handler(request: Request) -> Response:
    """
    Implements the /api/pipeline endpoint

    :param request: the HTTP request
    :return: a JSON representation of the active pipeline
    """
    response = Response(dumps(request.registry.plumbings, default=json_serializer))
    response.headers['Content-Type'] = 'application/json'

    return response


def search_handler(request: Request) -> Response:
    """
    Implements the /api/search endpoint

    :param request: the HTTP request with the 'query' request parameter
    :return: a JSON search result
    """
    match = request.params.get('q', request.params.get('query', ""))

    # Enable matching on scope.
    match = match.split('@').pop() if match and not match.endswith('@') else match

    entity_filter = request.params.get('entity_filter', '{http://pyff.io/role}idp')
    log.debug("match={}".format(match))
    store = request.registry.md.store

    def _response() -> Generator[bytes, bytes, None]:
        yield b('[')
        in_loop = False
        entities = store.search(query=match.lower(), entity_filter=entity_filter)
        for e in entities:
            if in_loop:
                yield b(',')
            yield b(dumps(e))
            in_loop = True
        yield b(']')

    response = Response(content_type='application/json')
    response.app_iter = _response()
    return response


def add_cors_headers_response_callback(event: NewRequest) -> None:
    def cors_headers(request: Request, response: Response) -> None:
        response.headers.update(
            {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'POST,GET,DELETE,PUT,OPTIONS',
                'Access-Control-Allow-Headers': ('Origin, Content-Type, Accept, ' 'Authorization'),
                'Access-Control-Allow-Credentials': 'true',
                'Access-Control-Max-Age': '1728000',
            }
        )

    event.request.add_response_callback(cors_headers)


def mkapp(*args: Any, **kwargs: Any) -> Any:
    md = kwargs.pop('md', None)
    if md is None:
        md = MDRepository()

    with Configurator(debug_logger=log) as ctx:
        ctx.add_subscriber(add_cors_headers_response_callback, NewRequest)

        if config.aliases is None:
            config.aliases = dict()

        if config.modules is None:
            config.modules = []

        ctx.registry.config = config
        config.modules.append('pyff.builtins')
        for mn in config.modules:
            importlib.import_module(mn)

        pipeline = None
        if args:
            pipeline = list(args)
        if pipeline is None and config.pipeline:
            pipeline = [config.pipeline]

        ctx.registry.scheduler = md.scheduler
        if pipeline is not None:
            ctx.registry.pipeline = pipeline
            ctx.registry.plumbings = [plumbing(v) for v in pipeline]
        ctx.registry.aliases = config.aliases
        ctx.registry.md = md
        if config.caching_enabled:
            ctx.registry.cache = TTLCache(config.cache_size, config.cache_ttl)
        else:
            ctx.registry.cache = NoCache()

        ctx.add_route('robots', '/robots.txt')
        ctx.add_view(robots_handler, route_name='robots')

        ctx.add_route('webfinger', '/.well-known/webfinger', request_method='GET')
        ctx.add_view(webfinger_handler, route_name='webfinger')

        ctx.add_route('search', '/api/search', request_method='GET')
        ctx.add_view(search_handler, route_name='search')

        ctx.add_route('status', '/api/status', request_method='GET')
        ctx.add_view(status_handler, route_name='status')

        ctx.add_route('resources', '/api/resources', request_method='GET')
        ctx.add_view(resources_handler, route_name='resources')

        ctx.add_route('pipeline', '/api/pipeline', request_method='GET')
        ctx.add_view(pipeline_handler, route_name='pipeline')

        ctx.add_route('call', '/api/call/{entry}', request_method=['POST', 'PUT'])
        ctx.add_view(process_handler, route_name='call')

        ctx.add_route('request', '/*path', request_method='GET')
        ctx.add_view(request_handler, route_name='request')

        start = utc_now() + timedelta(seconds=1)
        if config.update_frequency > 0:
            ctx.registry.scheduler.add_job(
                call,
                'interval',
                id="call/update",
                args=['update'],
                start_date=start,
                misfire_grace_time=10,
                seconds=config.update_frequency,
                replace_existing=True,
                max_instances=1,
                timezone=pytz.utc,
            )

        return ctx.make_wsgi_app()
