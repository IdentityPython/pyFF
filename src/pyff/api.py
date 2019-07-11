from pyramid.config import Configurator
from pyramid.response import Response
import pyramid.httpexceptions as exc
from .exceptions import ResourceException
from .constants import config
import importlib
from .pipes import plumbing
from .samlmd import entity_display_name
from six.moves.urllib_parse import quote_plus
from six import b
from .logs import get_log
from json import dumps
from datetime import datetime, timedelta
from .utils import dumptree, duration2timedelta, hash_id, json_serializer, b2u, make_default_scheduler
from .repo import MDRepository
import pkg_resources
from accept_types import AcceptableType
from lxml import etree
from pyramid.events import NewRequest
import requests
import threading

log = get_log(__name__)


def robots_handler(request):
    return Response("""
User-agent: *
Disallow: /
""")


def status_handler(request):
    d = {}
    for r in request.registry.md.rm:
        if 'Validation Errors' in r.info and r.info['Validation Errors']:
            d[r.url] = r.info['Validation Errors']
    _status = dict(version=pkg_resources.require("pyFF")[0].version,
                   invalids=d,
                   icon_store=dict(size=request.registry.md.icon_store.size()),
                   jobs=[dict(id=j.id, next_run_time=j.next_run_time) for j in request.registry.scheduler.get_jobs()],
                   threads=[t.name for t in threading.enumerate()],
                   store=dict(size=request.registry.md.store.size()))
    response = Response(dumps(_status, default=json_serializer))
    response.headers['Content-Type'] = 'application/json'
    return response


class MediaAccept(object):

    def __init__(self, accept):
        self._type = AcceptableType(accept)

    def has_key(self, key):
        return True

    def get(self, item):
        return self._type.matches(item)

    def __contains__(self, item):
        return self._type.matches(item)


def _fmt(data, accepter):
    if data is None or len(data) == 0:
        return 'text/plain', ''
    if isinstance(data, (etree._Element, etree._ElementTree)) and (
            accepter.get('text/xml') or accepter.get('application/xml')):
        return dumptree(data), 'application/xml'
    if isinstance(data, (dict, list)) and accepter.get('application/json'):
        return dumps(data, default=json_serializer), 'application/json'

    raise exc.exception_response(406)


def call(entry):
    r = requests.post('{}/api/call/{}'.format(config.base_url, entry))


def process_handler(request):
    _ctypes = {'xml': 'application/xml',
               'json': 'application/json'}

    def _d(x, do_split=True):
        if x is not None:
            x = x.strip()

        if x is None or len(x) == 0:
            return None, None

        if '.' in x:
            (pth, dot, extn) = x.rpartition('.')
            assert (dot == '.')
            if extn in _ctypes:
                return pth, extn

        return x, None

    log.debug(request)

    if request.matchdict is None:
        raise exc.exception_response(404)

    if request.body:
        try:
            request.matchdict.update(request.json_body)
        except ValueError as ex:
            pass

    entry = request.matchdict.get('entry', 'request')
    path = list(request.matchdict.get('path', []))
    match = request.params.get('q', request.params.get('query', None))
    if 0 == len(path):
        path = ['entities']

    alias = path.pop(0)
    path = '/'.join(path)
    path = path.replace(':/', '://')  # ugly workaround bc WSGI drops double-slashes

    log.debug("handling entry={}, alias={}, path={}".format(entry, alias, path))

    pfx = None
    if 'entities' not in alias:
        pfx = request.registry.aliases.get(alias, None)
        if pfx is None:
            raise exc.exception_response(404)

    path, ext = _d(path, True)
    if pfx and path:
        q = "{%s}%s" % (pfx, path)
        path = "/%s/%s" % (alias, path)
    else:
        q = path

    accept = str(request.accept).split(',')[0]  # TODO - sometimes the client sends > 1 accept header value with ','
    if (not accept or '*/*' in accept) and ext:
        accept = _ctypes[ext]

    try:
        accepter = MediaAccept(accept)
        for p in request.registry.plumbings:
            state = {entry: True,
                     'headers': {'Content-Type': None},
                     'accept': accepter,
                     'url': request.current_route_url(),
                     'select': q,
                     'match': match,
                     'path': path,
                     'stats': {}}

            r = p.process(request.registry.md,
                          state=state,
                          raise_exceptions=True,
                          scheduler=request.registry.scheduler)
            if r is not None:
                response = Response()
                response.headers.update(state.get('headers', {}))
                ctype = state.get('headers').get('Content-Type', None)
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
        log.warn(ex)
        raise exc.exception_response(409)
    except BaseException as ex:
        import traceback
        log.debug(traceback.format_exc())
        log.error(ex)
        raise exc.exception_response(500)

    raise exc.exception_response(404)


def webfinger_handler(request):
    """An implementation the webfinger protocol (http://tools.ietf.org/html/draft-ietf-appsawg-webfinger-12)
        in order to provide information about up and downstream metadata available at this pyFF instance.

Example:

.. code-block:: bash

        # curl http://localhost:8080/.well-known/webfinger?resource=http://localhost:8080

This should result in a JSON structure that looks something like this:

.. code-block:: json

        {"expires": "2013-04-13T17:40:42.188549",
         "links": [
            {"href": "http://reep.refeds.org:8080/role/sp.xml", "rel": "urn:oasis:names:tc:SAML:2.0:metadata"},
            {"href": "http://reep.refeds.org:8080/role/sp.json", "rel": "disco-json"}],
         "subject": "http://reep.refeds.org:8080"}

Depending on which version of pyFF your're running and the configuration you may also see downstream metadata
listed using the 'role' attribute to the link elements.
        """

    resource = request.params.get('resource', None)
    rel = request.params.get('rel', None)

    if resource is None:
        resource = request.host_url

    jrd = dict()
    dt = datetime.now() + duration2timedelta("PT1H")
    jrd['expires'] = dt.isoformat()
    jrd['subject'] = request.host_url
    links = list()
    jrd['links'] = links

    _dflt_rels = {
        'urn:oasis:names:tc:SAML:2.0:metadata': ['.xml', 'application/xml'],
        'disco-json': ['.json', 'application/json']
    }

    if rel is None or len(rel) == 0:
        rel = _dflt_rels.keys()
    else:
        rel = [rel]

    def _links(url, title=None):
        if url.startswith('/'):
            url = url.lstrip('/')
        for r in rel:
            suffix = ""
            if not url.endswith('/'):
                suffix = _dflt_rels[r][0]
            links.append(dict(rel=r,
                              type=_dflt_rels[r][1],
                              href='%s/%s%s' % (request.host_url, url, suffix)))

    _links('/entities/')
    for a in request.registry.md.store.collections():
        if a is not None and '://' not in a:
            _links(a)

    for entity in request.registry.md.store.lookup('entities'):
        entity_display = entity_display_name(entity)
        _links("/entities/%s" % hash_id(entity.get('entityID')), title=entity_display)

    for a in request.registry.aliases.keys():
        for v in request.registry.md.store.attribute(request.registry.aliases[a]):
            _links('%s/%s' % (a, quote_plus(v)))

    response = Response(dumps(jrd, default=json_serializer))
    response.headers['Content-Type'] = 'application/json'

    return response


def resources_handler(request):
    def _info(r):
        nfo = r.info
        nfo['Valid'] = r.is_valid()
        nfo['Parser'] = r.last_parser
        if r.last_seen is not None:
            nfo['Last Seen'] = r.last_seen
        if len(r.children) > 0:
            nfo['Children'] = [_info(cr) for cr in r.children]
        return nfo
    _resources = [_info(r) for r in request.registry.md.rm.children]
    response = Response(dumps(_resources, default=json_serializer))
    response.headers['Content-Type'] = 'application/json'

    return response


def pipeline_handler(request):
    response = Response(dumps(request.registry.plumbings, default=json_serializer))
    response.headers['Content-Type'] = 'application/json'

    return response


def search_handler(request):
    match = request.params.get('q', request.params.get('query', None))
    entity_filter = request.params.get('entity_filter', '{http://pyff.io/role}idp')
    log.debug("match={}".format(match))
    store = request.registry.md.store

    def _response():
        yield b('[')
        in_loop = False
        for e in store.search(query=match.lower(), entity_filter=entity_filter):
            if in_loop:
                yield b(',')
            yield b(dumps(e))
            in_loop = True
        yield b(']')

    response = Response(content_type='application/json')
    response.app_iter = _response()
    return response


def add_cors_headers_response_callback(event):
    def cors_headers(request, response):
        response.headers.update({
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'POST,GET,DELETE,PUT,OPTIONS',
            'Access-Control-Allow-Headers': 'Origin, Content-Type, Accept, Authorization',
            'Access-Control-Allow-Credentials': 'true',
            'Access-Control-Max-Age': '1728000',
        })

    event.request.add_response_callback(cors_headers)


def launch_memory_usage_server(port = 9002):
    import cherrypy
    import dowser

    cherrypy.tree.mount(dowser.Root())
    cherrypy.config.update({
        'environment': 'embedded',
        'server.socket_port': port
    })

    cherrypy.engine.start()


def mkapp(*args, **kwargs):

    md = kwargs.pop('md', None)
    if md is None:
        md = MDRepository()

    if config.devel_memory_profile:
        launch_memory_usage_server()

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

        pipeline = args or None
        if pipeline is None and config.pipeline:
            pipeline = [config.pipeline]

        ctx.registry.scheduler = md.scheduler
        if pipeline is not None:
            ctx.registry.pipeline = pipeline
            ctx.registry.plumbings = [plumbing(v) for v in pipeline]
        ctx.registry.aliases = config.aliases
        ctx.registry.md = md

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
        ctx.add_view(process_handler, route_name='request')

        start = datetime.utcnow()+timedelta(seconds=1)
        log.debug(start)
        if config.update_frequency > 0:
            ctx.registry.scheduler.add_job(call,
                                           'interval',
                                           id="call/update",
                                           args=['update'],
                                           start_date=start,
                                           seconds=config.update_frequency,
                                           replace_existing=True,
                                           max_instances=1)

        return ctx.make_wsgi_app()
