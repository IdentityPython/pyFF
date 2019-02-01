from wsgiref.simple_server import make_server
from pyramid.config import Configurator
from pyramid.response import Response
import pyramid.httpexceptions as exc
from .constants import config
import importlib
from .pipes import plumbing
from publicsuffix import PublicSuffixList
from .samlmd import MDRepository
from .store import make_store_instance
from six.moves.urllib_parse import quote_plus
from .logs import log
from json import dumps
from datetime import datetime, timedelta
from .utils import dumptree, duration2timedelta, hash_id
import os
import pkg_resources
from accept_types import AcceptableType
from lxml import etree


def robots(request):
    return Response("""
User-agent: *
Disallow: /
""")


def status(request):
    _status = dict(version=pkg_resources.require("pyFF")[0].version,
                   store=dict(size=request.registry.md.store.size()))
    response = Response(dumps(_status))
    response.headers['Content-Type'] = 'application/json'
    response.headers['Access-Control-Allow-Origin'] = '*'
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


def _output(data, accepter):
    if data is None or len(data) == 0:
        return ""
    if isinstance(data, (etree._Element, etree._ElementTree)) and (accepter.get('text/xml') or accepter.get('application/xml')):
        return dumptree(data)
    if isinstance(data, (dict, list)) and accepter.get('application/json'):
        return dumps(data)

    raise exc.exception_response(406)


def query(request):
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
    if 0 == len(path):
        path = ['entities']

    alias = path.pop(0)
    path = '/'.join(path)

    log.debug("handling entry={}, alias={}, path={}".format(entry,alias,path))

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

    accept = str(request.accept)
    if (not accept or '*/*' in accept) and ext is not None:
        accept = _ctypes[ext]

    try:
        request.registry.activity = entry
        accepter = MediaAccept(accept)
        for p in request.registry.plumbings:
            state = {entry: True,
                     'headers': {'Content-Type': None},
                     'accept': accepter,
                     'url': request.current_route_url(),
                     'select': q,
                     'path': path,
                     'stats': {}}

            r = p.process(request.registry.md, state=state)
            if r is None:
                raise exc.exception_response(404)

            response = Response()
            response.headers.update(state.get('headers', {}))
            ctype = state.get('headers').get('Content-Type', None)
            if not ctype:
                r = _output(r, accepter)
                ctype = accept

            response.body = r
            response.size = len(r)
            response.content_type = ctype
            cache_ttl = int(state.get('cache', 0))
            response.expires = datetime.now() + timedelta(seconds=cache_ttl)
            response.headers['Access-Control-Allow-Origin'] = '*'

            return response
    except Exception as ex:
        request.registry.activity = 'idle'
        log.error(ex)
        raise ex

    raise exc.exception_response(404)


def webfinger(request):
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

    resource = request.matchdict.get('resource', None)
    rel = request.matchdict.get('rel', None)

    if resource is None:
        resource = request.host_url

    jrd = dict()
    dt = datetime.now() + duration2timedelta("PT1H")
    jrd['expires'] = dt.isoformat()
    jrd['subject'] = request.host_url
    links = list()
    jrd['links'] = links

    _dflt_rels = {
        'urn:oasis:names:tc:SAML:2.0:metadata': '.xml',
        'disco-json': '.json'
    }

    if rel is None:
        rel = _dflt_rels.keys()
    else:
        rel = [rel]

    def _links(url):
        if url.startswith('/'):
            url = url.lstrip('/')
        for r in rel:
            suffix = ""
            if not url.endswith('/'):
                suffix = _dflt_rels[r]
            links.append(dict(rel=r,
                              href='%s/api/request/%s%s' % (request.host_url, url, suffix)))

    _links('/entities/')
    for a in request.registry.md.store.collections():
        if a is not None and '://' not in a:
            _links(a)

    for entity_id in request.registry.md.store.entity_ids():
        _links("/entities/%s" % hash_id(entity_id))

    for a in request.registry.aliases.keys():
        for v in request.registry.md.store.attribute(request.registry.aliases[a]):
            _links('%s/%s' % (a, quote_plus(v)))

    response = Response(dumps(jrd))
    response.headers['Content-Type'] = 'application/json'
    response.headers['Access-Control-Allow-Origin'] = '*'

    return response


def search(request):
    pass


def app_factory(global_config, **local_config):
    with Configurator(debug_logger=log) as ctx:
        if config.aliases is None:
            config.aliases = dict()

        if config.modules is None:
            config.modules = []

        ctx.registry.config = config
        config.modules.append('pyff.builtins')
        for mn in config.modules:
            importlib.import_module(mn)

        pipeline = global_config.get('pyff_pipeline', os.environ.get('PYFF_PIPELINE')).split(' ')
        ctx.registry.plumbings = [plumbing(v) for v in pipeline]
        ctx.registry.aliases = config.aliases
        ctx.registry.psl = PublicSuffixList()
        ctx.registry.md = MDRepository()
        ctx.registry.md.store = make_store_instance()

        ctx.add_route('robots', '/robots.txt')
        ctx.add_view(robots, route_name='robots')

        ctx.add_route('webfinger', '/.wellknown/webfinger', request_method='GET')
        ctx.add_view(webfinger, route_name='webfinger')

        ctx.add_route('status', '/api/status', request_method='GET')
        ctx.add_view(status, route_name='status')

        ctx.add_route('request', '/api/call/{entry}', request_method=['POST','PUT'])
        ctx.add_view(query, route_name='request')

        ctx.add_route('query', '/*path', request_method='GET')
        ctx.add_view(query, route_name='query')

        return ctx.make_wsgi_app()


def server_runner(*args):
    app = args[0]
    local_config = args[1]
    port = int(local_config.get('http_port', 8080))
    host = local_config.get('http_host', '0.0.0.0')
    s = make_server(host, port, app)
    s.serve_forever()


def main():
    server_runner(app_factory(None), '0.0.0.0', 8080)


if __name__ == '__main__':
    main()
