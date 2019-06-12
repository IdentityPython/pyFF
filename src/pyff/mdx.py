"""
An implementation of draft-lajoie-md-query

.. code-block:: bash

    Usage: pyffd <options> {pipeline-files}+

    -C|--no-caching
            Turn off caching
    -p <pidfile>
            Write a pidfile at the specified location
    -f
            Run in foreground
    -a
            Restart pyffd if any of the pipeline files change
    --log=<log> | -l<log>
            Set to either a file or syslog:<facility> (eg syslog:auth)
    --error-log=<log> | --access-log=<log>
            As --log but only affects the error or access log streams.
    --loglevel=<level>
            Set logging level
    -P<port>|--port=<port>
            Listen on the specified port
    -H<host>|--host=<host>
            Listen on the specified interface
    --frequency=<seconds>
            Wake up every <seconds> and run the update pipeline. By
            default the frequency is set to 600.
    -A<name:uri>|--alias=<name:uri>
            Add the mapping 'name: uri' to the toplevel URL alias
            table. This causes URLs on the form http://server/<name>/x
            to be processed as http://server/metadata/{uri}x. The
            default alias table is presented at http://server
    --dir=<dir>
            Chdir into <dir> after the server starts up.
    --proxy
            The service is running behind a proxy - respect the X-Forwarded-Host header.
    -m <module>|--modules=<module>
            Load a module

    {pipeline-files}+
            One or more pipeline files

"""

import importlib
import pkg_resources
import traceback
from six.moves.urllib_parse import urlparse, quote_plus
import os
import sys
from threading import Lock
import cherrypy
from cherrypy._cpdispatch import Dispatcher
from cherrypy._cperror import NotFound, HTTPError
from cherrypy.lib import cptools
from cherrypy.process.plugins import Monitor, SimplePlugin
from cherrypy.lib import caching
from simplejson import dumps
from .constants import config, parse_options
from .locks import ReadWriteLock
from .pipes import plumbing
from .utils import resource_string, duration2timedelta, debug_observer, render_template, hash_id, safe_b64e, safe_b64d
from .logs import get_log, SysLogLibHandler
from .samlmd import entity_simple_summary, entity_display_name, entity_info, MDRepository
import logging
from datetime import datetime
from publicsuffix2 import get_public_suffix
from .i18n import language
from . import samlmd
import six

if six.PY2:
    from cgi import escape
    _ = language.ugettext
else:
    from html import escape
    _ = language.gettext

log = get_log(__name__)
site_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "site")


class MDUpdate(Monitor):
    def __init__(self, bus, frequency=int(config.update_frequency), server=None):
        self.lock = Lock()
        self.server = server
        self.bus = bus
        Monitor.__init__(self, bus, lambda: self.run(server), frequency=frequency)
        self.subscribe()
        self.nruns = 0

    def run(self, server):
        locked = False
        try:
            self.lock.acquire()
            locked = True

            for p in server.plumbings:
                state = {'update': True}
                p.process(self.server.md, state=state)

            self.server.ready = True
        except Exception as ex:
            log.debug(traceback.format_exc())
            log.error(ex)
        finally:
            if locked:
                self.lock.release()

    def start(self):
        self.run(self.server)
        super(MDUpdate, self).start()

    def stop(self):
        super(MDUpdate, self).stop()

    start.priority = 80


class DirPlugin(SimplePlugin):
    def __init__(self, bus, d=None):
        SimplePlugin.__init__(self, bus)
        self.dir = d

    def start(self):
        os.chdir(self.dir)

    start.priority = 79


class EncodingDispatcher(object):
    """Cherrypy ass-u-me-s a lot about how requests are processed. In particular it is diffucult to send
    something that contains '/' and ':' (like a URL) using the standard dispatchers. This class provides
    a workaround by base64-encoding the troubling stuff and sending the result through the normal displatch
    pipeline. At the other end base64-encoded data is unpacked.
    """

    def __init__(self, prefixes, enc, next_dispatcher=Dispatcher()):
        self.prefixes = prefixes
        self.enc = enc
        self.next_dispatcher = next_dispatcher

    def dispatch(self, path_info):
        # log.debug("EncodingDispatcher (%s) called with %s" % (",".join(self.prefixes), path_info))
        # vpath = path_info.replace("%2F", "/")
        vpath = path_info
        for prefix in self.prefixes:
            if vpath.startswith(prefix):
                # log.debug("EncodingDispatcher (%s) called with %s" % (",".join(self.prefixes), path_info))
                vpath = path_info.replace("%2F", "/")
                plen = len(prefix)
                vpath = vpath[plen + 1:]
                npath = "%s/%s" % (prefix, self.enc(vpath))
                # log.debug("EncodingDispatcher %s" % npath.encode('ascii', errors='ignore'))
                if six.PY2:
                    npath = npath.encode('ascii', errors='ignore')
                return self.next_dispatcher(npath)
        return self.next_dispatcher(vpath)


class WellKnown(object):
    """Implementation of the .well-known URL namespace for pyFF. In particular this contains the webfinger
    implementation which returns information about up- and downstream metadata.
    """

    def __init__(self, server=None):
        self.server = server

    @cherrypy.expose
    def webfinger(self, resource=None, rel=None):
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
        if resource is None:
            resource = cherrypy.request.base

        jrd = dict()
        dt = datetime.now() + duration2timedelta("PT1H")
        jrd['expires'] = dt.isoformat()
        jrd['subject'] = cherrypy.request.base
        links = list()
        jrd['links'] = links

        _dflt_rels = {
            'urn:oasis:names:tc:SAML:2.0:metadata': '.xml',
            'disco-json': '.json'
        }

        if rel is None:
            rel = list(_dflt_rels.keys())
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
                                  href='%s/%s%s' % (cherrypy.request.base, url, suffix)))

        _links('/entities/')
        for a in self.server.md.store.collections():
            if a is not None and '://' not in a:
                _links(a)

        for entity_id in self.server.md.store.entity_ids():
            _links("/metadata/%s" % hash_id(entity_id))

        for a in list(self.server.aliases.keys()):
            for v in self.server.md.store.attribute(self.server.aliases[a]):
                _links('%s/%s' % (a, quote_plus(v)))

        cherrypy.response.headers['Content-Type'] = 'application/json'
        cherrypy.response.headers['Access-Control-Allow-Origin'] = '*'
        return dumps(jrd)


class NotImplementedFunction(object):
    def __init__(self, message):
        self.message = message

    def index(self):
        return self.message


class SHIBDiscovery(object):
    """
    An endpoint designed to provide backwards compatibility with standard shibboleth-based discovery services.
    """

    def __init__(self, server=None):
        self.server = server

    @cherrypy.expose
    def DS(self, *args, **kwargs):
        kwargs['path'] = "/role/idp.ds"
        kwargs['request_type'] = 'discovery'
        return self.server.request(**kwargs)

    @cherrypy.expose
    def WAYF(self, *args, **kwargs):
        raise HTTPError(400, _("400 Bad Request - shibboleth WAYF protocol not supported"))

    @cherrypy.expose
    def default(self, *args, **kwargs):
        log.debug("default args: %s, kwargs: %s" % (repr(args), repr(kwargs)))
        if len(args) > 0 and args[0] in self.server.aliases:
            kwargs['pfx'] = args[0]
            if len(args) > 1:
                kwargs['path'] = args[1]
            return self.server.request(**kwargs)
        else:
            kwargs['pfx'] = None
            kwargs['path'] = "/" + "/".join(args)
            return self.server.request(**kwargs)


class MDRoot(object):
    """The root application of pyFF. The root application assembles the MDStats and WellKnown classes with an
    MDServer instance.
    """

    def __init__(self, server):
        self.server = server
        self._well_known.server = server
        self.discovery.server = server

    discovery = SHIBDiscovery()

    _well_known = WellKnown()
    static = cherrypy.tools.staticdir.handler("/static", os.path.join(site_dir, "static"))

    @cherrypy.expose
    def status(self):
        status = "loading"
        if self.server.ready:
            status = "running"
        version = pkg_resources.require("pyFF")[0].version
        cherrypy.response.headers['Content-Type'] = 'application/json'
        cherrypy.response.headers['Access-Control-Allow-Origin'] = '*'
        return dumps({'status': status, 'version': version})

    @cherrypy.expose
    def shutdown(self):
        cfg = cherrypy.request.app.config['global']
        if 'allow_shutdown' in cfg and bool(cfg.get('allow_shutdown')):
            from threading import Timer
            Timer(3, cherrypy.engine.exit, ()).start()
            return "bye ..."
        else:  # pragma: nocover
            raise cherrypy.HTTPError(403, _("Endpoint disabled in configuration"))

    @cherrypy.expose
    @cherrypy.tools.expires(secs=3600, debug=True)
    def robots_txt(self):
        """Returns a robots.txt that disables all robots.
        """
        return """
User-agent: *
Disallow: /
"""

    @cherrypy.expose()
    @cherrypy.tools.expires(secs=3600, debug=True)
    def storage(self):
        """
        The crossdomain storage hub iframe
        """

        entity_id = cherrypy.request.params.get('entity_id')
        return render_template("storage.html")

    @cherrypy.expose
    def favicon_ico(self):
        """Returns the pyff icon (the alchemic symbol for sublimation).
        """
        cherrypy.response.headers['Content-Type'] = 'image/x-icon'
        return resource_string('favicon.ico', "site/static/icons")

    @cherrypy.expose
    def entities(self, path=None):
        """Process an MDX request with Content-Type hard-coded to application/xml. Regardless of the suffix
        you will get XML back from /entities/...
        """
        return self.server.request(path=path, request_type='mdq', content_type="application/xml")

    @cherrypy.expose
    def metadata(self, path=None):
        """The main request entry point. Any requests are subject to content negotiation based on Accept headers
        and based on file name extension. Requesting /metadata/foo.xml gets you (signed) XML (assuming your pipeline
        contains that mode), requesting /metadata/foo.json gets you json, and /metadata/foo.ds gets you a discovery
        interface based on the IdPs found in 'foo'. Here 'foo' is any supported lookup expression.
        """
        return self.server.request(path=path)

    @cherrypy.expose
    def about(self):
        """The 'about' page. Contains links to statistics etc.
        """
        import pkg_resources  # part of setuptools

        version = pkg_resources.require("pyFF")[0].version
        return render_template("about.html",
                               version=version,
                               cversion=cherrypy.__version__,
                               sysinfo=" ".join(os.uname()),
                               cmdline=" ".join(sys.argv),
                               repo=self.server.md,
                               plumbings=self.server.plumbings)

    @cherrypy.expose
    def reset(self):
        """The /reset page clears all local browser settings for the device. After visiting
        this page users of the discovery service will see a "new device" page.
        """
        return render_template("reset.html")

    @cherrypy.expose
    def settings(self):
        """The /settings page documents the (non) use of cookies.
        """
        return render_template("settings.html")

    @cherrypy.expose
    def search(self, query=None, entity_filter=None, related=None):
        """
Search the active set for matching entities.
        :param query: the string query
        :param entity_filter: an optional filter to apply to the active set before searching
        :param related: an optional '+'-separated list of related domain names for prioritizing search results
        :return: a JSON-formatted search result
        """
        cherrypy.response.headers['Content-Type'] = 'application/json'
        cherrypy.response.headers['Access-Control-Allow-Origin'] = '*'
        return dumps(self.server.md.store.search(query,
                                                 entity_filter=entity_filter,
                                                 related=related))

    @cherrypy.expose
    def index(self):
        """Alias for /metadata
        """
        return self.server.request()

    @cherrypy.expose
    def default(self, *args, **kwargs):
        """The default request processor unpacks base64-encoded reuqests and passes them onto the MDServer.request
        handler.
        """
        # log.debug("ROOT default args: %s, kwargs: %s" % (repr(args), repr(kwargs)))
        if len(args) > 0 and args[0] in self.server.aliases:
            kwargs['pfx'] = args[0]
            if len(args) > 1:
                kwargs['path'] = args[1]
            return self.server.request(**kwargs)
        else:
            kwargs['pfx'] = None
            kwargs['path'] = "/" + "/".join(args)
            return self.server.request(**kwargs)


class MDServer(object):
    """The MDServer class is the business logic of pyFF. This class is isolated from the request-decoding logic
    of MDRoot and from the ancilliary classes like MDStats and WellKnown.
    """

    def __init__(self, pipes=None, observers=None):

        if not observers:
            observers = []
        if not pipes:
            pipes = []
        self._pipes = pipes
        self.lock = ReadWriteLock()
        self.plumbings = [plumbing(v) for v in pipes]
        self.refresh = MDUpdate(cherrypy.engine, server=self, frequency=config.update_frequency)
        self.refresh.subscribe()
        self.aliases = config.aliases
        self.md = MDRepository()
        self.ready = False

        if config.autoreload:
            for f in pipes:
                cherrypy.engine.autoreload.files.add(f)

    def reload_pipeline(self):
        new_plumbings = [plumbing(v) for v in self._pipes]
        self.plumbings = new_plumbings

    class MediaAccept(object):

        def __init__(self):
            pass

        def has_key(self, key):
            return True

        def get(self, item):
            return self.__getitem__(item)

        def __getitem__(self, item):
            try:
                return cptools.accept(item, debug=True)
            except HTTPError:
                return False

    def request(self, **kwargs):
        """The main request processor. This code implements all rendering of metadata.
        """

        if not self.ready:
            raise HTTPError(503, _("Service Unavailable (repository loading)"))

        pfx = kwargs.get('pfx', None)
        path = kwargs.get('path', None)
        content_type = kwargs.get('content_type', None)
        request_type = kwargs.get('request_type', "negotiate")

        log.debug("MDServer pfx=%s, path=%s, content_type=%s" % (pfx, path, content_type))

        def _d(x, do_split=True):
            dot = six.u('.')
            if x is not None:
                x = x.strip()
            # log.debug("_d(%s,%s)" % (x, do_split))
            if x is None or len(x) == 0:
                return None, None

            if x.startswith("{base64}"):
                x = safe_b64d(x[8:])
                if isinstance(x, six.binary_type):
                    x = x.decode()

            if do_split and dot in x:
                (pth, _, extn) = x.rpartition(dot)
                if extn in _ctypes:
                    return pth, extn

            return x, None

        _ctypes = {'xml': 'application/xml',
                   'json': 'application/json',
                   'htm': 'text/html',
                   'html': 'text/html',
                   'ds': 'text/html',
                   's': 'application/json'}

        alias = None
        if pfx:
            alias = pfx
            pfx = self.aliases.get(alias, None)
            if pfx is None:
                raise NotFound()

        path, ext = _d(path, content_type is None)
        if pfx and path:
            q = "{%s}%s" % (pfx, path)
            path = "/%s/%s" % (alias, path)
        else:
            q = path

        if ext is not None:
            log.debug("request path: %s.%s, headers: %s" % (path, ext, cherrypy.request.headers))
        else:
            log.debug("request path: %s, headers: %s" % (path, cherrypy.request.headers))

        accept = {}
        if content_type is None:
            if ext is not None and ext in _ctypes:
                accept = {_ctypes[ext]: True}
            else:
                accept = MDServer.MediaAccept()
                if ext is not None:
                    path = "%s.%s" % (path, ext)
        else:
            accept = {content_type: True}

        with self.lock.readlock:
            if ext == 'ds':
                pdict = dict()
                entity_id = kwargs.get('entityID', None)
                if entity_id is None:
                    raise HTTPError(400, _("400 Bad Request - missing entityID"))

                e = self.md.store.lookup(entity_id)
                if e is None or len(e) == 0:
                    raise HTTPError(404)

                if len(e) > 1:
                    raise HTTPError(400, _("Bad Request - multiple matches for") + " %s" % entity_id)

                pdict['entity'] = entity_simple_summary(e[0])
                if not path:
                    pdict['search'] = "/search/"
                    pdict['list'] = "/role/idp.json"
                else:
                    pdict['search'] = "{}.s".format(escape(path, quote=True))
                    pdict['list'] = "{}.json".format(escape(path, quote=True))

                pdict['storage'] = "/storage/"
                cherrypy.response.headers['Content-Type'] = 'text/html'
                return render_template(config.ds_template, **pdict)
            elif ext == 's':
                query = kwargs.get('query', None)
                entity_filter = kwargs.get('entity_filter', None)
                related = kwargs.get('related', None)

                cherrypy.response.headers['Content-Type'] = 'application/json'
                cherrypy.response.headers['Access-Control-Allow-Origin'] = '*'

                if query is None:
                    log.debug("empty query - creating one")
                    query = [cherrypy.request.remote.ip]
                    referrer = cherrypy.request.headers.get('referrer', None)
                    if referrer is not None:
                        log.debug("including referrer: %s" % referrer)
                        url = urlparse(referrer)
                        host = url.netloc
                        if ':' in url.netloc:
                            (host, port) = url.netloc.split(':')
                        for host_part in host.rstrip(get_public_suffix(host)).split('.'):
                            if host_part is not None and len(host_part) > 0:
                                query.append(host_part)
                    log.debug("created query: %s" % ",".join(query))

                return dumps(self.md.store.search(query,
                                                  path=q,
                                                  entity_filter=entity_filter,
                                                  related=related))
            elif accept.get('text/html'):
                if not q:
                    if pfx:
                        title = pfx
                    else:
                        title = _("Metadata By Attributes")
                    return render_template("index.html",
                                           md=self.md,
                                           samlmd=samlmd,
                                           alias=alias,
                                           aliases=self.aliases,
                                           title=title)
                else:
                    entities = self.md.lookup(q)
                    if not entities:
                        raise NotFound()
                    if len(entities) > 1:
                        return render_template("metadata.html",
                                               md=self.md,
                                               samlmd=samlmd,
                                               subheading=q,
                                               entities=entities)
                    else:
                        entity = entities[0]
                        return render_template("entity.html",
                                               headline=entity_display_name(entity),
                                               subheading=entity.get('entityID'),
                                               entity_id=entity.get('entityID'),
                                               samlmd=samlmd,
                                               entity=entity_info(entity))
            else:
                for p in self.plumbings:
                    state = {'request': request_type,
                             'headers': {'Content-Type': 'text/xml'},
                             'accept': accept,
                             'url': cherrypy.url(relative=False),
                             'select': q,
                             'path': path,
                             'stats': {}}
                    r = p.process(self.md, state=state)
                    if r is not None:
                        cache_ttl = state.get('cache', 0)
                        log.debug("caching for %d seconds" % cache_ttl)
                        for k, v in list(state.get('headers', {}).items()):
                            cherrypy.response.headers[k] = v
                        cherrypy.response.headers['Access-Control-Allow-Origin'] = '*'
                        caching.expires(secs=cache_ttl)
                        return r
        raise NotFound()


def main():
    """
    The main entrypoint for the pyffd command.
    """
    args = parse_options("pyffd",
                         __doc__,
                         'hP:p:H:CfaA:l:Rm:',
                         ['help', 'loglevel=', 'log=', 'access-log=', 'error-log=',
                          'port=', 'host=', 'no-caching', 'autoreload', 'frequency=', 'module=',
                          'alias=', 'dir=', 'version', 'proxy', 'allow_shutdown'])

    engine = cherrypy.engine
    plugins = cherrypy.process.plugins

    if config.daemonize:
        cherrypy.config.update({'environment': 'production'})
        cherrypy.config.update({'log.screen': False})
        if config.error_log is None:
            config.error_log = 'syslog:daemon'
        if config.access_log is None:
            config.access_log = 'syslog:daemon'
        plugins.Daemonizer(engine).subscribe()

    if config.base_dir is not None:
        DirPlugin(engine, config.base_dir).subscribe()

    if config.pid_file:
        plugins.PIDFile(engine, config.pid_file).subscribe()

    def _b64(p):
        if p:
            return "{base64}%s" % safe_b64e(p)
        else:
            return ""

    def error_page(code, **kwargs):
        return render_template("%d.html" % code, **kwargs)

    observers = []

    if config.loglevel == logging.DEBUG:
        observers.append(debug_observer)

    config.modules.append('pyff.builtins')
    for mn in config.modules:
        importlib.import_module(mn)

    server = MDServer(pipes=args, observers=observers)

    pfx = ["/entities", "/metadata"] + ["/" + x for x in list(server.aliases.keys())]
    cfg = {
        'global': {
            'tools.encode.on': True,
            'tools.encode.text_only': False,
            'tools.encode.encoding': 'UTF-8',
            'server.socket_port': config.port,
            'server.socket_host': config.bind_address,
            'tools.caching.on': config.caching_enabled,
            'tools.caching.debug': config.caching_enabled,
            'tools.trailing_slash.on': True,
            'tools.caching.maxobj_size': 1000000000000,  # effectively infinite
            'tools.caching.maxsize': 1000000000000,
            'tools.caching.antistampede_timeout': 30,
            'tools.caching.delay': 3600,  # this is how long we keep static stuff
            'checker.on': False,
            'log.screen': True,
            'tools.proxy.on': config.proxy,
            'allow_shutdown': config.allow_shutdown,
            'error_page.404': lambda **kwargs: error_page(404, _=_, **kwargs),
            'error_page.503': lambda **kwargs: error_page(503, _=_, **kwargs),
            'error_page.500': lambda **kwargs: error_page(500, _=_, **kwargs),
            'error_page.400': lambda **kwargs: error_page(400, _=_, **kwargs)
        },
        '/': {
            'tools.encode.on': True,
            'tools.encode.encoding': 'UTF-8',
            'tools.caching.delay': config.caching_delay,
            'tools.proxy.on': config.proxy,
            'request.dispatch': EncodingDispatcher(pfx, _b64).dispatch,
            'request.dispatpch.debug': True,
        },
        '/static': {
            'tools.caching.on': config.caching_enabled,
            'tools.caching.delay': config.caching_delay,
            'tools.proxy.on': config.proxy
        },
        '/shutdown': {
            'allow_shutdown': config.allow_shutdown
        }
    }
    cherrypy.config.update(cfg)

    if config.error_log is not None:
        cherrypy.config.update({'log.screen': False})

    root = MDRoot(server)
    app = cherrypy.tree.mount(root, config=cfg)
    app.log.error_log.setLevel(config.loglevel)
    log_args = {'level': config.loglevel}
    if config.error_log is not None:
        log_args['filename'] = config.error_log
    logging.basicConfig(**log_args)

    if config.error_log is not None:
        if config.error_log.startswith('syslog:'):
            facility = config.error_log[7:]
            h = SysLogLibHandler(facility=facility)
            app.log.error_log.addHandler(h)
            cherrypy.config.update({'log.error_file': ''})
        else:
            cherrypy.config.update({'log.error_file': config.error_log})

    if config.access_log is not None:
        if config.access_log.startswith('syslog:'):
            facility = config.access_log[7:]
            h = SysLogLibHandler(facility=facility)
            app.log.access_log.addHandler(h)
            cherrypy.config.update({'log.access_file': ''})
        else:
            cherrypy.config.update({'log.access_file': config.access_log})

    engine.signals.subscribe()
    try:
        engine.start()
    except Exception as ex:
        logging.debug(traceback.format_exc())
        logging.error(ex)
        sys.exit(1)
    else:
        engine.block()


if __name__ == "__main__":
    main()
