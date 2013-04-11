"""
An implementation of draft-lajoie-md-query

Usage: pyffd <options> {pipeline-files}+

    -C|--no-cache
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
    {pipeline-files}+
            One or more pipeline files

"""
from StringIO import StringIO
import getopt
import traceback
from cherrypy.lib.cpstats import StatsPage
import os
import sys
from threading import RLock
import cherrypy
from cherrypy._cpdispatch import Dispatcher
from cherrypy._cperror import NotFound, HTTPError
from cherrypy.lib import cptools, static
from cherrypy.process.plugins import Monitor, SimplePlugin
from cherrypy.lib import caching
from simplejson import dumps
from pyff.constants import ATTRS
from pyff.locks import ReadWriteLock
from pyff.mdrepo import MDRepository
from pyff.pipes import plumbing
from pyff.utils import resource_string, template, xslt_transform, dumptree, duration2timedelta
from pyff.logs import log, SysLogLibHandler
import logging
from pyff.stats import stats
import lxml.html as html
from datetime import datetime

__author__ = 'leifj'
from pyff import __version__ as pyff_version


class MDUpdate(Monitor):
    def __init__(self, bus, frequency=600, server=None):
        self.lock = RLock()
        self.server = server
        self.bus = bus
        Monitor.__init__(self, bus, lambda: self.run(server), frequency=frequency)
        self.subscribe()

    def run(self, server):
        locked = False
        try:
            if self.lock.acquire(blocking=0):
                locked = True
                md = self.server.new_repository()
                for p in server.plumbings:
                    state = {'update': True, 'stats': {}}
                    p.process(md, state)
                    stats.update(state.get('stats', {}))
                if not md.sane():
                    log.error("update produced insane active repository - will try again later...")
                with server.lock.writelock:
                    log.debug("update produced new repository with %d entities" % md.index.size())
                    server.md = md
                    stats['Repository Update Time'] = datetime.now()
                    stats['Repository Size'] = md.index.size()
            else:
                log.error("another instance is running - will try again later...")
        except Exception, ex:
            traceback.print_exc()
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
    def __init__(self, prefixes, enc, next_dispatcher=Dispatcher()):
        self.prefixes = prefixes
        self.enc = enc
        self.next_dispatcher = next_dispatcher

    def dispatch(self, path_info):
        #log.debug("EncodingDispatcher (%s) called with %s" % (",".join(self.prefixes),path_info))
        vpath = path_info.replace("%2F", "/")
        for prefix in self.prefixes:
            if vpath.startswith(prefix):
                plen = len(prefix)
                vpath = vpath[plen + 1:]
                npath = "%s/%s" % (prefix, self.enc(vpath))
                #log.debug("EncodingDispatcher %s" % npath)
                return self.next_dispatcher(npath)
        return self.next_dispatcher(vpath)


site_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "site")

from lxml import etree


class MDStats(StatsPage):
    @cherrypy.expose
    def index(self):
        h = "".join(super(MDStats, self).index())
        parser = etree.HTMLParser()
        tree = etree.parse(StringIO(h), parser)
        body = tree.getroot().find("body")
        body.tag = 'div'
        str = etree.tostring(body, pretty_print=True, method="html")
        return template("basic.html").render(content=str, http=cherrypy.request)


class WellKnown():
    def __init__(self, server=None):
        self.server = server

    @cherrypy.expose
    def webfinger(self, resource=None, rel=None):
        if resource is None:
            raise cherrypy.HTTPError(400, "Bad Request - missing resource parameter")

        jrd = dict()
        dt = datetime.now() + duration2timedelta("PT1H")
        jrd['expires'] = dt.isoformat()
        jrd['subject'] = cherrypy.request.base
        links = list()
        jrd['links'] = links

        def _links(a):
            links.append(
                dict(rel='urn:oasis:names:tc:SAML:2.0:metadata', href='%s/%s.xml' % (cherrypy.request.base, a)))
            links.append(dict(rel='disco-json', href='%s/%s.json' % (cherrypy.request.base, a)))

        for a in self.server.md.keys():
            if not '://' in a:
                a = a.lstrip('/')
                _links(a)
            elif 'http://' in a or 'https://' in a:
                links.append(dict(rel='urn:oasis:names:tc:SAML:2.0:metadata',
                                  href=a,
                                  properties=dict()))

        for a in self.server.aliases.keys():
            for v in self.server.md.index.attribute(self.server.aliases[a]):
                _links('%s/%s' % (a, v))

        cherrypy.response.headers['Content-Type'] = 'application/json'
        return dumps(jrd)


class MDRoot():
    def __init__(self, server):
        self.server = server
        self._well_known.server = server

    stats = MDStats()
    _well_known = WellKnown()

    @cherrypy.expose
    @cherrypy.tools.expires(secs=3600, debug=True)
    def robots_txt(self):
        return """
User-agent: *
Disallow: /
"""

    @cherrypy.expose
    @cherrypy.tools.expires(secs=3600, debug=True)
    def favicon_ico(self):
        cherrypy.response.headers['Content-Type'] = 'image/x-icon'
        return resource_string('favicon.ico', "site/static/icons")

    @cherrypy.expose
    @cherrypy.tools.expires(secs=600, debug=True)
    def entities(self, path=None):
        return self.server.request(path=path, content_type="application/xml")

    @cherrypy.expose
    @cherrypy.tools.expires(secs=600, debug=True)
    def metadata(self, path=None):
        return self.server.request(path=path)

    @cherrypy.expose
    def finger(self, domain="localhost"):
        return template("finger.html").render(http=cherrypy.request, domain=domain)

    @cherrypy.expose
    def about(self):
        import pkg_resources  # part of setuptools

        version = pkg_resources.require("pyFF")[0].version
        return template("about.html").render(version=version,
                                             cversion=cherrypy.__version__,
                                             sysinfo=" ".join(os.uname()),
                                             http=cherrypy.request,
                                             cmdline=" ".join(sys.argv),
                                             stats=stats,
                                             repo=self.server.md,
                                             plumbings=["%s" % p for p in self.server.plumbings])

    @cherrypy.expose
    def search(self, paged=False, query=None, page=0, page_limit=10, entity_filter=None):
        """
Search the active set for matching entities.
        :param paged: page the result when True
        :param query: the string query
        :param page: the page to return of the paged result
        :param page_limit: the number of result per page
        :param entity_filter: an optional filter to apply to the active set before searching
        :return: a JSON-formatted search result
        """
        cherrypy.response.headers['Content-Type'] = 'application/json'
        if paged:
            res, more, total = self.server.md.search(query, page=int(page), page_limit=int(page_limit),
                                                     entity_filter=entity_filter)
            return dumps({'entities': res, 'more': more, 'total': total})
        else:
            return dumps(self.server.md.search(query))

    @cherrypy.expose
    def index(self):
        return self.server.request()

    @cherrypy.expose
    def static(self):
        return static.staticdir("/static", site_dir, debug=True)

    @cherrypy.expose
    def default(self, *args, **kwargs):
        log.debug("request default: %s" % ",".join(args))
        if len(args) > 0 and args[0] in self.server.aliases:
            kwargs['pfx'] = args[0]
            if len(args) > 1:
                kwargs['path'] = args[1]
            return self.server.request(**kwargs)
        else:
            log.debug("not an alias: %s" % "/".join(args))
            kwargs['pfx'] = None
            kwargs['path'] = "/" + "/".join(args)
            return self.server.request(**kwargs)

            #@cherrypy.expose
            #def default(self,pfx,path=None):
            #    log.debug("pfx=%s,path=%s" % (pfx,path))
            #    return self.server.request(pfx,path)


class MDServer():
    def __init__(self, pipes=None, autoreload=False, frequency=600, aliases=ATTRS, cache_enabled=True):
        if not pipes: pipes = []
        self.cache_enabled = cache_enabled
        self._md = None
        self.lock = ReadWriteLock()
        self.plumbings = [plumbing(v) for v in pipes]
        self.refresh = MDUpdate(cherrypy.engine, server=self, frequency=frequency)
        self.refresh.subscribe()
        self.aliases = aliases

        if autoreload:
            for f in pipes:
                cherrypy.engine.autoreload.files.add(f)

    def _set_md(self, md):
        self._md = md

    def _get_md(self):
        if self._md is None:
            raise cherrypy.HTTPError(503, message="Repository loading...")
        return self._md

    md = property(_get_md, _set_md)

    def new_repository(self):
        return MDRepository(metadata_cache_enabled=self.cache_enabled)

    class MediaAccept():
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
        stats['MD Requests'] += 1

        pfx = kwargs.get('pfx', None)
        path = kwargs.get('path', None)
        content_type = kwargs.get('content_type', None)

        log.debug("request pfx=%s, path=%s, content_type=%s" % (pfx, path, content_type))

        def escape(m):
            st = m.group(0)
            if st == '<':
                return '&lt;'
            if st == '>':
                return '&gt;'
            return st

        def _d(x):
            if x is None or len(x) == 0:
                return None, None

            if x.startswith("{base64}"):
                x = x[8:].decode('base64')

            if '.' in x:
                (p, sep, ext) = x.rpartition('.')
                return p, ext
            else:
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

        path, ext = _d(path)
        if pfx and path:
            q = "{%s}%s" % (pfx, path)
        else:
            q = path

        logging.debug("request %s %s" % (path, ext))
        log.debug(cherrypy.request.headers)
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
                pdict['http'] = cherrypy.request
                entityID = kwargs.get('entityID', None)
                if entityID is None:
                    raise HTTPError(400, "400 Bad Request - missing entityID")
                pdict['sp'] = self.md.sha1_id(entityID)
                pdict['ret'] = kwargs.get('return', None)
                if not path:
                    pdict['search'] = "/search/"
                else:
                    pdict['search'] = "%s.s" % path
                if pdict['ret'] is None:
                    raise HTTPError(400, "400 Bad Request - Missing 'return' parameter")
                pdict['returnIDParam'] = kwargs.get('returnIDParam', 'entityID')
                cherrypy.response.headers['Content-Type'] = 'text/html'
                pdict['style'] = '/static/css/style.css'  # TODO figure out how to sensibly set this per request

                return template("ds.html").render(**pdict)
            elif ext == 's':
                paged = bool(kwargs.get('paged', False))
                query = kwargs.get('query', None)
                page = kwargs.get('page', 0)
                page_limit = kwargs.get('page_limit', 10)
                entity_filter = kwargs.get('entity_filter', None)

                cherrypy.response.headers['Content-Type'] = 'application/json'
                if paged:
                    res, more, total = self.md.search(query,
                                                      path=q,
                                                      page=int(page),
                                                      page_limit=int(page_limit),
                                                      entity_filter=entity_filter)
                    log.debug(dumps({'entities': res, 'more': more, 'total': total}))
                    return dumps({'entities': res, 'more': more, 'total': total})
                else:
                    return dumps(self.md.search(query, path=q, entity_filter=entity_filter))
            elif accept.get('text/html'):
                if not q:
                    if pfx:
                        title = pfx
                    else:
                        title = "Metadata By Attributes"
                    return template("index.html").render(http=cherrypy.request,
                                                         md=self.md,
                                                         alias=alias,
                                                         aliases=self.aliases,
                                                         title=title)
                else:
                    entities = self.md.lookup(q)
                    if not entities:
                        raise NotFound()
                    if len(entities) > 1:
                        return template("metadata.html").render(http=cherrypy.request, md=self.md, entities=entities)
                    else:
                        entity = entities[0]
                        t = html.fragment_fromstring(unicode(xslt_transform(entity, "entity2html.xsl")))
                        for c_elt in t.findall(".//code[@role='entity']"):
                            c_txt = dumptree(entity, pretty_print=True, xml_declaration=False).decode("utf-8")
                            p = c_elt.getparent()
                            p.remove(c_elt)
                            if p.text is not None:
                                p.text += c_txt  # re.sub(".",escape,c_txt)
                            else:
                                p.text = c_txt  # re.sub(".",escape,c_txt)
                        xml = dumptree(t, xml_declaration=False).decode('utf-8')
                        return template("basic.html").render(http=cherrypy.request, content=xml)
            else:
                for p in self.plumbings:
                    state = {'request': True,
                             'headers': {'Content-Type': 'text/xml'},
                             'accept': accept,
                             'url': cherrypy.url(relative=False),
                             'select': q,
                             'stats': {}}
                    r = p.process(self.md, state=state)
                    if r is not None:
                        cache_ttl = state.get('cache', 0)
                        log.debug("caching for %d seconds" % cache_ttl)
                        caching.expires(secs=cache_ttl)
                        for k, v in state.get('headers', {}).iteritems():
                            cherrypy.response.headers[k] = v
                        return r
        raise NotFound()


def main():
    """
    The main entrypoint for the pyFF mdx server.
    """
    try:
        opts, args = getopt.getopt(sys.argv[1:],
                                   'hP:p:H:CfaA:l:',
                                   ['help', 'loglevel=', 'log=', 'access-log=', 'error-log=', 'port=', 'host=',
                                    'no-caching', 'autoreload', 'frequency=', 'alias=', 'dir=', 'version'])
    except getopt.error, msg:
        print msg
        print __doc__
        sys.exit(2)

    loglevel = logging.INFO
    error_log = None
    access_log = None
    port = 8080
    host = "127.0.0.1"
    pidfile = "/var/run/pyffd.pid"
    caching = True
    delay = 300
    daemonize = True
    autoreload = False
    frequency = 600
    aliases = ATTRS
    base_dir = None

    try:
        for o, a in opts:
            if o in ('-h', '--help'):
                print __doc__
                sys.exit(0)
            elif o == '--loglevel':
                loglevel = getattr(logging, a.upper(), None)
                if not isinstance(loglevel, int):
                    raise ValueError('Invalid log level: %s' % loglevel)
            elif o in ('--log', '-l'):
                error_log = a
                access_log = a
            elif o in '--error-log':
                error_log = a
            elif o in '--access-log':
                access_log = a
            elif o in ('--host', '-H'):
                host = a
            elif o in ('--port', '-P'):
                port = int(a)
            elif o in ('--pidfile', '-p'):
                pidfile = a
            elif o in ('--no-caching', '-C'):
                caching = False
            elif o in ('--caching-delay', 'D'):
                delay = int(caching)
            elif o in ('--foreground', '-f'):
                daemonize = False
            elif o in ('--autoreload', '-a'):
                autoreload = True
            elif o in '--frequency':
                frequency = int(a)
            elif o in ('-A', '--alias'):
                (a, sep, uri) = a.lpartition(':')
                if a and uri:
                    aliases[a] = uri
            elif o in '--dir':
                base_dir = a
            elif o in '--version':
                print "pyffd version %s (cherrypy version %s)" % (pyff_version, cherrypy.__version__)
                sys.exit(0)
            else:
                raise ValueError("Unknown option '%s'" % o)

    except Exception, ex:
        print ex
        print __doc__
        sys.exit(3)

    engine = cherrypy.engine
    plugins = cherrypy.process.plugins

    if daemonize:
        cherrypy.config.update({'environment': 'production'})
        cherrypy.config.update({'log.screen': False})
        if error_log is None:
            error_log = 'syslog:daemon'
        if access_log is None:
            access_log = 'syslog:daemon'
        plugins.Daemonizer(engine).subscribe()

    if base_dir is not None:
        DirPlugin(engine, base_dir).subscribe()

    if pidfile:
        plugins.PIDFile(engine, pidfile).subscribe()

    def _b64(p):
        if p:
            return "{base64}%s" % p.encode('base64')
        else:
            return ""

    def error_page(code, **kwargs):
        kwargs['http'] = cherrypy.request
        return template("%d.html" % code).render(**kwargs)

    server = MDServer(pipes=args, autoreload=autoreload, frequency=frequency, aliases=aliases, cache_enabled=caching)
    pfx = ["/entities", "/metadata"] + ["/" + x for x in server.aliases.keys()]

    cfg = {
        'global': {
            'server.socket_port': port,
            'server.socket_host': host,
            'tools.caching.on': caching,
            'tools.caching.debug': True,
            'tools.trailing_slash.on': True,
            'tools.caching.maxobj_size': 1000000000000, # effectively infinite
            'tools.caching.maxsize': 1000000000000,
            'tools.caching.antistampede_timeout': None,
            'tools.caching.delay': 3600,  # this is how long we keep static stuff
            'tools.cpstats.on': True,
            'error_page.404': lambda **kwargs: error_page(404, **kwargs),
            'error_page.503': lambda **kwargs: error_page(503, **kwargs),
            'error_page.500': lambda **kwargs: error_page(500, **kwargs),
            'error_page.400': lambda **kwargs: error_page(400, **kwargs)
        },
        '/': {
            'tools.caching.delay': delay,
            'tools.staticdir.root': site_dir,
            'tools.cpstats.on': True,
            'request.dispatch': EncodingDispatcher(pfx, _b64).dispatch,
            'request.dispatpch.debug': True,
        },
        '/static': {
            'tools.staticdir.on': True,
            'tools.staticdir.root': site_dir,
            'tools.staticdir.dir': "static",
        }
    }
    cherrypy.config.update(cfg)

    if error_log is not None:
        cherrypy.config.update({'log.screen': False})

    root = MDRoot(server)
    app = cherrypy.tree.mount(root, config=cfg)
    if error_log is not None:
        if error_log.startswith('syslog:'):
            facility = error_log[7:]
            h = SysLogLibHandler(facility=facility)
            app.log.error_log.addHandler(h)
            cherrypy.config.update({'log.error_file': ''})
        else:
            cherrypy.config.update({'log.error_file': error_log})

    if access_log is not None:
        if access_log.startswith('syslog:'):
            facility = error_log[7:]
            h = SysLogLibHandler(facility=facility)
            app.log.access_log.addHandler(h)
            cherrypy.config.update({'log.access_file': ''})
        else:
            cherrypy.config.update({'log.access_file': access_log})

    app.log.error_log.setLevel(loglevel)

    try:
        engine.start()
    except Exception, ex:
        logging.error(ex)
        sys.exit(1)
    else:
        engine.block()


if __name__ == "__main__":
    main()