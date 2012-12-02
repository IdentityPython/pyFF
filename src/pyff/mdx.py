"""
An implementation of draft-lajoie-md-query

Usage: pyffd [-C|--no-cache] [-p <pidfile>] [-f] [-a] [--loglevel=<level>]
             [-P<port>|--port=<port>] [-H<host>|--host=<host>] {pipeline-files}+

    -C|--no-cache
            Turn off caching
    -p <pidfile>
            Write a pidfile at the specified location
    -f
            Run in foreground
    -a
            Restart pyffd if any of the pipeline files change
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
from cherrypy.lib import cptools,static
from cherrypy.process.plugins import Monitor
from cherrypy.lib import caching
from simplejson import dumps
from pyff.constants import ATTRS
#from pyff.dj import DiscoJuice
from pyff.locks import ReadWriteLock
from pyff.mdrepo import MDRepository
from pyff.pipes import plumbing
from pyff.utils import resource_string, template, xslt_transform, dumptree
from pyff.logs import log
import logging
from pyff.stats import stats
import lxml.html as html
from datetime import datetime

__author__ = 'leifj'

class MDUpdate(Monitor):
    def __init__(self,bus,frequency=600,server=None):
        self.lock = RLock()
        self.server = server
        self.bus = bus
        Monitor.__init__(self,bus,lambda:self.run(server),frequency=frequency)

    def run(self,server):
        locked = False
        try:
            if self.lock.acquire(blocking=0):
                locked = True
                md = self.server.new_repository()
                for p in server.plumbings:
                    state={'update':True,'stats':{}}
                    p.process(md,state)
                    stats.update(state.get('stats',{}))
                if not md.sane():
                    log.error("update produced insane active repository - will try again later...")
                with server.lock.writelock:
                    log.debug("update produced new repository with %d entities" % md.index.size())
                    server.md = md
                    stats['Repository Update Time'] = datetime.now()
                    stats['Repository Size'] = md.index.size()
            else:
                log.error("another instance is running - will try again later...")
        except Exception,ex:
            traceback.print_exc()
        finally:
            if locked:
                self.lock.release()

class EncodingDispatcher(object):
    def __init__(self,prefixes,enc,next_dispatcher=Dispatcher()):
        self.prefixes = prefixes
        self.enc = enc
        self.next_dispatcher = next_dispatcher

    def dispatch(self,path_info):
        log.debug("EncodingDispatcher (%s) called with %s" % (",".join(self.prefixes),path_info))
        vpath = path_info.replace("%2F", "/")
        for prefix in self.prefixes:
            if vpath.startswith(prefix):
                plen = len(prefix)
                vpath = vpath[plen+1:]
                npath =  "%s/%s" % (prefix,self.enc(vpath))
                log.debug("EncodingDispatcher %s" % npath)
                return self.next_dispatcher(npath)
        return self.next_dispatcher(vpath)

site_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)),"site")

from lxml import etree

class MDStats(StatsPage):

    @cherrypy.expose
    def index(self):
        h = "".join(super(MDStats,self).index())
        parser = etree.HTMLParser()
        tree = etree.parse(StringIO(h), parser)
        body = tree.getroot().find("body")
        body.tag = 'div'
        str = etree.tostring(body,pretty_print=True,method="html")
        return template("basic.html").render(content=str,http=cherrypy.request)

class MDRoot():
    def __init__(self,server):
        self.server = server

    stats = MDStats()

    @cherrypy.expose
    @cherrypy.tools.expires(secs=3600,debug=True)
    def robots_txt(self):
        return """
User-agent: *
Disallow: /
"""

    @cherrypy.expose
    @cherrypy.tools.expires(secs=3600,debug=True)
    def favicon_ico(self):
        cherrypy.response.headers['Content-Type'] = 'image/x-icon'
        return resource_string('favicon.ico',"site/static/icons")

    @cherrypy.expose
    @cherrypy.tools.expires(secs=600,debug=True)
    def entities(self,path=None):
        return self.server.request(path=path,content_type="application/xml")

    @cherrypy.expose
    @cherrypy.tools.expires(secs=600,debug=True)
    def metadata(self,path=None):
        return self.server.request(path=path)

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
            plumbings=["%s" % p for p in self.server.plumbings],
        )

    @cherrypy.expose
    def search(self,query):
        cherrypy.response.headers['Content-Type'] = 'application/json'
        return dumps(self.server.md.search(query))

    @cherrypy.expose
    def index(self):
        return self.server.request()

    @cherrypy.expose
    def static(self):
        return static.staticdir("/static",site_dir,debug=True)

    @cherrypy.expose
    def default(self,pfx,path=None):
        return self.server.request(pfx,path)

class MDServer():
    def __init__(self, pipes=None, autoreload=False, frequency=600, aliases=ATTRS,cache_enabled=True):
        if not pipes: pipes = []
        self.cache_enabled = cache_enabled
        self._md = None
        self.lock = ReadWriteLock()
        self.plumbings = [plumbing(v) for v in pipes]
        self.refresh = MDUpdate(cherrypy.engine,server=self,frequency=frequency)
        self.refresh.subscribe()
        self.aliases = aliases

        if autoreload:
            for f in pipes:
                cherrypy.engine.autoreload.files.add(f)

    def _set_md(self,md):
        self._md = md

    def _get_md(self):
        if self._md is None:
            raise cherrypy.HTTPError(503,message="Repository loading...")
        return self._md

    md = property(_get_md,_set_md)

    def new_repository(self):
        return MDRepository(metadata_cache_enabled=self.cache_enabled)

    def start(self):
        self.refresh.run(self)

    class MediaAccept():
        def has_key(self,key):
            return True

        def get(self,item):
            return self.__getitem__(item)

        def __getitem__(self, item):
            try:
                return cptools.accept(item,debug=True)
            except HTTPError:
                return False

    def request(self,pfx=None,path=None,content_type=None):
        stats['MD Requests'] += 1

        def escape(m):
            str = m.group(0)
            if str == '<':
                return '&lt;'
            if str == '>':
                return '&gt;'
            return str

        def _d(x):
            if x is None or len(x) == 0:
                return None,None

            if x.startswith("{base64}"):
                x = x[8:].decode('base64')

            if '.' in x:
                (p,sep,ext) = x.rpartition('.')
                return p,ext
            else:
                return x,None

        _ctypes = {'xml': 'application/xml',
                   'json': 'application/json',
                    'htm': 'text/html',
                    'html': 'text/html'}

        alias=None
        if pfx:
            alias = pfx
            pfx = self.aliases.get(alias,None)
            if pfx is None:
                raise NotFound()

        path,ext = _d(path)
        if pfx and path:
            path = "{%s}%s" % (pfx,path)

        logging.debug("request %s %s" % (path,ext))
        log.debug(cherrypy.request.headers)
        accept = {}
        if content_type is None:
            if ext is not None and ext in _ctypes:
                accept = {_ctypes[ext]:True}
            else:
                accept = MDServer.MediaAccept()
                if ext is not None:
                    path = "%s.%s" % (path,ext)
        else:
            accept = {content_type:True}
        with self.lock.readlock:
            if accept.get('text/html'):
                if not path:
                    if pfx:
                        title=pfx
                    else:
                        title="Metadata By Attributes"
                    return template("index.html").render(http=cherrypy.request,
                        md=self.md,
                        alias=alias,
                        aliases=self.aliases,
                        title=title)
                else:
                    entities = self.md.lookup(path)
                    if not entities:
                        raise NotFound()
                    if len(entities) > 1:
                        return template("metadata.html").render(http=cherrypy.request,md=self.md,entities=entities)
                    else:
                        entity = entities[0]
                        t = html.fragment_fromstring(unicode(xslt_transform(entity,"entity2html.xsl")))
                        for c_elt in t.findall(".//code[@role='entity']"):
                            c_txt = dumptree(entity,pretty_print=True,xml_declaration=False).decode("utf-8")
                            p = c_elt.getparent()
                            p.remove(c_elt)
                            if p.text is not None:
                                p.text += c_txt #re.sub(".",escape,c_txt)
                            else:
                                p.text = c_txt # re.sub(".",escape,c_txt)
                        xml = dumptree(t,xml_declaration=False).decode('utf-8')
                        return template("basic.html").render(http=cherrypy.request,content=xml)
            else:
                for p in self.plumbings:
                    state = {'request': True,
                             'headers':{'Content-Type': 'text/xml'},
                             'accept': accept,
                             'url': cherrypy.url(relative=False),
                             'select': path,
                             'stats':{}}
                    r = p.process(self.md,state=state)
                    if r is not None:
                        cache_ttl = state.get('cache',0)
                        log.debug("caching for %d seconds" % cache_ttl)
                        caching.expires(secs=cache_ttl)
                        for k,v in state.get('headers',{}).iteritems():
                            cherrypy.response.headers[k] = v
                        return r
        raise NotFound()


def main():
    """
    The main entrypoint for the pyFF mdx server.
    """
    try:
        opts, args = getopt.getopt(sys.argv[1:],
            'hP:p:H:CfaA:',
            ['help', 'loglevel=','port=','host=','no-caching','autoreload','frequency=','alias='])
    except getopt.error, msg:
        print msg
        print __doc__
        sys.exit(2)

    loglevel = logging.INFO
    logfile = None #TODO configure logging file(s)
    port = 8080
    host = "127.0.0.1"
    pidfile = "/var/run/pyffd.pid"
    caching = True
    delay = 300
    daemonize = True
    autoreload = False
    frequency = 600
    aliases = ATTRS

    try:
        for o, a in opts:
            if o in ('-h', '--help'):
                print __doc__
                sys.exit(0)
            elif o in ('--loglevel'):
                loglevel = getattr(logging, a.upper(), None)
                if not isinstance(loglevel, int):
                    raise ValueError('Invalid log level: %s' % loglevel)
            elif o in ('--logfile'):
                logfile = a
            elif o in ('--host','-H'):
                host = a
            elif o in ('--port','-P'):
                port = int(a)
            elif o in ('--pidfile','-p'):
                pidfile = a
            elif o in ('--no-caching','-C'):
                caching = False
            elif o in ('--caching-delay','D'):
                delay = int(caching)
            elif o in ('--foreground','-f'):
                daemonize = False
            elif o in ('--autoreload','-a'):
                autoreload = True
            elif o in ('--frequency'):
                frequency = int(a)
            elif o in ('-A','--alias'):
                (a,sep,uri) = a.lpartition(':')
                if a and uri:
                    aliases[a] = uri
            else:
                raise ValueError("Unknown option %s" % o)

    except Exception,ex:
        print ex
        print __doc__
        sys.exit(3)

    engine = cherrypy.engine
    plugins = cherrypy.process.plugins

    if daemonize:
        cherrypy.config.update({'environment': 'production'})
        cherrypy.config.update({'log.screen': False})
        plugins.Daemonizer(engine).subscribe()

    if pidfile:
        plugins.PIDFile(engine, pidfile).subscribe()

    def _b64(p):
        if p:
            return "{base64}%s" % p.encode('base64')
        else:
            return ""

    def error_page(code,**kwargs):
        kwargs['http'] = cherrypy.request
        return template("%d.html" % code).render(**kwargs)

    server = MDServer(pipes=args,autoreload=autoreload,frequency=frequency,aliases=aliases,cache_enabled=caching)
    pfx = ["/entities","/metadata"]+["/"+x for x in server.aliases.keys()]

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
            'tools.caching.delay': 3600, # this is how long we keep static stuff
            'tools.cpstats.on': True,
            'error_page.404': lambda **kwargs: error_page(404,**kwargs),
            'error_page.503': lambda **kwargs: error_page(503,**kwargs),
            'error_page.500': lambda **kwargs: error_page(500,**kwargs)
        },
        '/': {
            'tools.caching.delay': delay,
            'tools.staticdir.root': site_dir,
            'tools.cpstats.on': True,
            'request.dispatch': EncodingDispatcher(pfx,_b64).dispatch,
            'request.dispatpch.debug': True,
        },
        '/static': {
            'tools.staticdir.on': True,
            'tools.staticdir.root': site_dir,
            'tools.staticdir.dir': "static",
        }
    }
    cherrypy.config.update(cfg)

    root = MDRoot(server)
    #root.dj = DiscoJuice()
    app = cherrypy.tree.mount(root,config=cfg)
    app.log.error_log.setLevel(loglevel)
    app.log.error_log.setLevel(loglevel)
    #Always start the engine; this will start all other services
    try:
        engine.start()
        server.start() # we start the update here to give time for logging to initialize
    except:
        # Assume the error has been logged already via bus.log.
        sys.exit(1)
    else:
        engine.block()

if __name__ == "__main__":
    main()