"""
An implementation of draft-lajoie-md-query

Usage: pyffd [-C|--no-cache] [-P|--port] [-H|--host] {pipeline-files}+

"""
import getopt
import os
import sys
from threading import RLock
import cherrypy
from cherrypy._cpdispatch import Dispatcher
from cherrypy._cperror import NotFound, HTTPError
from cherrypy.lib import cptools,static, cpstats
from cherrypy.process.plugins import Monitor
from cherrypy.lib import caching
import re
from simplejson import dumps
import time
from pyff.index import hash_id
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
                md = MDRepository()
                for p in server.plumbings:
                    p.process(md,state={'update':True})
                if not md.sane():
                    log.error("update produced insane active repository - will retry...")
                with server.lock.writelock:
                    log.debug("updating metadata repository with %d entities" % md.index.size())
                    server.md = md
                    stats['Repository Update Time'] = datetime.now()
                    stats['Repository Size'] = md.index.size()

        except Exception,ex:
            #log.error(ex)
            raise ex
        finally:
            if locked:
                self.lock.release()

class EncodingDispatcher(object):
    def __init__(self,prefix,enc,next_dispatcher=Dispatcher()):
        self.prefix = prefix
        self.plen = len(prefix)
        self.enc = enc
        self.next_dispatcher = next_dispatcher

    def __call__(self,path_info):
        vpath = path_info.replace("%2F", "/")
        vpath = vpath[self.plen+1:]
        npath =  "%s/%s" % (self.prefix,self.enc(vpath))
        log.debug("EncodingDispatcher %s" % npath)
        handler =  self.next_dispatcher(npath)
        cherrypy.request.is_index = False
        return handler

site_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)),"site")

class MDRoot():
    def __init__(self,server):
        self.server = server

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
        return self.server.mdx(path)

    @cherrypy.expose
    @cherrypy.tools.expires(secs=600,debug=True)
    def json(self,path=None):
        return self.server.mdx(path,content_type="application/json")

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
            plumbings=["%s" % p for p in self.server.plumbings],
        )

    @cherrypy.expose
    def html(self,id):

        def escape(m):
            str = m.group(0)
            if str == '<':
                return '&lt;'
            if str == '>':
                return '&gt;'
            return str

        entities = self.server.md.lookup(id)
        if not entities:
            raise NotFound()
        if len(entities) > 1:
            return template("metadata.html").render(http=cherrypy.request,md=self.server.md,entities=entities)
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

    @cherrypy.expose
    def search(self,query):
        cherrypy.response.headers['Content-Type'] = 'application/json'
        return dumps(self.server.md.search(query))

    @cherrypy.expose
    def metadata(self):
        return template("metadata.html").render(entities=self.server.md,md=self.server.md,http=cherrypy.request)

    @cherrypy.expose
    def index(self):
        return self.server.request("")

    @cherrypy.expose
    def static(self):
        return static.staticdir("/static",site_dir,debug=True)

    @cherrypy.expose
    def default(self,*args):
        path = "/".join(args)
        return self.server.request(path)

class MDServer():
    def __init__(self, pipes=None):
        if not pipes: pipes = []
        self.md = MDRepository()
        self.lock = ReadWriteLock()
        self.plumbings = [plumbing(v) for v in pipes]
        self.refresh = MDUpdate(cherrypy.engine,server=self)
        self.refresh.subscribe()

    def start(self):
        self.refresh.run(self)

    class MediaAccept():
        def has_key(self,key):
            return True

        def __getitem__(self, item):
            try:
                return cptools.accept(item,debug=True)
            except HTTPError:
                return False

    def request(self,path,select=None,content_type=None):
        stats['MD Requests'] += 1
        log.debug(cherrypy.request.headers)
        accept = {}
        if content_type is None:
            accept = MDServer.MediaAccept()
        else:
            accept = {content_type:True}

        with self.lock.readlock:
            for p in self.plumbings:
                state = {'request':{ "/%s" % path: True},
                         'headers':{'Content-Type': 'text/xml'},
                         'accept': accept,
                         'url': cherrypy.url(relative=False),
                         'select': select}
                r = p.process(self.md,state=state)
                if r is not None:
                    cache_ttl = state.get('cache',0)
                    log.debug("caching for %d seconds" % cache_ttl)
                    caching.expires(secs=cache_ttl)
                    for k,v in state.get('headers',{}).iteritems():
                        cherrypy.response.headers[k] = v
                    return r
        raise NotFound()

    def mdx(self,path,content_type=None):
        """
The entities method is special - it gets called by the EncodingDispatcher which by-passes most
of the RESTful path decoding/parsing mechanisms in cherrypy. Instead the entities method
gets (as a string) the part of the path-info after the dispatcher "mount point" - typically
/entities/ after url-dequoting.
        """

        def _d(x):
            if x is None:
                return None

            if x.startswith("{base64}"):
                return x[8:].decode('base64')
            else:
                return x

        return self.request("entities",_d(path),content_type=content_type)

def main():
    """
    The main entrypoint for the pyFF mdx server.
    """
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hP:p:H:Cf', ['help', 'loglevel=','port=','host=','no-caching'])
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
    server = MDServer(pipes=args)
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
            'tools.encode.on': True,
            'tools.encode.encoding': "utf8",
        },
        '/': {
            'tools.caching.delay': delay,
            'tools.staticdir.root': site_dir,
            'tools.cpstats.on': True,
            'tools.encode.on': True,
            'tools.encode.encoding': "utf8",
        },
        '/static': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': 'static'
        },
        '/entities': {
            'tools.caching.delay': delay,
            'request.dispatch': EncodingDispatcher("/entities",_b64),
            'tools.cpstats.on': True,
            'tools.encode.on': True,
            'tools.encode.encoding': "utf8",
        },
        '/json': {
            'tools.caching.delay': delay,
            'request.dispatch': EncodingDispatcher("/json",_b64),
            'tools.cpstats.on': True,
            'tools.encode.on': True,
            'tools.encode.encoding': "utf8",
        }
    }
    cherrypy.config.update(cfg)
    root = MDRoot(server)
    root.cpstats = cpstats.StatsPage()
    app = cherrypy.tree.mount(root,config=cfg)
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