"""
An implementation of draft-lajoie-md-query

Usage: pyffd [-C|--no-cache] [-P|--port] [-H|--host] {pipeline-files}+

"""
import getopt
from mako.lookup import TemplateLookup
import os
import sys
from threading import RLock
import cherrypy
from cherrypy._cpdispatch import Dispatcher
from cherrypy._cperror import NotFound
from cherrypy.lib import cptools,static
from cherrypy.process.plugins import Monitor
from cherrypy.lib import caching
from pyff.locks import ReadWriteLock
from pyff.mdrepo import MDRepository
from pyff.pipes import plumbing
from pyff.utils import resource_string, resource_filename, template
from pyff.logs import log
import logging

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
                    log.debug("found %d things" % len(md))
                    server.md = md
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
        cherrypy.request.is_index = True
        print handler
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
    def entities(self,path=None):
        return self.server.mdx(path)

    @cherrypy.expose
    def about(self):
        import pkg_resources  # part of setuptools
        version = pkg_resources.require("pyFF")[0].version
        return template("about.html").render(version=version,
            sysinfo=" ".join(os.uname()),
            http=cherrypy.request,
            cmdline=" ".join(sys.argv),
            stats=self.server.stats(),
            plumbings=["%s" % p for p in self.server.plumbings],
        )

    @cherrypy.expose
    def index(self):
        return self.server.request("")

    @cherrypy.expose
    def static(self):
        return static.staticdir("/static",site_dir,debug=True)

    @cherrypy.expose
    def default(self,*args):
        path = "/".join(args)
        log.debug("default %s" % path)
        return self.server.request(path)

class MDServer():
    def __init__(self, pipes=None):
        if not pipes: pipes = []
        self.md = MDRepository()
        self.lock = ReadWriteLock()
        self.plumbings = [plumbing(v) for v in pipes]
        self.refresh = MDUpdate(cherrypy.engine,server=self)
        self.refresh.subscribe()

    def stats(self):
        return {
            'md': self.md.stats(),
        }

    def start(self):
        self.refresh.run(self)

    class MediaAccept():
        def has_key(self,key):
            return True

        def __getitem__(self, item):
            return cptools.accept(item,debug=True)

    def request(self,path,select=None):

        with self.lock.readlock:
            for p in self.plumbings:
                state = {'request':{ "/%s" % path: True},
                         'headers':{'Content-Type': 'text/xml'},
                         'accept': MDServer.MediaAccept(),
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

    def mdx(self,path):
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

        filter = _d(path)
        #accepts = cherrypy.request.headers.elements('Accept')
        select = None
        if filter is not None:
            if '=' in path:
                (k,eq,v) = filter.partition('=')
                select = "!//md:EntityDescriptor[//md:Attribute[@type='%s' && md:AttributeValue[text()='%s']]" % (k,v)
            elif '@idp' in path:
                select = "!//md:EntityDescriptor[md:IDPSSODescriptor]"
            elif '@sp' in path:
                select = "!//md:EntityDescriptor[md:SPSSODescriptor]"
            else:
                select = "!//md:EntityDescriptor[@entityID='%s']" % filter

        return self.request("entities",select)

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
            'tools.caching.delay': 3600 # this is how long we keep static stuff
        },
        '/': {
            'tools.caching.delay': delay,
            'tools.staticdir.root': site_dir
        },
        '/static': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': 'static'
        },
        '/entities': {
            'tools.caching.delay': delay,
            'request.dispatch': EncodingDispatcher("/entities",_b64),
        }
    }
    cherrypy.config.update(cfg)
    app = cherrypy.tree.mount(MDRoot(server),config=cfg)
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