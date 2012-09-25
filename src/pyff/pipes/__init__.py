"""
Pipes and plumbing. Plumbing instances are sequences of pipes. Each pipe is called in order to load, select,
transform, sign or output SAML metadata.
"""

import os
import yaml
from pyff.utils import resource_string
from pyff.logs import log
from StringIO import StringIO

__author__ = 'leifj'

class PipeLoader(object):
    """
A utility class for dynamically loading the parts of a plumbing instance.

Each part (aka pipe) is a callable with the following signature:

.. function:: pipe(req,*opts)

    :param req: request.
    :type req: Plumbing.Request
    :param opts: optional arguments
    :type opts: iterable

The pipe may return a transformed copy of or replacement for t. The return value must be an
instance of ElementTree. The pipe may also through a PipeException which will cause the rest
of the pipeline to get cancelled. The pipe may also replace req.t instead of returning a
transformed copy in which case it should return None
    """

    def _n(self,d):
        lst = d.split()
        name = lst[0]
        opts = lst[1:]
        return name,opts

    def load_pipe(self,d):
        """
Return a triple callable,name,args of the pipe specified by the object d. The following alternatives
for d are allowed:

 - d is a string (or unicode) in which case the pipe is named d called with None as args.
 - d is a dict of the form {name: args} (i.e one key) in which case the pipe named *name* is called with args
 - d is an iterable (eg tuple or list) in which case d[0] is treated as the pipe name and d[1:] becomes the args
        """
        log.debug("load_pipe %s" % d)
        name = None
        args = None
        opts = []
        if type(d) is str or type(d) is unicode:
            name,opts = self._n(d)
        elif hasattr(d,'__iter__') and not type(d) is dict:
            if not len(d):
                raise Exception,"This does not look like a length of pipe... \n%s" % repr(d)
            name,opts = self._n(d[0])
        elif type(d) is dict:
            k = d.keys()[0]
            name,opts = self._n(k)
            args = d[k]
        else:
            raise Exception,"This does not look like a length of pipe... \n%s" % repr(d)

        if name is None:
            raise Exception,"Anonymous length of pipe... \n%s" % repr(d)

        mname = "pyff.pipes.builtins"
        fn = name
        if ':' in name:
            (mname,sep,fn) = name.rpartition(":")
        pm = mname
        if '.' in mname:
            (pm,sep,mn) = mname.rpartition('.')
            log.debug("importing %s from %s to find %s" % (mn,pm,fn))
        else:
            log.debug("importing %s from %s to find %s" % (mname,pm,fn))
        module = __import__(mname,fromlist=[pm])
        if hasattr(module,fn) and hasattr(getattr(module,fn),'__call__'):
            return getattr(module,fn),opts,fn,args
        elif hasattr(module,"_%s" % fn) and hasattr(getattr(module,"_%s" % fn),'__call__'):
            return getattr(module,"_%s" % fn),opts,fn,args
        else:
            raise ValueError("No such method %s in %s" % (fn,mname))

        #return __import__("pyff.pipes.%s" % name, fromlist=["pyff.pipes"]),name,args

class PipeException(Exception):
    pass

class Plumbing(object):
    """
A plumbing instance represents a basic processing chaing for SAML metadata. A basic example:

.. code-block:: yaml

    - local:
       - /var/metadata/registry

    - select:
       - #md:EntityDescriptor[md:IDPSSODescriptor]

    - xslt:
        stylesheet: tidy.xsl

    - xslt:
        stylesheet: pp.xsl

    - fork:
        - sign:
           key: signer.key
           cert: signer.crt

       - publish:
           output: /var/metadata/public/metadata.xml

Running this plumbing would bake all metadata found in /var/metadata/registry
into an EntitiesDescriptor element with @Name http://example.com/metadata.xml,
cacheDuration 1hr, validUntil 1 day from now. The tree woud be transformed
using the "tidy" and "pp" (for pretty-print) stylesheets and would then be
signed (using signer.key) and finally published in /var/metadata/public/metadata.xml
    """
    def __init__(self,pipeline,id):
        self.id = id
        self.pipeline = pipeline

    def __iter__(self):
        return self.pipeline

    def __str__(self):
        out = StringIO()
        yaml.dump(self.pipeline,stream=out)
        return out.getvalue()

    class Request(object):
        """
Represents a single request. When processing a set of pipelines a single request is
used. Any part of the pipeline may modify any of the fields.
        """
        def __init__(self,plumbing,md,t,name=None,args=[],state={}):
            self.plumbing = plumbing
            self.md = md
            self.t = t
            self.name = name
            self.args = args
            self.state = state
            self.done = False

    def process(self,md,state={},t=None):
        """
The main entrypoint for processing a request pipeline. Calls the inner processor.
        """
        req = Plumbing.Request(self,md,t,state=state)
        self._process(req)
        return req.t

    def _process(self,req):
        """
The inner request pipeline processor.
        """
        log.debug('Processing \n%s' % self)
        for p in self.pipeline:
            try:
                pipe,opts,name,args = loader.load_pipe(p)
                log.debug("traversing pipe %s,%s,%s using %s" % (pipe,name,args,opts))
                if type(args) is str or type(args) is unicode:
                    args = [args]
                if args is not None and type(args) is not dict and type(args) is not list and type(args) is not tuple:
                    raise ValueError("Unknown argument type %s" % repr(args))
                req.args = args
                req.name = name
                ot = pipe(req,*opts)
                if ot is not None:
                    req.t = ot
                log.debug("new state after %s: %s (done=%s)" % (pipe,req.state,req.done))
                if req.done:
                    break
            except PipeException,ex:
                log.error(ex)
                break

def plumbing(fn):
    """
Create a new plumbing instance by parsing yaml from the filename. This uses the resource framework to locate
the yaml file which means that pipelines can be shipped as plugins.
    """
    id = os.path.splitext(fn)[0]
    ystr = resource_string(fn)
    if ystr is None:
        raise ValueError("Plumbing not found: %s" % fn)
    pipeline = yaml.safe_load(ystr)

    return Plumbing(pipeline=pipeline,id=id)

loader = PipeLoader()