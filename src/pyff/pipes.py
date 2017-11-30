"""
Pipes and plumbing. Plumbing instances are sequences of pipes. Each pipe is called in order to load, select,
transform, sign or output SAML metadata.
"""

import traceback
from six import StringIO
import os
import yaml
from .utils import resource_string, PyffException
from .logs import log

__author__ = 'leifj'

registry = dict()


def pipe(*args, **kwargs):
    """
    Register the decorated function in the pyff pipe registry
    :param name: optional name - if None, use function name
    """

    def deco_none(f):
        return f

    def deco_pipe(f):
        f_name = kwargs.get('name', f.__name__)
        registry[f_name] = f
        return f

    if 1 == len(args):
        f = args[0]
        registry[f.__name__] = f
        return deco_none
    else:
        return deco_pipe


class PipeException(PyffException):
    pass


class PluginsRegistry(dict):
    """
    The plugin registry uses pkg_resources.iter_entry_points to list all EntryPoints in the group 'pyff.pipe'. All pipe
    entry_points must have the following prototype:

    def the_something_func(req,*opts):
        pass

    Referencing this function as an entry_point using something = module:the_somethig_func in setup.py allows the
    function to be referenced as 'something' in a pipeline.
    """
    # def __init__(self):
    #    for entry_point in iter_entry_points('pyff.pipe'):
    #        if entry_point.name in self:
    #            log.warn("Duplicate entry point: %s" % entry_point.name)
    #        else:
    #            log.debug("Registering entry point: %s" % entry_point.name)
    #            self[entry_point.name] = entry_point.load()


def load_pipe(d):
    """Return a triple callable,name,args of the pipe specified by the object d.

    :param d: The following alternatives for d are allowed:

    - d is a string (or unicode) in which case the pipe is named d called with None as args.
    - d is a dict of the form {name: args} (i.e one key) in which case the pipe named *name* is called with args
    - d is an iterable (eg tuple or list) in which case d[0] is treated as the pipe name and d[1:] becomes the args
    """

    def _n(_d):
        lst = _d.split()
        _name = lst[0]
        _opts = lst[1:]
        return _name, _opts

    name = None
    args = None
    opts = []
    if type(d) is str or type(d) is unicode:
        name, opts = _n(d)
    elif hasattr(d, '__iter__') and not type(d) is dict:
        if not len(d):
            raise PipeException("This does not look like a length of pipe... \n%s" % repr(d))
        name, opts = _n(d[0])
    elif type(d) is dict:
        k = d.keys()[0]
        name, opts = _n(k)
        args = d[k]
    else:
        raise PipeException("This does not look like a length of pipe... \n%s" % repr(d))

    if name is None:
        raise PipeException("Anonymous length of pipe... \n%s" % repr(d))

    func = None
    if name in registry:
        func = registry[name]

    if func is None or not hasattr(func, '__call__'):
        raise PipeException('No pipe named %s is installed' % name)

    return func, opts, name, args


class PipelineCallback(object):
    """
A delayed pipeline callback used as a post for parse_saml_metadata
    """

    def __init__(self, entry_point, req):
        self.entry_point = entry_point
        self.plumbing = Plumbing(req.plumbing.pipeline, "%s-via-%s" % (req.plumbing.id, entry_point))
        self.req = req

    def __call__(self, *args, **kwargs):
        t = args[0]
        if t is None:
            raise ValueError("PipelineCallback must be called with a parse-tree argument")
        try:
            return self.plumbing.process(self.req.md, state={self.entry_point: True}, t=t)
        except Exception as ex:
            traceback.print_exc(ex)
            raise ex


class Plumbing(object):
    """
A plumbing instance represents a basic processing chain  for SAML metadata. A simple, yet reasonably complete example:

.. code-block:: yaml

    - load:
        - /var/metadata/registry
        - http://md.example.com
    - select:
       - #md:EntityDescriptor[md:IDPSSODescriptor]
    - xslt:
        stylesheet: tidy.xsl
    - fork:
        - finalize:
            Name: http://example.com/metadata.xml
            cacheDuration: PT1H
            validUntil: PT1D
        - sign:
           key: signer.key
           cert: signer.crt
       - publish: /var/metadata/public/metadata.xml

Running this plumbing would bake all metadata found in /var/metadata/registry and at http://md.example.com into an
EntitiesDescriptor element with @Name http://example.com/metadata.xml, @cacheDuration set to 1hr and @validUntil
1 day from the time the 'finalize' command was run. The tree woud be transformed using the "tidy" stylesheets and
would then be signed (using signer.key) and finally published in /var/metadata/public/metadata.xml
    """

    def __init__(self, pipeline, pid):
        self._id = pid
        self.pipeline = pipeline

    @property
    def id(self):
        return self._id

    @property
    def pid(self):
        return self._id

    def __iter__(self):
        return self.pipeline

    def __str__(self):
        out = StringIO()
        yaml.dump(self.pipeline, stream=out)
        return out.getvalue()

    class Request(object):
        """
Represents a single request. When processing a set of pipelines a single request is used. Any part of the pipeline
may modify any of the fields.
        """

        def __init__(self, pl, md, t, name=None, args=None, state=None):
            if not state:
                state = dict()
            if not args:
                args = []
            self.plumbing = pl
            self.md = md
            self.t = t
            self.name = name
            self.args = args
            self.state = state
            self.done = False

        def process(self, pl):
            """The inner request pipeline processor.

            :param pl: The plumbing to run this request through
            """
            log.debug("Processing pipeline... \n{}".format(pl))
            for p in pl.pipeline:
                cb, opts, name, args = load_pipe(p)
                # log.debug("traversing pipe %s,%s,%s using %s" % (pipe,name,args,opts))
                if type(args) is str or type(args) is unicode:
                    args = [args]
                if args is not None and type(args) is not dict and type(args) is not list and type(args) is not tuple:
                    raise PipeException("Unknown argument type %s" % repr(args))
                self.args = args
                self.name = name
                ot = cb(self, *opts)
                if ot is not None:
                    self.t = ot
                if self.done:
                    break
            return self.t

    def process(self, md, state=None, t=None):
        """
The main entrypoint for processing a request pipeline. Calls the inner processor.


:param md: The current metadata repository
:param state: The active request state
:param t: The active working document
:return: The result of applying the processing pipeline to t.
        """
        if not state:
            state = dict()
        # req = Plumbing.Request(self, md, t, state=state)
        # self.iprocess(req)
        # return req.t
        return Plumbing.Request(self, md, t, state=state).process(self)

    def iprocess(self, req):
        """The inner request pipeline processor.

        :param req: The request to run through the pipeline
        """
        log.debug("Processing pipeline... {}".format(self.pipeline))
        for p in self.pipeline:
            try:
                pipe, opts, name, args = load_pipe(p)
                # log.debug("traversing pipe %s,%s,%s using %s" % (pipe,name,args,opts))
                if type(args) is str or type(args) is unicode:
                    args = [args]
                if args is not None and type(args) is not dict and type(args) is not list and type(args) is not tuple:
                    raise PipeException("Unknown argument type %s" % repr(args))
                req.args = args
                req.name = name
                ot = pipe(req, *opts)
                if ot is not None:
                    req.t = ot
                if req.done:
                    break
            except PipeException as ex:
                log.error(ex)
                break
        return req.t


def plumbing(fn):
    """
Create a new plumbing instance by parsing yaml from the filename.

:param fn: A filename containing the pipeline.
:return: A plumbing object

This uses the resource framework to locate the yaml file which means that pipelines can be shipped as plugins.
    """
    pid = os.path.splitext(fn)[0]
    ystr = resource_string(fn)
    if ystr is None:
        raise PipeException("Plumbing not found: %s" % fn)
    pipeline = yaml.safe_load(ystr)

    return Plumbing(pipeline=pipeline, pid=pid)
