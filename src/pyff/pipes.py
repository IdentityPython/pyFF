"""
Pipes and plumbing. Plumbing instances are sequences of pipes. Each pipe is called in order to load, select,
transform, sign or output SAML metadata.
"""
from __future__ import annotations

import functools
import os
import traceback
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Type, Union

import yaml
from apscheduler.schedulers.background import BackgroundScheduler
from lxml.etree import Element, ElementTree

from pyff.logs import get_log
from pyff.repo import MDRepository
from pyff.store import SAMLStoreBase
from pyff.utils import PyffException, is_text, resource_string

log = get_log(__name__)

__author__ = 'leifj'

registry: Dict[str, Callable] = dict()


def pipe(*args, **kwargs) -> Callable:
    """
    A decorator that registers a function as a pipeline in pyFF. Functions decorated *should* have the
    following prototype:

    @pipe
    def foo(req: Plumbing.Request, *opts)
        pass
    """

    def pipe_decorator(f: Callable) -> Callable:
        if 'name' in kwargs:  # called with the name argument @pipe(name=...) or as @pipe()
            f_name = kwargs.get('name', f.__name__)
            registry[f_name] = f

        @functools.wraps(f)
        def wrapper_pipe(*iargs, **ikwargs) -> Any:
            # the 'opts' parameter gets special treatment:
            # locate the type annotation of 'opts' and if it exists assume it refers to a pydantic dataclass
            # before propagating the call to the wrapped function replace opts with the pydantic dataclass object
            # created from the Tuple provided
            opts_type: Optional[Type] = None
            if 'opts' in f.__annotations__:
                opts_type = f.__annotations__['opts']

            if opts_type is not None:
                opts_in = ikwargs.pop('opts')
                ikwargs['opts'] = opts_type(**dict(list(zip(opts_in[::2], opts_in[1::2]))))

            return f(*iargs, **ikwargs)

        return wrapper_pipe

    if len(args) == 1 and callable(args[0]):  # called without arguments @pipe
        registry[args[0].__name__] = args[0]
        return pipe_decorator(args[0])
    else:
        return pipe_decorator


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


def load_pipe(d: Any) -> Tuple[Callable, Any, str, Optional[Union[str, Dict, List]]]:
    """Return a triple callable,name,args of the pipe specified by the object d.

    :param d: The following alternatives for d are allowed:

    - d is a string (or unicode) in which case the pipe is named d called with None as args.
    - d is a dict of the form {name: args} (i.e one key) in which case the pipe named *name* is called with args
    - d is an iterable (a list) in which case d[0] is treated as the pipe name and d[1:] becomes the args
    """

    def _n(_d: str) -> Tuple[str, List[str]]:
        lst = _d.split()
        _name = lst[0]
        _opts = lst[1:]
        return _name, _opts

    name = None
    args = None
    opts: List[str] = []
    if is_text(d):
        name, opts = _n(d)
    elif hasattr(d, '__iter__') and not type(d) is dict:
        if not len(d):
            raise PipeException("This does not look like a length of pipe... \n%s" % repr(d))
        name, opts = _n(d[0])
    elif type(d) is dict:
        k = list(d.keys())[0]
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

    def __init__(self, entry_point: str, req: Plumbing.Request, store: Optional[SAMLStoreBase] = None) -> None:
        self.entry_point = entry_point
        self.plumbing = Plumbing(req.scope_of(entry_point).plumbing.pipeline, f"{req.plumbing.id}-via-{entry_point}")
        self.req = req
        self.store = store

    def __str__(self) -> str:
        return f"<PipelineCallback to {self.req.plumbing}>"

    def __repr__(self) -> str:
        return str(self)

    def __copy__(self) -> PipelineCallback:
        # TODO: This seems... dangerous. What's the need for this?
        return self

    def __deepcopy__(self, memo: Any) -> PipelineCallback:
        # TODO: This seems... dangerous. What's the need for this?
        return self

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        log.debug("{!s}: called".format(self.plumbing))
        t = args[0]
        if t is None:
            raise ValueError("PipelineCallback must be called with a parse-tree argument")
        try:
            state = kwargs
            state[self.entry_point] = True
            log.debug("state: {}".format(repr(state)))
            return self.plumbing.process(self.req.md, store=self.store, state=state, t=t)
        except Exception as ex:
            log.debug(traceback.format_exc())
            log.error(f'Got an exception executing the plumbing process: {ex}')
            raise ex


class Plumbing(object):
    """
    A plumbing instance represents a basic processing chain for SAML metadata. A simple, yet reasonably complete example:

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

    def __init__(self, pipeline: Iterable[Dict[str, Any]], pid: str):
        self._id = pid
        self.pipeline = pipeline

    def to_json(self) -> Iterable[Dict[str, Any]]:
        # TODO: to_json seems like the wrong name for this function?
        return self.pipeline

    @property
    def id(self) -> str:
        return self._id

    @property
    def pid(self) -> str:
        return self._id

    def __iter__(self) -> Iterable[Dict[str, Any]]:
        return self.pipeline

    def __str__(self) -> str:
        return "PL[id={!s}]".format(self.pid)

    class Request(object):
        """
        Represents a single request. When processing a set of pipelines a single request is used.
        Any part of the pipeline may modify any of the fields.
        """

        def __init__(
            self,
            pl: Plumbing,
            md: MDRepository,
            t=None,
            name=None,
            args=None,
            state: Optional[Dict[str, Any]] = None,
            store=None,
            scheduler: Optional[BackgroundScheduler] = None,
            raise_exceptions: bool = True,
        ):
            if not state:
                state = dict()
            if not args:
                args = []
            self.plumbing: Plumbing = pl
            self.md: MDRepository = md
            self.t: ElementTree = t
            self._id: Optional[str] = None
            self.name = name
            self.args: Optional[Union[str, Dict, List]] = args
            self.state: Dict[str, Any] = state
            self.done: bool = False
            self._store: SAMLStoreBase = store
            self.scheduler: Optional[BackgroundScheduler] = scheduler
            self.raise_exceptions: bool = raise_exceptions
            self.exception: Optional[BaseException] = None
            self.parent: Optional[Plumbing.Request] = None

        def scope_of(self, entry_point: str) -> Plumbing.Request:
            for _p in self.plumbing.pipeline:
                if f'with {entry_point}' in _p:
                    return self
            if self.parent is None:
                return self
            return self.parent.scope_of(entry_point)

        @property
        def id(self) -> Optional[str]:
            if self.t is None:
                return None
            if self._id is None:
                self._id = self.t.get('entityID')
            if self._id is None:
                self._id = self.t.get('Name')
            return self._id

        def set_id(self, _id: Optional[str]) -> None:
            self._id = _id

        def set_parent(self, _parent: Optional[Plumbing.Request]) -> None:
            self.parent = _parent

        @property
        def store(self) -> SAMLStoreBase:
            if self._store:
                return self._store
            return self.md.store

        def process(self, pl: Plumbing) -> ElementTree:
            """The inner request pipeline processor.

            :param pl: The plumbing to run this request through
            """
            return pl.iprocess(self)

    def iprocess(self, req: Plumbing.Request) -> ElementTree:
        """The inner request pipeline processor.

        :param req: The request to run through the pipeline
        """
        # log.debug("Processing {}".format(self.pipeline))
        for p in self.pipeline:
            try:
                pipefn, opts, name, args = load_pipe(p)
                log.debug(
                    "{!s}: calling '{}' using args:\n{} and opts:\n{}".format(
                        self.pipeline, name, repr(args), repr(opts)
                    )
                )
                if is_text(args):
                    args = [args]
                if args is not None and type(args) is not dict and type(args) is not list and type(args) is not tuple:
                    raise PipeException("Unknown argument type %s" % repr(args))
                req.args = args
                req.name = name
                ot = pipefn(req, *opts)
                if ot is not None:
                    req.t = ot
                if req.done:
                    break
            except BaseException as ex:
                log.debug(traceback.format_exc())
                log.error(f'Got exception when loading/executing pipe: {ex}')
                req.exception = ex
                if req.raise_exceptions:
                    raise ex
                break
        return req.t

    def process(
        self,
        md: MDRepository,
        args: Any = None,
        state: Optional[Dict[str, Any]] = None,
        t: Optional[ElementTree] = None,
        store: Optional[SAMLStoreBase] = None,
        raise_exceptions: bool = True,
        scheduler: Optional[BackgroundScheduler] = None,
    ) -> Optional[Element]:  # TODO: unsure about this return type
        """
        The main entrypoint for processing a request pipeline. Calls the inner processor.


        :param scheduler: a scheduler for use in pipes
        :param raise_exceptions: weather to raise or just log exceptions in the process
        :param md: The current metadata repository
        :param state: The active request state
        :param t: The active working document
        :param store: The store object to operate on
        :param args: Pipeline arguments
        :return: The result of applying the processing pipeline to t.
        """
        if not state:
            state = dict()

        return Plumbing.Request(
            self, md, t=t, args=args, state=state, store=store, raise_exceptions=raise_exceptions, scheduler=scheduler
        ).process(self)


def plumbing(fn: str) -> Plumbing:
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
