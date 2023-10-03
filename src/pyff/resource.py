"""

An abstraction layer for metadata fetchers. Supports both synchronous and asynchronous fetchers with cache.

"""
from __future__ import annotations

import os
import traceback
from collections import defaultdict, deque
from datetime import datetime
from enum import Enum
from threading import Condition, Lock
from typing import TYPE_CHECKING, Any, Callable, Deque, Dict, Iterable, List, Mapping, Optional, Tuple
from urllib.parse import quote as urlescape

import requests
from lxml.etree import ElementTree
from pydantic import ConfigDict, BaseModel, Field
from requests.adapters import Response

from pyff.constants import config
from pyff.exceptions import ResourceException
from pyff.fetch import make_fetcher
from pyff.logs import get_log
from pyff.utils import (
    Watchable,
    hex_digest,
    img_to_data,
    non_blocking_lock,
    resource_string,
    safe_write,
    url_get,
    utc_now,
)

if TYPE_CHECKING:
    from pyff.parse import ParserInfo, PyffParser
    from pyff.pipes import PipelineCallback
    from pyff.utils import Lambda

    # ensure static analysis doesn't flag these as unused
    assert PyffParser
    assert PipelineCallback
    assert Lambda

requests.packages.urllib3.disable_warnings()

log = get_log(__name__)


class URLHandler(object):
    def __init__(self, *args, **kwargs):
        log.debug("create urlhandler {} {}".format(args, kwargs))
        self.pending: Dict[str, Resource] = {}
        self.name = kwargs.pop('name', None)
        self.content_handler = kwargs.pop('content_handler', None)
        self._setup()

    def _setup(self):
        self.done = Condition()
        self.lock = Lock()
        self.fetcher = make_fetcher(name=self.name, content_handler=self.content_handler)
        self.fetcher.add_watcher(self)

    def __getstate__(self):
        return dict(name=self.name)

    def __setstate__(self, state):
        self.__dict__.update(state)
        self._setup()

    def is_done(self):
        return self.count == 0

    def thing_to_url(self, t):
        return t

    @property
    def count(self):
        return len(self.pending)

    def schedule(self, things):
        try:
            self.lock.acquire()
            self.i_schedule(things)
        finally:
            self.lock.release()

    def i_schedule(self, things):
        for t in things:
            url = self.thing_to_url(t)
            self.pending[url] = t
            self.fetcher.schedule(url)

    def i_handle(self, t, url=None, response=None, exception=None, last_fetched=None):
        raise NotImplementedError()

    def __call__(self, watched=None, url=None, response=None, exception=None, last_fetched=None):
        if url in self.pending:
            t = self.pending[url]
            with self.lock:
                log.debug("RESPONSE url={}, exception={} @ {}".format(url, exception, self.count))
                self.i_handle(t, url=url, response=response, exception=exception, last_fetched=last_fetched)
                del self.pending[url]

        if self.is_done():
            try:
                self.done.acquire()
                self.done.notify()
            finally:
                self.done.release()


class IconHandler(URLHandler):
    def __init__(self, *args, **kwargs):
        kwargs['content_handler'] = IconHandler._convert_image_response
        super().__init__(self, *args, **kwargs)
        self.icon_store = kwargs.pop('icon_store')

    @staticmethod
    def _convert_image_response(response):
        return img_to_data(response.content, response.headers.get('Content-Type'))

    def i_handle(self, t, url=None, response=None, exception=None, last_fetched=None):
        try:
            if exception is None:
                self.icon_store.update(url, response)
            else:
                self.icon_store.update(url, None, info=dict(exception=exception))
        except BaseException as ex:
            log.debug(traceback.format_exc())
            log.error(f'Failed handling icon: {ex}')


class ResourceHandler(URLHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(self, *args, **kwargs)

    def thing_to_url(self, t: Resource) -> Optional[str]:
        return t.url

    def i_handle(self, t: Resource, url=None, response=None, exception=None, last_fetched=None):
        try:
            if exception is not None:
                t.info.exception = exception
            else:
                children = t.parse(lambda u, v: response)
                if t.t is None:
                    log.debug(f'no thing while i_handle {url}')
                self.i_schedule(children)
        except BaseException as ex:
            log.debug(traceback.format_exc())
            log.error(f'Failed handling resource: {ex}')
            t.info.exception = ex


class ResourceOpts(BaseModel):
    alias: Optional[str] = Field(None, alias='as')  # TODO: Rename to 'name'?
    # a certificate (file) or a SHA1 fingerprint to use for signature verification
    verify: Optional[str] = None
    # TODO: move classes to make the correct typing work: Iterable[Union[Lambda, PipelineCallback]] = Field([])
    via: List[Callable] = Field([])
    # A list of callbacks that can be used to pre-process parsed metadata before validation. Use as a clue-bat.
    # TODO: sort imports to make the correct typing work: Iterable[PipelineCallback] = Field([])
    cleanup: List[Callable] = Field([])
    fail_on_error: bool = False
    # remove invalid EntityDescriptor elements rather than raise an error
    filter_invalid: bool = True
    # set to False to turn off all XML schema validation
    validate_schema: bool = Field(True, alias='validate')
    verify_tls: bool = False
    model_config = ConfigDict(arbitrary_types_allowed=True)

    def to_dict(self) -> Dict[str, Any]:
        res = self.dict()
        # Compensate for the 'alias' field options
        res['as'] = res.pop('alias')
        res['validate'] = res.pop('validate_schema')
        return res


class ResourceLoadState(str, Enum):
    Fetched = 'Fetched'
    Parsing = 'Parsing'
    Parsed = 'Parsed'
    Ready = 'Ready'


class ResourceInfo(BaseModel):
    resource: str  # URL
    state: Optional[ResourceLoadState] = None
    http_headers: Dict[str, Any] = Field({})
    reason: Optional[str] = None
    status_code: Optional[str] = None # HTTP status code as string. TODO: change to int
    parser_info: Optional[ParserInfo] = None
    expired: Optional[bool] = None
    exception: Optional[BaseException] = None
    model_config = ConfigDict(arbitrary_types_allowed=True)

    def to_dict(self) -> Dict[str, Any]:
        def _format_key(k: str) -> str:
            special = {'http_headers': 'HTTP Response Headers'}
            if k in special:
                return special[k]
            # Turn validation_errors into 'Validation Errors'
            return k.replace('_', ' ').title()

        res = {_format_key(k): v for k, v in self.dict().items()}

        if self.parser_info:
            # Move contents from sub-dict to top of dict, for backwards compatibility
            res.update(self.parser_info.to_dict())
        del res['Parser Info']

        # backwards compat
        if res['Description'] == 'SAML Metadata':
            del res['Description']
        if res['Exception'] is None:
            del res['Exception']

        return res

class Resource(Watchable):
    def __init__(self, url: Optional[str], opts: ResourceOpts):
        super().__init__()
        self.url: Optional[str] = url
        self.opts: ResourceOpts = opts
        self.t: Optional[ElementTree] = None
        self.type: str = "text/plain"
        self.etag: Optional[str] = None
        self.expire_time: Optional[datetime] = None
        self.never_expires: bool = False
        self.last_seen: Optional[datetime] = None
        self.last_parser: Optional['PyffParser'] = None  # importing PyffParser in this module causes a loop
        self._infos: Deque[ResourceInfo] = deque(maxlen=config.info_buffer_size)
        self.children: Deque[Resource] = deque()
        self.trust_info: Optional[dict] = None
        self.md_sources: Optional[dict] = None
        self._setup()

    def _setup(self):
        if self.url is not None:
            if "://" not in self.url:
                pth = os.path.abspath(self.url)
                if os.path.isdir(pth):
                    self.url = "dir://{}".format(pth)
                elif os.path.isfile(pth) or os.path.isabs(self.url):
                    self.url = "file://{}".format(pth)

            if self.url.startswith('file://') or self.url.startswith('dir://'):
                self.never_expires = True

        self.lock = Lock()

    def __getstate__(self):
        raise ValueError("this object should not be pickled")

    def __setstate__(self, state):
        raise ValueError("this object should not be unpickled")

    @property
    def local_copy_fn(self):
        return os.path.join(config.local_copy_dir, urlescape(self.url))

    @property
    def post(
        self,
    ) -> Iterable[Callable]:  # TODO: move classes to make this work -> List[Union['Lambda', 'PipelineCallback']]:
        return self.opts.via

    def add_via(self, callback: Callable) -> None:
        # TODO: move classes to be able to declare callback: Union['Lambda', 'PipelineCallback']
        self.opts.via.append(callback)

    @property
    def cleanup(self) -> Iterable[Callable]:  # TODO: move classes to make this work -> Iterable['PipelineCallback']:
        return self.opts.cleanup

    def __str__(self):
        return "Resource {} expires at {} using ".format(
            self.url if self.url is not None else "(root)", self.expire_time
        ) + ",".join(["{}={}".format(k, v) for k, v in sorted(list(self.opts.dict().items()))])

    def reload(self, fail_on_error=False):
        with non_blocking_lock(self.lock):
            if fail_on_error:
                for r in self.walk():
                    r.parse(url_get)
            else:
                rp = ResourceHandler(name="Metadata")
                rp.schedule(self.children)
                try:
                    rp.done.acquire()
                    rp.done.wait()
                finally:
                    rp.done.release()
                rp.fetcher.stop()
                rp.fetcher.join()
            self.notify()

    def __len__(self):
        return len(self.children)

    def __iter__(self):
        return self.walk()

    def __eq__(self, other):
        return self.url == other.url

    def __contains__(self, item):
        return item in self.children

    def walk(self):
        if self.url is not None:
            yield self
        for c in self.children:
            for cn in c.walk():
                yield cn

    def is_expired(self) -> bool:
        if self.never_expires or self.expire_time is None:
            return False
        return self.expire_time < utc_now()

    def is_valid(self) -> bool:
        return not self.is_expired() and self.last_seen is not None and self.last_parser is not None

    def add_info(self) -> ResourceInfo:
        info = ResourceInfo(resource=self.url)
        self._infos.append(info)
        return info

    def _replace(self, r: Resource) -> None:
        for i in range(0, len(self.children)):
            if self.children[i].url == r.url:
                self.children[i] = r
                return
        raise ValueError("Resource {} not present - use add_child".format(r.url))

    def add_child(self, url: str, opts: ResourceOpts) -> Resource:
        r = Resource(url, opts)
        if r in self.children:
            log.debug(f'\n\n{self}:\nURL {url}\nReplacing child {r}')
            self._replace(r)
        else:
            log.debug(f'\n\n{self}:\nURL {url}\nAdding child {r}')
            if not r.opts.via:
                log.debug('Empty Via')
            self.children.append(r)

        return r

    @property
    def name(self) -> Optional[str]:
        if self.opts.alias:
            return self.opts.alias
        return self.url

    @property
    def info(self) -> ResourceInfo:
        if self._infos is None or not self._infos:
            return ResourceInfo(resource=self.url)
        else:
            return self._infos[-1]

    def load_backup(self) -> Optional[str]:
        if config.local_copy_dir is None:
            return None

        try:
            res = resource_string(self.local_copy_fn)
            if isinstance(res, bytes):
                return res.decode('utf-8')
            return res
        except IOError as ex:
            log.warning(
                "Caught an exception trying to load local backup for {} via {}: {}".format(
                    self.url, self.local_copy_fn, ex
                )
            )
            return None

    def save_backup(self, data: Optional[str]) -> None:
        if config.local_copy_dir is not None:
            try:
                safe_write(self.local_copy_fn, data, True)
            except IOError as ex:
                log.warning("unable to save backup copy of {}: {}".format(self.url, ex))

    def load_resource(self, getter: Callable[[str], Response]) -> Tuple[Optional[str], int, ResourceInfo]:
        data: Optional[str] = None
        status: int = 500
        info = self.add_info()
        verify_tls = self.opts.verify_tls

        log.debug("Loading resource {}".format(self.url))

        if not self.url:
            log.error(f'No URL for resource {self}')
            return data, status, info

        try:
            r = getter(self.url, verify_tls)

            info.http_headers = dict(r.headers)
            log.debug(
                "got status_code={:d}, encoding={} from_cache={} from {}".format(
                    r.status_code, r.encoding, getattr(r, "from_cache", False), self.url
                )
            )
            status = r.status_code
            info.reason = r.reason

            if r.ok:
                data = r.text
                _etag = r.headers.get('ETag', None)
                if not _etag:
                    _etag = hex_digest(r.text, 'sha256')
                self.etag = _etag
            elif self.local_copy_fn is not None:
                log.warning(
                    "Got status={:d} while getting {}. Attempting fallback to local copy.".format(
                        r.status_code, self.url
                    )
                )
                data = self.load_backup()
                if data is not None and len(data) > 0:
                    info.reason = "Retrieved from local cache because status: {} != 200".format(status)
                    status = 218

            info.status_code = str(status)

        except IOError as ex:
            if self.local_copy_fn is not None:
                log.warning("caught exception from {} - trying local backup: {}".format(self.url, ex))
                data = self.load_backup()
                if data is not None and len(data) > 0:
                    info.reason = "Retrieved from local cache because exception: {}".format(ex)
                    status = 218
            if data is None or not len(data) > 0:
                raise ex  # propagate exception if we can't find a backup

        if data is None or not len(data) > 0:
            raise ResourceException("failed to fetch {} (status: {:d})".format(self.url, status))

        info.state = ResourceLoadState.Fetched

        return data, status, info

    def parse(self, getter: Callable[[str], Response]) -> Deque[Resource]:
        data, status, info = self.load_resource(getter)

        if not data:
            raise ResourceException(f'Nothing to parse when loading resource {self}')

        info.state = ResourceLoadState.Parsing
        # local import to avoid circular import
        from pyff.parse import parse_resource

        info.parser_info = parse_resource(self, data)

        if status != 218:  # write backup unless we just loaded from backup
            self.last_seen = utc_now().replace(microsecond=0)
            self.save_backup(data)

        info.state = ResourceLoadState.Parsed
        if self.t is not None:
            if self.post:
                for cb in self.post:
                    if self.t is not None:
                        n_t = cb(self.t, self.opts.dict())
                        if n_t is None:
                            log.warn(f'callback did not return anything when parsing {self.url} {info}')
                        self.t = n_t

            if self.is_expired():
                info.expired = True
                raise ResourceException("Resource at {} expired on {}".format(self.url, self.expire_time))
            else:
                info.expired = False

            if info.parser_info:
                for (eid, error) in list(info.parser_info.validation_errors.items()):
                    log.error(error)
        else:
            log.debug(f'Parser did not produce anything (probably ok) when parsing {self.url} {info}')

        info.state = ResourceLoadState.Ready

        return self.children

    def global_trust_info(self):
        trust_info = {}
        for r in self.walk():
            if r.url and r.trust_info is not None:
                trust_info[r.url] = r.trust_info['profiles']
        return trust_info

    def global_md_sources(self):
        from pyff.samlmd import SAMLParserInfo

        md_sources = defaultdict(list)
        for r in self.walk():
            if r.url:
                for info in r._infos:
                    if isinstance(info.parser_info, SAMLParserInfo):
                        for entity_id in info.parser_info.entities:
                            md_sources[entity_id].append(r.url)
        return md_sources
