"""

An abstraction layer for metadata fetchers. Supports both syncronous and asyncronous fetchers with cache.

"""

from .logs import get_log
import os
import requests
from .constants import config
from datetime import datetime
from collections import deque
from .parse import parse_resource
from .exceptions import ResourceException
from .utils import url_get, non_blocking_lock, hex_digest, img_to_data, Watchable
from copy import deepcopy
from threading import Lock, Condition
from .fetch import make_fetcher

requests.packages.urllib3.disable_warnings()

log = get_log(__name__)


class URLHandler(object):
    def __init__(self, *args, **kwargs):
        log.debug("create urlhandler {} {}".format(args, kwargs))
        self.pending = {}
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
            self.pending[self.thing_to_url(t)] = t
            self.fetcher.schedule(self.thing_to_url(t))

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
            log.warn(ex)


class ResourceHandler(URLHandler):

    def __init__(self, *args, **kwargs):
        super().__init__(self, *args, **kwargs)

    def thing_to_url(self, t):
        return t.url

    def i_handle(self, t, url=None, response=None, exception=None, last_fetched=None):
        try:
            if exception is not None:
                t.info['Exception'] = exception
            else:
                children = t.parse(lambda u: response)
                self.i_schedule(children)
        except BaseException as ex:
            log.warn(ex)
            t.info['Exception'] = ex


class Resource(Watchable):
    def __init__(self, url=None, **kwargs):
        super().__init__()
        self.url = url
        self.opts = kwargs
        self.t = None
        self.type = "text/plain"
        self.etag = None
        self.expire_time = None
        self.never_expires = False
        self.last_seen = None
        self.last_parser = None
        self._infos = deque(maxlen=config.info_buffer_size)
        self.children = deque()
        self._setup()

    def _setup(self):
        self.opts.setdefault('cleanup', [])
        self.opts.setdefault('via', [])
        self.opts.setdefault('fail_on_error', False)
        self.opts.setdefault('verify', None)
        self.opts.setdefault('filter_invalid', True)
        self.opts.setdefault('validate', True)
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
    def post(self):
        return self.opts['via']

    def add_via(self, callback):
        self.opts['via'].append(callback)

    @property
    def cleanup(self):
        return self.opts['cleanup']

    def __str__(self):
        return "Resource {} expires at {} using ".format(self.url if self.url is not None else "(root)", self.expire_time) + \
               ",".join(["{}={}".format(k, v) for k, v in list(self.opts.items())])

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

    def is_expired(self):
        if self.never_expires:
            return False
        now = datetime.now()
        return self.expire_time is not None and self.expire_time < now

    def is_valid(self):
        return not self.is_expired() and self.last_seen is not None and self.last_parser is not None

    def add_info(self, info):
        self._infos.append(info)

    def _replace(self, r):
        for i in range(0, len(self.children)):
            if self.children[i].url == r.url:
                self.children[i] = r
                return
        raise ValueError("Resource {} not present - use add_child".format(r.url))

    def add_child(self, url, **kwargs):
        opts = deepcopy(self.opts)
        if 'as' in opts:
            del opts['as']
        opts.update(kwargs)
        r = Resource(url, **opts)
        if r in self.children:
            self._replace(r)
        else:
            self.children.append(r)

        return r

    @property
    def name(self):
        if 'as' in self.opts:
            return self.opts['as']
        else:
            return self.url

    @property
    def info(self):
        if self._infos is None or not self._infos:
            return dict()
        else:
            return self._infos[-1]

    def parse(self, getter):
        info = dict()
        info['Resource'] = self.url
        self.add_info(info)
        data = None
        log.debug("getting {}".format(self.url))

        r = getter(self.url)

        info['HTTP Response Headers'] = r.headers
        log.debug("got status_code={:d}, encoding={} from_cache={} from {}".
                  format(r.status_code, r.encoding, getattr(r, "from_cache", False), self.url))
        info['Status Code'] = str(r.status_code)
        info['Reason'] = r.reason

        if r.ok:
            data = r.text
        else:
            raise ResourceException("Got status={:d} while getting {}".format(r.status_code, self.url))

        parse_info = parse_resource(self, data)
        if parse_info is not None and isinstance(parse_info, dict):
            info.update(parse_info)

        if self.t is not None:
            self.last_seen = datetime.now()
            if self.post and isinstance(self.post, list):
                for cb in self.post:
                    if self.t is not None:
                        self.t = cb(self.t, **self.opts)

            if self.is_expired():
                info['Expired'] = True
                raise ResourceException("Resource at {} expired on {}".format(self.url, self.expire_time))
            else:
                info['Expired'] = False

            for (eid, error) in list(info['Validation Errors'].items()):
                log.error(error)

            self.etag = r.headers.get('ETag', None) or hex_digest(r.text, 'sha256')

        return self.children
