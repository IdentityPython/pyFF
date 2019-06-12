"""

An abstraction layer for metadata fetchers. Supports both syncronous and asyncronous fetchers with cache.

"""

from .logs import get_log
import os
import requests
from .constants import config
from datetime import datetime
from collections import deque
import six
from .parse import parse_resource
from itertools import chain
from .exceptions import ResourceException
from .utils import url_get, non_blocking_lock, hex_digest
from copy import deepcopy
from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.events import EVENT_JOB_ERROR, EVENT_JOB_EXECUTED, EVENT_JOB_MISSED
from apscheduler.schedulers.base import STATE_RUNNING
from threading import Lock

if six.PY2:
    from UserDict import DictMixin as ResourceManagerBase
elif six.PY3:
    from collections import MutableMapping as ResourceManagerBase

requests.packages.urllib3.disable_warnings()

log = get_log(__name__)


def fetch(r, store=None):
    return r.fetch(store=store)


class Fetcher(object):
    def __init__(self, rm, scheduler, store, fail_on_error=False, stop_when_done=False, when_done=None):
        self.scheduler = scheduler
        self.store = store
        self.rm = rm
        self.stop_when_done = stop_when_done
        self.fail = []
        self.ok = []
        self.pending = {}

    @property
    def count(self):
        return len(self.pending)

    def is_done(self):
        return self.count == 0

    def schedule(self, resources):
        for r in resources:
            job = self.scheduler.add_job(fetch,
                                         coalesce=True,
                                         misfire_grace_time=2*config.update_frequency,
                                         name="fetch {}".format(r.url),
                                         id="fetch {}".format(r.url),
                                         args=[r],
                                         kwargs=dict(store=self.store))
            self.pending[job.id] = r
            r.current_job = job.id

    def __call__(self, *args, **kwargs):
        event = args[0]
        log.debug("event {} returned {} threw {}".format(repr(event), event.retval, event.exception))

        if event.code == EVENT_JOB_ERROR:
            self.fail.append(event)
            r = self.pending.pop(event.job_id)
            r.current_job = None
            r.info['Exception'] = event.exception
        elif event.code == EVENT_JOB_EXECUTED:
            self.ok.append(event)
            r = self.pending.pop(event.job_id)
            r.current_job = None
        elif event.code == EVENT_JOB_MISSED:
            r = self.pending.get(event.job_id)  # avoid a race on count
            self.schedule([r])
            del self.pending[event.job_id]

        if event.retval is not None and hasattr(event.retval, '__iter__'):
            self.schedule(event.retval)

        log.debug("waiting for {} jobs to finish...".format(self.count))

        if self.is_done():
            self.store.refresh()
            log.debug("this fetcher is done!")
            if self.stop_when_done:
                log.debug("shutting down...")
                self.scheduler.shutdown(wait=False)
            self.scheduler.remove_listener(self)


class ResourceManager(ResourceManagerBase):

    def __init__(self, max_tries=10):
        self._resources = dict()
        self.shutdown = False
        self.max_tries = max_tries
        self.lock = Lock()

    def __setitem__(self, key, value):
        if not isinstance(value, Resource):
            raise ValueError("I can only store Resources")
        self._resources[key] = value

    def __getitem__(self, key):
        return self._resources[key]

    def __delitem__(self, key):
        if key in self:
            del self._resources[key]

    def keys(self):
        return list(self._resources.keys())

    def values(self):
        return list(self._resources.values())

    def walk(self, url=None):
        if url is not None:
            return self[url].walk()
        else:
            i = [r.walk() for r in list(self.values())]
            return chain(*i)

    def add(self, r):
        if not isinstance(r, Resource):
            raise ValueError("I can only store Resources")
        self[r.name] = r

    def __contains__(self, item):
        return item in self._resources

    def __len__(self):
        return len(list(self.values()))

    def __iter__(self):
        return self.walk()

    def reload(self, url=None, fail_on_error=False, store=None, scheduler=None):
        # type: (object, basestring) -> None
        with non_blocking_lock(self.lock):
            if url is not None:
                resources = deque([self[url]])
            else:
                resources = deque(list(self.values()))

            if fail_on_error:
                for r in resources:
                    r.fetch(store=store)
                    for c in r.walk():
                        c.fetch(store=store)
            else:
                stop_when_done = False
                if scheduler is None:
                    scheduler = BlockingScheduler()
                    stop_when_done = True

                fetcher = Fetcher(rm=self,
                                  scheduler=scheduler,
                                  store=store,
                                  stop_when_done=stop_when_done)
                scheduler.add_listener(fetcher,
                                       EVENT_JOB_EXECUTED | EVENT_JOB_ERROR | EVENT_JOB_MISSED)
                fetcher.schedule(resources)

                if scheduler.state != STATE_RUNNING:
                    scheduler.start()


class Resource(object):
    def __init__(self, url, **kwargs):
        self.url = url
        self.opts = kwargs
        self.t = None
        self.type = "text/plain"
        self.expire_time = None
        self.never_expires = False
        self.last_seen = None
        self.last_parser = None
        self.current_job = None
        self._infos = deque(maxlen=config.info_buffer_size)
        self.children = deque()

        def _null(t):
            return t

        self.opts.setdefault('cleanup', [])
        self.opts.setdefault('via', [])
        self.opts.setdefault('fail_on_error', False)
        self.opts.setdefault('as', None)
        self.opts.setdefault('verify', None)
        self.opts.setdefault('filter_invalid', True)
        self.opts.setdefault('validate', True)

        if "://" not in self.url:
            if os.path.isfile(self.url):
                self.url = "file://{}".format(os.path.abspath(self.url))

        if self.url.startswith('file://'):
            self.never_expires = True

    @property
    def post(self):
        return self.opts['via']

    def add_via(self, callback):
        self.opts['via'].append(callback)

    @property
    def cleanup(self):
        return self.opts['cleanup']

    def __str__(self):
        return "Resource {} expires at {} using ".format(self.url, self.expire_time) + \
               ",".join(["{}={}".format(k, v) for k, v in list(self.opts.items())])

    def walk(self):
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

    def add_child(self, url, **kwargs):
        opts = deepcopy(self.opts)
        del opts['as']
        opts.update(kwargs)
        r = Resource(url, **opts)
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

    def _etag(self, r):
        return r.headers.get('ETag', None) or hex_digest(r.text, 'sha256')

    def fetch(self, store=None):
        info = dict()
        info['Resource'] = self.url
        self.add_info(info)
        data = None
        log.debug("fetching {}".format(self.url))
        if os.path.isdir(self.url):
            data = self.url
            info['Directory'] = self.url
        elif '://' in self.url:
            r = url_get(self.url)

            info['HTTP Response Headers'] = r.headers
            log.debug("got status_code={:d}, encoding={} from_cache={} from {}".
                      format(r.status_code, r.encoding, getattr(r, "from_cache", False), self.url))
            info['Status Code'] = str(r.status_code)
            info['Reason'] = r.reason

            if r.ok:
                data = r.text
            else:
                raise ResourceException("Got status={:d} while fetching {}".format(r.status_code, self.url))
        else:
            raise ResourceException("Unknown resource type {}".format(self.url))

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

            if store is not None:
                store.update(self.t, tid=self.name, etag=self._etag(r))

        return self.children
