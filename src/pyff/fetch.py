"""

An abstraction layer for metadata fetchers. Supports both syncronous and asyncronous fetchers with cache.

"""

from __future__ import absolute_import, unicode_literals
from .logs import log
import os
import requests
from requests_file import FileAdapter
from .constants import config
from datetime import datetime
from collections import deque
from UserDict import DictMixin
from concurrent import futures
from .parse import parse_resource
from itertools import chain
from requests_cache.core import CachedSession
from copy import deepcopy

requests.packages.urllib3.disable_warnings()


class ResourceException(Exception):
    def __init__(self, msg, wrapped=None, data=None):
        self._wraped = wrapped
        self._data = data
        super(self.__class__, self).__init__(msg)

    def raise_wraped(self):
        raise self._wraped


class ResourceManager(DictMixin):
    def __init__(self):
        self._resources = dict()
        self.shutdown = False

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
        return self._resources.keys()

    def values(self):
        return self._resources.values()

    def walk(self, url=None):
        if url is not None:
            return self[url].walk()
        else:
            i = [r.walk() for r in self.values()]
            return chain(*i)

    def add(self, r):
        if not isinstance(r, Resource):
            raise ValueError("I can only store Resources")
        self[r.name] = r

    def __contains__(self, item):
        return item in self._resources

    def reload(self, url=None, fail_on_error=False, store=None):
        # type: (object, basestring) -> None
        if url is not None:
            resources = deque([self[url]])
        else:
            resources = deque(self.values())

        with futures.ThreadPoolExecutor(max_workers=config.worker_pool_size) as executor:
            while resources:
                tasks = dict((executor.submit(r.fetch, store=store), r) for r in resources)
                new_resources = deque()
                for future in futures.as_completed(tasks):
                    r = tasks[future]
                    try:
                        res = future.result()
                        if res is not None:
                            for nr in res:
                                new_resources.append(nr)
                    except Exception as ex:
                        log.error(str(ex))
                        if fail_on_error:
                            raise ex
                resources = new_resources


class Resource(object):
    def __init__(self, url, **kwargs):
        self.url = url
        self.opts = kwargs
        self.t = None
        self.type = "text/plain"
        self.expire_time = None
        self.last_seen = None
        self._infos = deque(maxlen=config.info_buffer_size)
        self.children = deque()

        def _null(t):
            return t

        self.opts.setdefault('cleanup', _null)
        self.opts.setdefault('via', _null)
        self.opts.setdefault('fail_on_error', False)
        self.opts.setdefault('as', None)
        self.opts.setdefault('verify', None)
        self.opts.setdefault('filter_invalid', True)
        self.opts.setdefault('validate', True)

        if "://" not in self.url:
            if os.path.isfile(self.url):
                self.url = "file://{}".format(os.path.abspath(self.url))

    @property
    def post(self):
        return self.opts['via']

    @property
    def cleanup(self):
        return self.opts['cleanup']

    def __str__(self):
        return "Resource {} expires at {} using ".format(self.url, self.expire_time) + \
               ",".join(["{}={}".format(k, v) for k, v in self.opts.items()])

    def walk(self):
        yield self
        for c in self.children:
            for cn in c.walk():
                yield cn

    def is_expired(self):
        now = datetime.now()
        return self.expire_time is not None and self.expire_time < now

    def is_valid(self):
        return self.t is not None and not self.is_expired()

    def add_info(self, info):
        self._infos.append(info)

    def add_child(self, url, **kwargs):
        opts = dict()
        opts.update(self.opts)
        del opts['as']
        opts.update(kwargs)
        self.children.append(Resource(url, **opts))

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

    def fetch(self, store=None):
        info = dict()
        info['Resource'] = self.url
        self.add_info(info)
        data = None

        if os.path.isdir(self.url):
            data = self.url
            info['Directory'] = self.url
        elif '://' in self.url:
            s = None
            if 'file://' in self.url:
                s = requests.session()
                s.mount('file://', FileAdapter())
            else:
                s = CachedSession(cache_name="pyff_cache",
                                  expire_after=config.request_cache_time,
                                  old_data_on_error=True)

            r = s.get(self.url, verify=False, timeout=config.request_timeout)
            if config.request_override_encoding is not None:
                r.encoding = config.request_override_encoding

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
            if self.post is not None:
                self.t = self.post(self.t, **self.opts)

            if self.is_expired():
                info['Expired'] = True
                raise ResourceException("Resource at {} expired on {}".format(self.url,self.expire_time))
            else:
                info['Expired'] = False

            for (eid, error) in info['Validation Errors'].items():
                log.error(error)

            if store is not None:
                store.update(self.t, tid=self.name)

        return self.children
