"""
Various decorators used in pyFF.
"""
from collections import namedtuple
import functools

__author__ = 'leifj'

import time
from pyff.logs import log


def retry(ex, tries=4, delay=3, backoff=2, logger=log):
    """Retry calling the decorated function using exponential backoff based on

    * http://www.saltycrane.com/blog/2009/11/trying-out-retry-decorator-python/
    * http://wiki.python.org/moin/PythonDecoratorLibrary#Retry

    :param ex: the exception to check. may be a tuple of
        excpetions to check
    :type ex: Exception or tuple
    :param tries: number of times to try (not retry) before giving up
    :type tries: int
    :param delay: initial delay between retries in seconds
    :type delay: int
    :param backoff: backoff multiplier e.g. value of 2 will double the delay
        each retry
    :type backoff: int
    :param logger: logger to use. If None, print
    :type logger: logging.Logger instance
    """

    def deco_retry(f):
        def f_retry(*args, **kwargs):
            mtries, mdelay = tries, delay
            try_one_last_time = True
            while mtries > 1:
                try:
                    return f(*args, **kwargs)
                except ex, e:
                    msg = "%s, Retrying in %d seconds..." % (str(e), mdelay)
                    if logger:
                        logger.warn(msg)
                    else:
                        print msg
                    time.sleep(mdelay)
                    mtries -= 1
                    mdelay *= backoff
            if try_one_last_time:
                return f(*args, **kwargs)
            return

        return f_retry  # true decorator

    return deco_retry


def deprecated(func):
    """This is a decorator which can be used to mark functions
    as deprecated. It will result in a warning being emitted
    when the function is used."""

    @functools.wraps(func)
    def new_func(*args, **kwargs):
        log.warn("Call to deprecated function %s at %s:%d" % (func.__name__,
                                                              func.func_code.co_filename,
                                                              func.func_code.co_firstlineno + 1))
        return func(*args, **kwargs)

    return new_func


class _HashedSeq(list):
    __slots__ = 'hashvalue'

    def __init__(self, tup, thehash=hash):
        self[:] = tup
        self.hashvalue = thehash(tup)

    def __hash__(self):
        return self.hashvalue


def _make_key(args, kwds, typed,
              kwd_mark=(object(),),
              fasttypes={int, str, frozenset, type(None)},
              thesorted=sorted,
              thetuple=tuple,
              thetype=type,
              thelen=len):
    'Make a cache key from optionally typed positional and keyword arguments'
    key = args
    if kwds:
        sorted_items = thesorted(kwds.items())
        key += kwd_mark
        for item in sorted_items:
            key += item
    if typed:
        key += thetuple(thetype(v) for v in args)
        if kwds:
            key += thetuple(thetype(v) for k, v in sorted_items)
    elif thelen(key) == 1 and thetype(key[0]) in fasttypes:
        return key[0]
    return _HashedSeq(key)


_CacheObject = namedtuple("CacheObject", ['valid_until', 'object'])


def cached(typed=False, ttl=None, hash_key=None):
    def decorating(func):

        cache = dict()
        stats = dict(hits=0, misses=0)
        make_key = hash_key or _make_key

        def wrapper(*args, **kwargs):
            key = make_key(args, kwargs, typed)
            now = time.time()
            if key in cache:
                o = cache[key]
                if o.valid_until is None or o.valid_until > now:
                    stats['hits'] += 1
                    return o.object

            result = func(*args, **kwargs)
            stats['misses'] += 1
            expires = None
            if ttl is not None:
                expires = now + ttl
            cache[key] = _CacheObject(valid_until=expires, object=result)
            return result

        def clear():
            cache.clear()
            stats.hits = 0
            stats.misses = 0

        @property
        def hits():
            return stats['hits']

        @property
        def misses():
            return stats['misses']

        def invalidate(*args, **kwargs):
            key = make_key(args, kwargs, typed)
            if key in cache:
                del cache[key]

        wrapper.__wrapped__ = func
        wrapper.clear = clear
        wrapper.hits = hits
        wrapper.misses = misses
        wrapper.invalidate = invalidate

        return functools.update_wrapper(wrapper, func)

    return decorating


