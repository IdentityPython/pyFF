"""
Various decorators used in pyFF.
"""
import functools
from collections import namedtuple
import time
from .logs import get_log

__author__ = 'leifj'

log = get_log(__name__)


def heapy(trace=False, minsize=0):
    def decorating(func):
        def new_func(*args, **kwargs):
            from gc import collect
            collect()
            from guppy import hpy
            hp = hpy()
            hp.setrelheap()
            r = func(*args, **kwargs)
            collect()
            after = hp.heap()
            print("-----------------------------")
            print(args)
            print(kwargs)
            print(after)
            print("+++++++++++++++++++++++++++++")
            if trace and after.size > minsize:
                import pdb
                pdb.set_trace()

            return r
        return new_func
    return decorating


def deprecated(logger=log, reason="Complain to the developer about unspecified code deprecation"):
    """This is a decorator which can be used to mark functions
    as deprecated. It will result in a warning being emitted
    when the function is used."""

    def decorating(func):
        def new_func(*args, **kwargs):
            msg = "Call to deprecated function %s at %s:%d\nReason: %s" % (func.__name__,
                                                                           func.__code__.co_filename,
                                                                           func.__code__.co_firstlineno + 1, reason)
            if logger:
                logger.warn(msg)
            else:
                print(msg)

            return func(*args, **kwargs)

        return new_func

    return decorating
