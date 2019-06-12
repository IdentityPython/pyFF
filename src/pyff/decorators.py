"""
Various decorators used in pyFF.
"""
import functools
from collections import namedtuple
import time
from .logs import get_log

__author__ = 'leifj'

log = get_log(__name__)


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
