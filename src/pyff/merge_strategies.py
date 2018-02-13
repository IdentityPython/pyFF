"""
Merge strategies
"""
__author__ = 'leifj'


def replace_existing(old, new):
    if old is not None:
        old.getparent().replace(old, new)
    return new


def remove(old, new):
    if old is not None:
        old.getparent().remove(old)
    return None
