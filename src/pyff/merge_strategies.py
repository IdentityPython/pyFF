"""
Merge strategies
"""
__author__ = 'leifj'


def replace_existing(e1, e2):
    if e1 is not None:
        e1.getparent().replace(e1, e2)


def remove(e1, e2):
    if e1 is not None:
        e1.getparent().remove(e1)
