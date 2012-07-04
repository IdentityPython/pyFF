from datetime import timedelta
import os
import pkg_resources
import re

__author__ = 'leifj'



def resource_string(name,pfx=None):
    if os.path.exists(name):
        with open(name) as fd:
            return fd.read()
    if pkg_resources.resource_exists(__name__,name):
        return pkg_resources.resource_string(__name__,name)
    elif pfx and pkg_resources.resource_exists(__name__,"%s/%s" % (pfx,name)):
        return pkg_resources.resource_string(__name__,"%s/%s" % (pfx,name))
    return None

def dmerge(a, b) :
    for k in a :
        v = a[k]
        if isinstance(v, dict) and k in b:
            dmerge(v, b[k])
    a.update(b)

def tdelta(input):
    keys = ["weeks", "days", "hours", "minutes"]
    regex = "".join(["((?P<%s>\d+)%s ?)?" % (k, k[0]) for k in keys])
    kwargs = {}
    for k,v in re.match(regex, input).groupdict(default="0").items():
        kwargs[k] = int(v)
    return timedelta(**kwargs)