from copy import deepcopy
from datetime import timedelta
import os
import pkg_resources
import re
from lxml import etree
from time import gmtime, strftime
import logging

__author__ = 'leifj'

def resource_string(name,pfx=None):
    """
Attempt to load and return the contents (as a string) of the resource named by
the first argument in the first location of:

# as name in the current directory
# as name in the `pfx` subdirectory of the current directory if it exists
# as name relative to the package
# as pfx/name relative to the package

The last two alternatives is used to locate resources distributed in the package.
This includes certain XSLT and XSD files.

:param name: The string name of a resource
:param pfx: An optional prefix to use in searching for name

    """
    if os.path.exists(name):
        with open(name) as fd:
            return fd.read()
    elif pfx and os.path.exists(os.path.join(pfx,name)):
        with open(os.path.join(pfx,name)) as fd:
            return fd.read()
    elif pkg_resources.resource_exists(__name__,name):
        return pkg_resources.resource_string(__name__,name)
    elif pfx and pkg_resources.resource_exists(__name__,"%s/%s" % (pfx,name)):
        return pkg_resources.resource_string(__name__,"%s/%s" % (pfx,name))

    return None

def dmerge(a, b):
    """
Deep merge of two isomorphically structured dictionaries.

:param a: The dictionary to merge into
:param b: The dictionary to merge from
    """
    for k in a :
        v = a[k]
        if isinstance(v, dict) and k in b:
            dmerge(v, b[k])
    a.update(b)

def tdelta(input):
    """
Parse a time delta from expressions like 1w 32d 4h 5s - i.e in weeks, days hours and/or seconds.

:param input: A human-friendly string representation of a timedelta
    """
    keys = ["weeks", "days", "hours", "minutes"]
    regex = "".join(["((?P<%s>\d+)%s ?)?" % (k, k[0]) for k in keys])
    kwargs = {}
    for k,v in re.match(regex, input).groupdict(default="0").items():
        kwargs[k] = int(v)
    return timedelta(**kwargs)

def dumptree(t):
    """
Return a string representation of the tree.

:param t: An ElemenTree to serialize
    """
    return etree.tostring(t,encoding='UTF-8',xml_declaration=True)#,pretty_print=True)

def iso_now():
    """
Current time in ISO format
    """
    return strftime("%Y-%m-%dT%H:%M:%SZ", gmtime())

class ResourceResolver(etree.Resolver):
    def resolve(self, system_url, public_id, context):
        """
        Resolves URIs using the resource API
        """
        logging.debug("resolve SYSTEM URL' %s' for '%s'" % (system_url,public_id))
        path = system_url.split("/")
        fn = path[len(path)-1]
        if pkg_resources.resource_exists(__name__,fn):
            return self.resolve_file(pkg_resources.resource_stream(__name__,fn),context)
        elif pkg_resources.resource_exists(__name__,"schema/%s" % fn):
            return self.resolve_file(pkg_resources.resource_stream(__name__,"schema/%s" % fn),context)
        else:
            raise ValueError("Unable to locate %s" % fn)

_SCHEMA = None

def schema():
    global _SCHEMA
    if _SCHEMA is None:
        try:
            parser = etree.XMLParser()
            parser.resolvers.add(ResourceResolver())
            st = etree.parse(pkg_resources.resource_stream(__name__,"schema/schema.xsd"),parser)
            _SCHEMA = etree.XMLSchema(st)
        except etree.XMLSchemaParseError, e:
            logging.error(e.error_log)
            raise e
    return _SCHEMA