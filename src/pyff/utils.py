"""

This module contains various utilities.

"""
from datetime import timedelta, datetime
import tempfile
import traceback
from mako.lookup import TemplateLookup
import os
import pkg_resources
import re
from lxml import etree
from time import gmtime, strftime, clock
from pyff.logs import log
import threading
import httplib2
from email.utils import parsedate

__author__ = 'leifj'


def _e(error_log):
    return "\n".join(filter(lambda x: ":WARNING:" not in x, ["%s" % e for e in error_log]))


def resource_string(name, pfx=None):
    """
Attempt to load and return the contents (as a string) of the resource named by
the first argument in the first location of:

# as name in the current directory
# as name in the `pfx` subdirectory of the current directory if provided
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
    elif pfx and os.path.exists(os.path.join(pfx, name)):
        with open(os.path.join(pfx, name)) as fd:
            return fd.read()
    elif pkg_resources.resource_exists(__name__, name):
        return pkg_resources.resource_string(__name__, name)
    elif pfx and pkg_resources.resource_exists(__name__, "%s/%s" % (pfx, name)):
        return pkg_resources.resource_string(__name__, "%s/%s" % (pfx, name))

    return None


def resource_filename(name, pfx=None):
    """
Attempt to find and return the filename of the resource named by the first argument
in the first location of:

# as name in the current directory
# as name in the `pfx` subdirectory of the current directory if provided
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
    elif pfx and os.path.exists(os.path.join(pfx, name)):
        with open(os.path.join(pfx, name)) as fd:
            return fd.read()
    elif pkg_resources.resource_exists(__name__, name):
        return pkg_resources.resource_filename(__name__, name)
    elif pfx and pkg_resources.resource_exists(__name__, "%s/%s" % (pfx, name)):
        return pkg_resources.resource_filename(__name__, "%s/%s" % (pfx, name))

    return None


def dmerge(a, b):
    """
Deep merge of two isomorphically structured dictionaries.

:param a: The dictionary to merge into
:param b: The dictionary to merge from
    """
    for k in a:
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
    for k, v in re.match(regex, input).groupdict(default="0").items():
        kwargs[k] = int(v)
    return timedelta(**kwargs)


def dumptree(t, pretty_print=False, xml_declaration=True):
    """
Return a string representation of the tree, optionally pretty_print(ed) (default False)

:param t: An ElemenTree to serialize
    """
    return etree.tostring(t, encoding='UTF-8', xml_declaration=xml_declaration, pretty_print=pretty_print)


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
        log.debug("resolve SYSTEM URL' %s' for '%s'" % (system_url, public_id))
        path = system_url.split("/")
        fn = path[len(path) - 1]
        if pkg_resources.resource_exists(__name__, fn):
            return self.resolve_file(pkg_resources.resource_stream(__name__, fn), context)
        elif pkg_resources.resource_exists(__name__, "schema/%s" % fn):
            return self.resolve_file(pkg_resources.resource_stream(__name__, "schema/%s" % fn), context)
        else:
            raise ValueError("Unable to locate %s" % fn)


_SCHEMA = None


def schema():
    global _SCHEMA
    if _SCHEMA is None:
        try:
            parser = etree.XMLParser()
            parser.resolvers.add(ResourceResolver())
            st = etree.parse(pkg_resources.resource_stream(__name__, "schema/schema.xsd"), parser)
            _SCHEMA = etree.XMLSchema(st)
        except etree.XMLSchemaParseError, ex:
            log.error(_e(ex.error_log))
            raise ex
    return _SCHEMA


def safe_write(fn, data):
    tmpn = None
    try:
        dirname, basename = os.path.split(fn)
        with tempfile.NamedTemporaryFile('w', delete=False, prefix=".%s" % basename, dir=dirname) as tmp:
            tmp.write(data)
            tmpn = tmp.name
        if os.path.exists(tmpn) and os.stat(tmpn).st_size > 0:
            os.rename(tmpn, fn)
            return True
    except Exception, ex:
        log.error(ex)
    finally:
        if tmpn is not None:
            try:
                os.unlink(tmpn)
            except Exception:
                pass
    return False


site_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "site")
templates = TemplateLookup(directories=[os.path.join(site_dir, 'templates')])


def template(name):
    return templates.get_template(name)


class URLFetch(threading.Thread):
    def __init__(self, url, verify, id=None, enable_cache=False, tries=0):
        self.url = url.strip()
        self.verify = verify
        self.id = id
        self.result = None
        self.ex = None
        self.cached = False
        self.enable_cache = enable_cache
        self.cache_ttl = 0
        self.last_modified = None
        self.date = None
        self.tries = 0
        self.resp = None
        self.start_time = 0
        self.end_time = 0
        self.tries = tries

        if self.id is None:
            self.id = self.url

        threading.Thread.__init__(self)

    def time(self):
        if self.isAlive():
            raise ValueError("I'm not done yet")
        return self.end_time - self.start_time

    def run(self):

        def _parse_date(str):
            if str is None:
                return datetime.new()
            return datetime(*parsedate(str)[:6])

        self.start_time = clock()
        try:
            cache = None
            if self.enable_cache:
                log.debug("fetching %s using cache" % self.url)
                cache = ".cache"
            else:
                log.debug("fetching %s without using cache" % self.url)

            if self.url.startswith('file://'):
                path = self.url[7:]
                if not os.path.exists(path):
                    raise IOError("File not found: %s" % path)

                with open(path, 'r') as fd:
                    self.result = fd.read()
                    self.cached = False
                    self.date = datetime.now()
                    self.last_modified = datetime.fromtimestamp(os.stat(path).st_mtime)
            else:
                h = httplib2.Http(cache=cache, timeout=20,
                                  disable_ssl_certificate_validation=True) # yes this is correct!
                resp, content = h.request(self.url)
                self.resp = resp
                self.last_modified = _parse_date(resp.get('last-modified', resp.get('date', None)))
                self.date = _parse_date(resp['date'])
                if resp.status != 200:
                    log.error("got %d: %s from %s" % (resp.status, resp.reason, self.url))
                    raise IOError(resp.reason)
                self.result = content
                self.cached = resp.fromcache

            log.debug("got %d bytes from %s" % (len(self.result), self.url))
        except Exception, ex:
            traceback.print_exc()
            self.ex = ex
            self.result = None
        finally:
            self.end_time = clock()


def root(t):
    if hasattr(t, 'getroot') and hasattr(t.getroot, '__call__'):
        return t.getroot()
    else:
        return t


def duration2timedelta(period):
    regex = re.compile(
        '(?P<sign>[-+]?)P(?:(?P<years>\d+)[Yy])?(?:(?P<months>\d+)[Mm])?(?:(?P<days>\d+)[Dd])?(?:T(?:(?P<hours>\d+)[Hh])?(?:(?P<minutes>\d+)[Mm])?(?:(?P<seconds>\d+)[Ss])?)?')

    # Fetch the match groups with default value of 0 (not None)
    m = regex.match(period)
    if not m:
        return None

    duration = m.groupdict(0)

    # Create the timedelta object from extracted groups
    delta = timedelta(days=int(duration['days']) + (int(duration['months']) * 30) + (int(duration['years']) * 365),
                      hours=int(duration['hours']),
                      minutes=int(duration['minutes']),
                      seconds=int(duration['seconds']))

    if duration['sign'] == "-":
        delta *= -1

    return delta


def filter_lang(elts, langs=["en"]):
    def _l(elt):
        return elt.get("{http://www.w3.org/XML/1998/namespace}lang", None) in langs

    if elts is None or len(elts) == 0:
        return []

    lst = filter(_l, elts)
    if lst:
        return lst
    else:
        return elts


def xslt_transform(t, stylesheet, params={}):
    xsl = etree.fromstring(resource_string(stylesheet, "xslt"))
    transform = etree.XSLT(xsl)
    return transform(t, **params)

def total_seconds(dt):
    if hasattr(dt, "total_seconds"):
        return dt.total_seconds()
    else: 
        return (dt.microseconds + (dt.seconds + dt.days * 24 * 3600) * 10 ** 6) / 10 ** 6
