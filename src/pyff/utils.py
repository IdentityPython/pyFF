"""

This module contains various utilities.

"""
from collections import MutableSet, namedtuple
from copy import deepcopy
from datetime import timedelta, datetime
import tempfile
import traceback
import cherrypy
from mako.lookup import TemplateLookup
import os
import pkg_resources
import re
from lxml import etree
from time import gmtime, strftime, clock
from pyff.constants import NS
from pyff.decorators import cached, retry
from pyff.logs import log
import httplib2
import hashlib
from email.utils import parsedate
from urlparse import urlparse
from threading import local, Thread

__author__ = 'leifj'

import i18n

_ = i18n.language.ugettext

sentinel = object()

class PyffException(Exception):
    pass


def _e(error_log, m=None):
    def _f(x):
        if ":WARNING:" in x:
            return False
        if m is not None and not m in x:
            return False
        return True

    return "\n".join(filter(_f, ["%s" % e for e in error_log]))


def debug_observer(e):
    log.error(repr(e))


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
    name = os.path.expanduser(name)
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
        return name
    elif pfx and os.path.exists(os.path.join(pfx, name)):
        return os.path.join(pfx, name)
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


def totimestamp(dt, epoch=datetime(1970, 1, 1)):
    td = dt - epoch
    # return td.total_seconds()
    return (td.microseconds + (td.seconds + td.days * 24 * 3600) * 10**6) / 1e6


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


@cached(hash_key=lambda *args, **kwargs: hash(args[0]))
def validate_document(t):
    schema().assertValid(t)


def safe_write(fn, data):
    """Safely write data to a file with name fn
    :param fn: a filename
    :param data: some data to write
    :return: True or False depending on the outcome of the write
    """
    tmpn = None
    try:
        fn = os.path.expanduser(fn)
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
        if tmpn is not None and os.path.exists(tmpn):
            try:
                os.unlink(tmpn)
            except Exception, ex:
                log.warn(ex)
                pass
    return False


site_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "site")
templates = TemplateLookup(directories=[os.path.join(site_dir, 'templates')])


def template(name):
    return templates.get_template(name)


def request_vhost(request):
    return request.headers.get('X-Forwarded-Host', request.headers.get('Host', request.base))


def render_template(name, **kwargs):
    kwargs.setdefault('http', cherrypy.request)
    kwargs.setdefault('brand', "pyFF @ %s" % request_vhost(cherrypy.request))
    kwargs.setdefault('_', _)
    return template(name).render(**kwargs)

_Resource = namedtuple("Resource", ["result", "cached", "date", "last_modified", "resp", "time"])


@retry(IOError)
def load_url(url, enable_cache=True, timeout=60):

    def _parse_date(s):
        if s is None:
            return datetime.new()
        return datetime(*parsedate(s)[:6])

    start_time = clock()
    cache = httplib2.FileCache(".cache")
    headers = dict()
    if not enable_cache:
        headers['cache-control'] = 'no-cache'

    log.debug("fetching (caching: %s) '%s'" % (enable_cache, url))

    if url.startswith('file://'):
        path = url[7:]
        if not os.path.exists(path):
            raise IOError("file not found: %s" % path)

        with open(path, 'r') as fd:
            return _Resource(result=fd.read(),
                             cached=False,
                             date=datetime.now(),
                             resp=None,
                             time=clock()-start_time,
                             last_modified=datetime.fromtimestamp(os.stat(path).st_mtime))
    else:
        h = httplib2.Http(cache=cache,
                          timeout=timeout,
                          disable_ssl_certificate_validation=True)  # trust is done using signatures over here
        resp, content = h.request(url, headers=headers)
        if resp.status != 200:
            raise IOError(resp.reason)
        return _Resource(result=content,
                         cached=resp.fromcache,
                         date=_parse_date(resp['date']),
                         resp=resp,
                         time=clock()-start_time,
                         last_modified=_parse_date(resp.get('last-modified', resp.get('date', None))))


class URLFetch(Thread):
    def __init__(self, url, verify, id=None, enable_cache=False, tries=0, post=None, timeout=120):
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
        self.post = post
        self.timeout = timeout

        if self.id is None:
            self.id = self.url

        Thread.__init__(self)

    def time(self):
        if self.isAlive():
            raise ValueError("caller attempted to obtain execution time while fetcher still active")
        return self.end_time - self.start_time

    def run(self):

        def _parse_date(s):
            if s is None:
                return datetime.new()
            return datetime(*parsedate(s)[:6])

        self.start_time = clock()
        try:
            cache = httplib2.FileCache(".cache")
            headers = dict()
            if not self.enable_cache:
                headers['cache-control'] = 'no-cache'

            log.debug("fetching '%s'" % self.url)

            if self.url.startswith('file://'):
                path = self.url[7:]
                if not os.path.exists(path):
                    raise IOError("file not found: %s" % path)

                with open(path, 'r') as fd:
                    self.result = fd.read()
                    self.cached = False
                    self.date = datetime.now()
                    self.last_modified = datetime.fromtimestamp(os.stat(path).st_mtime)
            else:
                h = httplib2.Http(cache=cache,
                                  timeout=self.timeout,
                                  disable_ssl_certificate_validation=True)  # trust is done using signatures over here
                resp, content = h.request(self.url, headers=headers)
                self.resp = resp
                self.last_modified = _parse_date(resp.get('last-modified', resp.get('date', None)))
                self.date = _parse_date(resp['date'])
                if resp.status != 200:
                    raise IOError(resp.reason)
                self.result = content
                self.cached = resp.fromcache

            log.debug("got %d bytes from '%s'" % (len(self.result), self.url))
        except Exception, ex:
            #traceback.print_exc()
            log.warn("unable to fetch '%s': %s" % (self.url, ex))
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

    if elts is None:
        return []

    lst = filter(_l, elts)
    if lst:
        return lst
    else:
        return elts

thread_data = local()

def xslt_transform(t, stylesheet, params={}):
    if not hasattr(thread_data,'xslt'):
        thread_data.xslt = dict()

    transform = None
    if not stylesheet in thread_data.xslt:
        xsl = etree.fromstring(resource_string(stylesheet, "xslt"))
        thread_data.xslt[stylesheet] = etree.XSLT(xsl)
    transform = thread_data.xslt[stylesheet]
    return transform(deepcopy(t), **params)


def total_seconds(dt):
    if hasattr(dt, "total_seconds"):
        return dt.total_seconds()
    else:
        return (dt.microseconds + (dt.seconds + dt.days * 24 * 3600) * 10 ** 6) / 10 ** 6


def etag(s):
    return hash_str('sha1',s)


def hash_str(hn, s):
    if hn == 'null':
        return s
    if not hasattr(hashlib, hn):
        raise ValueError("Unknown digest mechanism: '%s'" % hn)
    hash_m = getattr(hashlib, hn)
    h = hash_m()
    h.update(s)
    return h.hexdigest()


def hash_id(entity, hn='sha1', prefix=True):
    entity_id = entity
    if hasattr(entity, 'get'):
        entity_id = entity.get('entityID')

    hstr = hex_digest(entity_id, hn)
    if prefix:
        return "{%s}%s" % (hn, hstr)
    else:
        return hstr


def hex_digest(data, hn='sha1'):
    if hn == 'null':
        return data

    if not hasattr(hashlib, hn):
        raise ValueError("Unknown digest '%s'" % hn)

    m = getattr(hashlib, hn)()
    m.update(data)
    return m.hexdigest()


def parse_xml(io, base_url=None):
    return etree.parse(io, base_url=base_url, parser=etree.XMLParser(resolve_entities=False))


class EntitySet(MutableSet):
    def __init__(self, initial=None):
        self._e = dict()
        if initial is not None:
            for e in initial:
                self.add(e)

    def add(self, value):
        self._e[value.get('entityID')] = value

    def discard(self, value):
        entityID = value.get('entityID')
        if entityID in self._e:
            del self._e[entityID]

    def __iter__(self):
        for e in self._e.values():
            yield e

    def __len__(self):
        return len(self._e.keys())

    def __contains__(self, item):
        return item.get('entityID') in self._e.keys()


class MetadataException(Exception):
    pass


def find_merge_strategy(strategy_name):
    if not '.' in strategy_name:
        strategy_name = "pyff.merge_strategies.%s" % strategy_name
    (mn, sep, fn) = strategy_name.rpartition('.')
    # log.debug("import %s from %s" % (fn,mn))
    module = None
    if '.' in mn:
        (pn, sep, modn) = mn.rpartition('.')
        module = getattr(__import__(pn, globals(), locals(), [modn], -1), modn)
    else:
        module = __import__(mn, globals(), locals(), [], -1)
    strategy = getattr(module, fn)  # we might aswell let this fail early if the strategy is wrongly named

    if strategy is None:
        raise MetadataException("Unable to find merge strategy %s" % strategy_name)

    return strategy


def entities_list(t=None):
        """
        :param t: An EntitiesDescriptor or EntityDescriptor element

        Returns the list of contained EntityDescriptor elements
        """
        if t is None:
            return []
        elif root(t).tag == "{%s}EntityDescriptor" % NS['md']:
            return [root(t)]
        else:
            return iter_entities(t)


def iter_entities(t):
    return t.iter('{%s}EntityDescriptor' % NS['md'])


def has_tag(t, tag):
    tags = t.iter(tag)
    return next(tags, sentinel) is not sentinel


def url2host(url):
    try:
        (host, sep, port) = urlparse(url).netloc.partition(':')
        return host
    except ValueError:
        return None


def subdomains(domain):
    domains = []
    dsplit = domain.split('.')
    for i in range(1, len(dsplit)-1):
        domains.append(".".join(dsplit[i:]))
    return domains


def ddist(a, b):
    if len(a) > len(b):
        return ddist(b, a)

    a = a.split('.')
    b = b.split('.')

    d = [x[0] == x[1] for x in zip(a[::-1], b[::-1])]
    if False in d:
        return d.index(False)
    return len(a)


def avg_domain_distance(d1, d2):
    dd = 0
    n = 0
    for a in d1.split(';'):
        for b in d2.split(';'):
            d = ddist(a, b)
            if log.isDebugEnabled():
                log.debug("ddist %s %s -> %d" % (a,b,d))
            dd += d
            n += 1
    return int(dd / n)
