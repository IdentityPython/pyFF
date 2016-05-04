"""

This module contains various utilities.

"""
import hashlib
import io
import tempfile
from collections import namedtuple
from datetime import timedelta, datetime
from email.utils import parsedate
from threading import local
from time import gmtime, strftime, clock
from traceback import print_exc
from urlparse import urlparse

import xmlsec
import cherrypy
import httplib2
import iso8601
import os
import pkg_resources
import re
from jinja2 import Environment, PackageLoader
from lxml import etree

from .constants import NS
from .decorators import retry
from .logs import log

__author__ = 'leifj'

import i18n

sentinel = object()
thread_data = local()


class PyffException(Exception):
    pass


def xml_error(error_log, m=None):
    def _f(x):
        if ":WARNING:" in x:
            return False
        if m is not None and m not in x:
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
        with io.open(name) as fd:
            return fd.read()
    elif pfx and os.path.exists(os.path.join(pfx, name)):
        with io.open(os.path.join(pfx, name)) as fd:
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


def totimestamp(dt, epoch=datetime(1970, 1, 1)):
    epoch = epoch.replace(tzinfo=dt.tzinfo)

    td = dt - epoch
    ts = (td.microseconds + (td.seconds + td.days * 24 * 3600) * 10 ** 6) / 1e6
    return int(ts)


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
    return iso_fmt()


def iso_fmt(tstamp=None):
    """
Timestamp in ISO format
    """
    return strftime("%Y-%m-%dT%H:%M:%SZ", gmtime(tstamp))


def iso2datetime(s):
    return iso8601.parse_date(s)


class ResourceResolver(etree.Resolver):
    def __init__(self):
        super(ResourceResolver, self).__init__()

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


def schema():
    if not hasattr(thread_data, 'schema'):
        thread_data.schema = None

    if thread_data.schema is None:
        try:
            parser = etree.XMLParser()
            parser.resolvers.add(ResourceResolver())
            st = etree.parse(pkg_resources.resource_stream(__name__, "schema/schema.xsd"), parser)
            thread_data.schema = etree.XMLSchema(st)
        except etree.XMLSchemaParseError, ex:
            log.error(xml_error(ex.error_log))
            raise ex
    return thread_data.schema


def check_signature(t, key):
    if key is not None:
        log.debug("verifying signature using %s" % key)
        refs = xmlsec.verified(t, key, drop_signature=True)
        if len(refs) != 1:
            raise MetadataException(
                "XML metadata contains %d signatures - exactly 1 is required" % len(refs))
        t = refs[0]  # prevent wrapping attacks

    return t

# @cached(hash_key=lambda *args, **kwargs: hash(args[0]))
def validate_document(t):
    schema().assertValid(t)


def request_vhost(request):
    return request.headers.get('X-Forwarded-Host', request.headers.get('Host', request.base))


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
    return False


site_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "site")
env = Environment(loader=PackageLoader(__package__, 'templates'), extensions=['jinja2.ext.i18n'])
env.install_gettext_callables(i18n.language.gettext, i18n.language.ngettext, newstyle=True)

import urllib
from markupsafe import Markup


def urlencode_filter(s):
    if type(s) == 'Markup':
        s = s.unescape()
    s = s.encode('utf8')
    s = urllib.quote_plus(s)
    return Markup(s)

def truncate_filter(s,max_len=10):
    if len(s) > max_len:
        return s[0:max_len]+"..."
    else:
        return s

env.filters['u'] = urlencode_filter
env.filters['truncate'] = truncate_filter

def template(name):
    return env.get_template(name)

def render_template(name, **kwargs):
    kwargs.setdefault('http', cherrypy.request)
    kwargs.setdefault('brand', "pyFF @ %s" % request_vhost(cherrypy.request))
    kwargs.setdefault('_', _)
    return template(name).render(**kwargs)


_Resource = namedtuple("Resource", ["result", "cached", "date", "last_modified", "resp", "time"])


def parse_date(s):
    if s is None:
        return datetime.now()
    return datetime(*parsedate(s)[:6])

@retry((IOError, httplib2.HttpLib2Error))
def load_url(url, enable_cache=True, timeout=60):
    start_time = clock()
    cache = httplib2.FileCache(".cache")
    headers = dict()
    if not enable_cache:
        headers['cache-control'] = 'no-cache'

    log.debug("fetching (caching: %s) '%s'" % (enable_cache, url))

    if url.startswith('file://'):
        path = url[7:]
        if not os.path.exists(path):
            log.error("file not found: %s" % path)
            return _Resource(result=None,
                             cached=False,
                             date=None,
                             resp=None,
                             time=None,
                             last_modified=None)

        with io.open(path, 'rb') as fd:
            return _Resource(result=fd.read(),
                             cached=False,
                             date=datetime.now(),
                             resp=None,
                             time=clock() - start_time,
                             last_modified=datetime.fromtimestamp(os.stat(path).st_mtime))
    else:
        h = httplib2.Http(cache=cache,
                          timeout=timeout,
                          disable_ssl_certificate_validation=True)  # trust is done using signatures over here
        log.debug("about to request %s" % url)
        print repr(cache.__dict__)
        try:
            resp, content = h.request(url, headers=headers)
        except Exception, ex:
            print_exc(ex)
            raise ex
        log.debug("got status: %d" % resp.status)
        if resp.status != 200:
            log.debug("got resp code %d (%d bytes)" % (resp.status, len(content)))
            raise IOError(resp.reason)
        log.debug("last-modified header: %s" % resp.get('last-modified'))
        log.debug("date header: %s" % resp.get('date'))
        log.debug("last modified: %s" % resp.get('date', resp.get('last-modified', None)))
        return _Resource(result=content,
                         cached=resp.fromcache,
                         date=parse_date(resp['date']),
                         resp=resp,
                         time=clock() - start_time,
                         last_modified=parse_date(resp.get('date', resp.get('last-modified', None))))


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


def filter_lang(elts, langs=None):

    if langs is None or type(langs) is not list:
        langs = ['en']

    def _l(elt):
        return elt.get("{http://www.w3.org/XML/1998/namespace}lang", "en") in langs

    if elts is None:
        return []

    lst = filter(_l, elts)
    if lst:
        return lst
    else:
        return elts


def xslt_transform(t, stylesheet, params=None):
    if not params:
        params = dict()

    if not hasattr(thread_data, 'xslt'):
        thread_data.xslt = dict()

    transform = None
    if stylesheet not in thread_data.xslt:
        xsl = etree.fromstring(resource_string(stylesheet, "xslt"))
        thread_data.xslt[stylesheet] = etree.XSLT(xsl)
    transform = thread_data.xslt[stylesheet]
    try:
        return transform(t, **params)
    except etree.XSLTApplyError, ex:
        for entry in transform.error_log:
            log.error('\tmessage from line %s, col %s: %s' % (entry.line, entry.column, entry.message))
            log.error('\tdomain: %s (%d)' % (entry.domain_name, entry.domain))
            log.error('\ttype: %s (%d)' % (entry.type_name, entry.type))
            log.error('\tlevel: %s (%d)' % (entry.level_name, entry.level))
            log.error('\tfilename: %s' % entry.filename)
        raise ex


def valid_until_ts(elt, default_ts):
    ts = default_ts
    valid_until = elt.get("validUntil", None)
    if valid_until is not None:
        dt = iso8601.parse_date(valid_until)
        if dt is not None:
            ts = totimestamp(dt)

    cache_duration = elt.get("cacheDuration", None)
    if cache_duration is not None:
        dt = datetime.utcnow() + duration2timedelta(cache_duration)
        if dt is not None:
            ts = totimestamp(dt)

    return ts


def total_seconds(dt):
    if hasattr(dt, "total_seconds"):
        return dt.total_seconds()
    else:
        return (dt.microseconds + (dt.seconds + dt.days * 24 * 3600) * 10 ** 6) / 10 ** 6


def etag(s):
    return hex_digest('sha1', s)


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


class EntitySet(object):
    def __init__(self, initial=None):
        self._e = dict()
        if initial is not None:
            for e in initial:
                self.add(e)

    def add(self, value):
        self._e[value.get('entityID')] = value

    def discard(self, value):
        entity_id = value.get('entityID')
        if entity_id in self._e:
            del self._e[entity_id]

    def __iter__(self):
        for e in self._e.values():
            yield e

    def __len__(self):
        return len(self._e.keys())

    def __contains__(self, item):
        return item.get('entityID') in self._e.keys()


class MetadataException(Exception):
    pass


class MetadataExpiredException(MetadataException):
    pass


def find_merge_strategy(strategy_name):
    if '.' not in strategy_name:
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
    if t is None:
        return []
    return t.iter('{%s}EntityDescriptor' % NS['md'])


def find_entity(t, e_id, attr='entityID'):
    for e in iter_entities(t):
        if e.get(attr) == e_id:
            return e
    return None


def has_tag(t, tag):
    tags = t.iter(tag)
    return next(tags, sentinel) is not sentinel


def url2host(url):
    (host, sep, port) = urlparse(url).netloc.partition(':')
    return host



def subdomains(domain):
    dl = []
    dsplit = domain.split('.')
    if len(dsplit) < 3:
        dl.append(domain)
    else:
        for i in range(1, len(dsplit) - 1):
            dl.append(".".join(dsplit[i:]))

    return dl


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
            log.debug("ddist %s %s -> %d" % (a, b, d))
            dd += d
            n += 1
    return int(dd / n)
