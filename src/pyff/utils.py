# coding=utf-8


"""

This module contains various utilities.

"""
import base64
import cgi
import contextlib
import hashlib
import io
import os
import random
import re
import tempfile
import threading
import time
import traceback
from _collections_abc import Mapping, MutableMapping
from copy import copy
from datetime import datetime, timedelta, timezone
from email.utils import parsedate
from itertools import chain
from threading import local
from time import gmtime, strftime
from typing import Any, BinaryIO, Callable, Dict, List, Optional, Sequence, Set, Tuple, Union

import pkg_resources
import requests
import xmlsec
from apscheduler.executors.pool import ThreadPoolExecutor
from apscheduler.jobstores.memory import MemoryJobStore
from apscheduler.jobstores.redis import RedisJobStore
from apscheduler.schedulers.background import BackgroundScheduler
from cachetools import LRUCache
from lxml import etree
from lxml.etree import Element, ElementTree
from requests import Session
from requests.adapters import BaseAdapter, HTTPAdapter, Response
from requests.packages.urllib3.util.retry import Retry
from requests.structures import CaseInsensitiveDict
from requests_cache import CachedSession
from requests_file import FileAdapter
from six.moves.urllib_parse import urlparse

from pyff import __version__
from pyff.constants import NS, config
from pyff.exceptions import *
from pyff.logs import get_log

etree.set_default_parser(etree.XMLParser(resolve_entities=False))

__author__ = 'leifj'

log = get_log(__name__)

sentinel = object()
thread_data = local()


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


def trunc_str(x, l):
    return (x[:l] + '..') if len(x) > l else x


def resource_string(name: str, pfx: Optional[str] = None) -> Optional[Union[str, bytes]]:
    """
    Attempt to load and return the contents (as a string, or bytes) of the resource named by
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
    data: Optional[Union[str, bytes]] = None
    if os.path.exists(name):
        with io.open(name) as fd:
            data = fd.read()
    elif pfx and os.path.exists(os.path.join(pfx, name)):
        with io.open(os.path.join(pfx, name)) as fd:
            data = fd.read()
    elif pkg_resources.resource_exists(__name__, name):
        data = pkg_resources.resource_string(__name__, name)
    elif pfx and pkg_resources.resource_exists(__name__, "%s/%s" % (pfx, name)):
        data = pkg_resources.resource_string(__name__, "%s/%s" % (pfx, name))

    return data


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


def totimestamp(dt: datetime, epoch=datetime(1970, 1, 1)) -> int:
    epoch = epoch.replace(tzinfo=dt.tzinfo)

    td = dt - epoch
    ts = (td.microseconds + (td.seconds + td.days * 24 * 3600) * 10 ** 6) / 1e6
    return int(ts)


def dumptree(t: ElementTree, pretty_print: bool = False, method: str = 'xml', xml_declaration: bool = True) -> str:
    """
    Return a string representation of the tree, optionally pretty_print(ed) (default False)

    :param t: An ElementTree to serialize
    """
    return etree.tostring(
        t, encoding='UTF-8', method=method, xml_declaration=xml_declaration, pretty_print=pretty_print
    )


def iso_now() -> str:
    """
    Current time in ISO format
    """
    return iso_fmt()


def iso_fmt(tstamp: Optional[float] = None) -> str:
    """
    Timestamp in ISO format
    """
    return strftime("%Y-%m-%dT%H:%M:%SZ", gmtime(tstamp))


def ts_now() -> int:
    return int(time.time())


def iso2datetime(s: str) -> datetime:
    # TODO: All timestamps in SAML are supposed to be without offset from UTC - raise exception if it is not?
    if s.endswith('Z'):
        s = s[:-1] + '+00:00'
    return datetime.fromisoformat(s)


def datetime2iso(dt: datetime) -> str:
    s = dt.replace(microsecond=0).isoformat()
    # Use 'Z' instead of +00:00 suffix for UTC times
    if s.endswith('+00:00'):
        s = s[:-6] + 'Z'
    return s


def first_text(elt, tag, default=None):
    for matching in elt.iter(tag):
        return matching.text
    return default


class ResourceResolver(etree.Resolver):
    def __init__(self):
        super(ResourceResolver, self).__init__()

    def resolve(self, system_url, public_id, context):
        """
        Resolves URIs using the resource API
        """
        # log.debug("resolve SYSTEM URL' %s' for '%s'" % (system_url, public_id))
        path = system_url.split("/")
        fn = path[len(path) - 1]
        if pkg_resources.resource_exists(__name__, fn):
            return self.resolve_file(pkg_resources.resource_stream(__name__, fn), context)
        elif pkg_resources.resource_exists(__name__, "schema/%s" % fn):
            return self.resolve_file(pkg_resources.resource_stream(__name__, "schema/%s" % fn), context)
        else:
            raise ValueError("Unable to locate %s" % fn)


thread_local_lock = threading.Lock()


def schema():
    if not hasattr(thread_data, 'schema'):
        thread_data.schema = None

    if thread_data.schema is None:
        try:
            thread_local_lock.acquire(blocking=True)
            parser = etree.XMLParser()
            parser.resolvers.add(ResourceResolver())
            st = etree.parse(pkg_resources.resource_stream(__name__, "schema/schema.xsd"), parser)
            thread_data.schema = etree.XMLSchema(st)
        except etree.XMLSchemaParseError as ex:
            traceback.print_exc()
            log.error(xml_error(ex.error_log))
            raise ex
        finally:
            thread_local_lock.release()
    return thread_data.schema


def redis():
    if not hasattr(thread_data, 'redis'):
        thread_data.redis = None

    try:
        from redis import StrictRedis
    except ImportError:
        raise ValueError("redis_py missing from dependencies")

    if thread_data.redis is None:
        try:
            thread_local_lock.acquire(blocking=True)
            thread_data.redis = StrictRedis(host=config.redis_host, port=config.redis_port)
        except BaseException as ex:
            traceback.print_exc()
            log.error(ex)
            raise ex
        finally:
            thread_local_lock.release()

    return thread_data.redis


def check_signature(t: ElementTree, key: Optional[str], only_one_signature: bool = False) -> ElementTree:
    if key is not None:
        log.debug("verifying signature using %s" % key)
        refs = xmlsec.verified(t, key, drop_signature=True)
        if only_one_signature and len(refs) != 1:
            raise MetadataException("XML metadata contains %d signatures - exactly 1 is required" % len(refs))
        t = refs[0]  # prevent wrapping attacks

    return t


def validate_document(t):
    schema().assertValid(t)


def request_vhost(request):
    return request.headers.get('X-Forwarded-Host', request.headers.get('Host', request.base))


def request_scheme(request):
    return request.headers.get('X-Forwarded-Proto', request.scheme)


def ensure_dir(fn):
    d = os.path.dirname(fn)
    if not os.path.exists(d):
        os.makedirs(d)


def safe_write(fn, data, mkdirs=False):
    """Safely write data to a file with name fn
    :param fn: a filename
    :param data: some string data to write
    :param mkdirs: create directories along the way (False by default)
    :return: True or False depending on the outcome of the write
    """
    tmpn = None
    try:
        fn = os.path.expanduser(fn)
        dirname, basename = os.path.split(fn)
        kwargs = dict(delete=False, prefix=".%s" % basename, dir=dirname)
        if six.PY3:
            kwargs['encoding'] = "utf-8"
            mode = 'w+'
        else:
            mode = 'w+b'

        if mkdirs:
            ensure_dir(fn)

        if isinstance(data, six.binary_type):
            data = data.decode('utf-8')

        with tempfile.NamedTemporaryFile(mode, **kwargs) as tmp:
            if six.PY2:
                data = data.encode('utf-8')

            log.debug("safe writing {} chrs into {}".format(len(data), fn))
            tmp.write(data)
            tmpn = tmp.name
        if os.path.exists(tmpn) and os.stat(tmpn).st_size > 0:
            os.rename(tmpn, fn)
            # made these file readable by all
            os.chmod(fn, 0o644)
            return True
    except Exception as ex:
        log.debug(traceback.format_exc())
        log.error(ex)
    finally:
        if tmpn is not None and os.path.exists(tmpn):
            try:
                os.unlink(tmpn)
            except Exception as ex:
                log.warning(ex)
    return False


def parse_date(s):
    if s is None:
        return datetime.now()
    return datetime(*parsedate(s)[:6])


def root(t):
    if hasattr(t, 'getroot') and hasattr(t.getroot, '__call__'):
        return t.getroot()
    else:
        return t


def with_tree(elt, cb):
    cb(elt)
    if isinstance(elt.tag, six.string_types):
        for child in list(elt):
            with_tree(child, cb)


def duration2timedelta(period: str) -> Optional[timedelta]:
    regex = re.compile(
        r'(?P<sign>[-+]?)'
        r'P(?:(?P<years>\d+)[Yy])?(?:(?P<months>\d+)[Mm])?(?:(?P<days>\d+)[Dd])?'
        r'(?:T(?:(?P<hours>\d+)[Hh])?(?:(?P<minutes>\d+)[Mm])?(?:(?P<seconds>\d+)[Ss])?)?'
    )

    # Fetch the match groups with default value of 0 (not None)
    m = regex.match(period)
    if not m:
        return None

    # workaround error: Argument 1 to "groupdict" of "Match" has incompatible type "int"; expected "str"
    duration = m.groupdict(0)  # type: ignore

    # Create the timedelta object from extracted groups
    delta = timedelta(
        days=int(duration['days']) + (int(duration['months']) * 30) + (int(duration['years']) * 365),
        hours=int(duration['hours']),
        minutes=int(duration['minutes']),
        seconds=int(duration['seconds']),
    )

    if duration['sign'] == "-":
        delta *= -1

    return delta


def _lang(elt: Element, default_lang: Optional[str]) -> Optional[str]:
    return elt.get("{http://www.w3.org/XML/1998/namespace}lang", default_lang)


def lang_dict(elts: Sequence[Element], getter=lambda e: e, default_lang: Optional[str] = None) -> Dict[str, Callable]:
    if default_lang is None:
        default_lang = config.langs[0]

    r = dict()
    for e in elts:
        _l = _lang(e, default_lang)
        if not _l:
            raise ValueError('Could not get lang from element, and no default provided')
        r[_l] = getter(e)
    return r


def find_lang(elts: Sequence[Element], lang: str, default_lang: str) -> Element:
    return next((e for e in elts if _lang(e, default_lang) == lang), elts[0])


def filter_lang(elts: Any, langs: Optional[Sequence[str]] = None) -> List[Element]:
    if langs is None or type(langs) is not list:
        langs = config.langs

    # log.debug("langs: {}".format(langs))

    if elts is None:
        return []

    elts = list(elts)

    if len(elts) == 0:
        return []

    if not langs:
        raise RuntimeError('Configuration is missing langs')

    dflt = langs[0]
    lst = [find_lang(elts, l, dflt) for l in langs]
    if len(lst) > 0:
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
    except etree.XSLTApplyError as ex:
        for entry in transform.error_log:
            log.error('\tmessage from line %s, col %s: %s' % (entry.line, entry.column, entry.message))
            log.error('\tdomain: %s (%d)' % (entry.domain_name, entry.domain))
            log.error('\ttype: %s (%d)' % (entry.type_name, entry.type))
            log.error('\tlevel: %s (%d)' % (entry.level_name, entry.level))
            log.error('\tfilename: %s' % entry.filename)
        raise ex


# TODO: Unused function
def valid_until_ts(elt, default_ts: int) -> int:
    ts = default_ts
    valid_until = elt.get("validUntil", None)
    if valid_until is not None:
        try:
            dt = datetime.fromtimestamp(valid_until)
            ts = totimestamp(dt)
        except Exception:
            pass

    cache_duration = elt.get("cacheDuration", None)
    if cache_duration is not None:
        _duration = duration2timedelta(cache_duration)
        if _duration is not None:
            dt = utc_now() + _duration
            ts = totimestamp(dt)

    return ts


def total_seconds(dt: timedelta) -> float:
    if hasattr(dt, "total_seconds"):
        return dt.total_seconds()
    # TODO: Remove? I guess this is for Python < 3
    return (dt.microseconds + (dt.seconds + dt.days * 24 * 3600) * 10 ** 6) / 10 ** 6


def etag(s):
    return hex_digest(s, hn="sha256")


def hash_id(entity: Element, hn: str = 'sha1', prefix: bool = True) -> str:
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

    if not isinstance(data, six.binary_type):
        data = data.encode("utf-8")

    m = getattr(hashlib, hn)()
    m.update(data)
    return m.hexdigest()


def parse_xml(io: BinaryIO, base_url: Optional[str] = None) -> ElementTree:
    huge_xml = config.huge_xml
    return etree.parse(
        io, base_url=base_url, parser=etree.XMLParser(resolve_entities=False, collect_ids=False, huge_tree=huge_xml)
    )


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
            # log.debug("ddist %s %s -> %d" % (a, b, d))
            dd += d
            n += 1
    return int(dd / n)


def sync_nsmap(nsmap, elt):
    fix = []
    for ns in elt.nsmap:
        if ns not in nsmap:
            nsmap[ns] = elt.nsmap[ns]
        elif nsmap[ns] != elt.nsmap[ns]:
            fix.append(ns)
        else:
            pass


def rreplace(s, old, new, occurrence):
    li = s.rsplit(old, occurrence)
    return new.join(li)


def load_callable(name):
    from importlib import import_module

    p, m = name.rsplit(':', 1)
    mod = import_module(p)
    return getattr(mod, m)


# semantics copied from https://github.com/lordal/md-summary/blob/master/md-summary
# many thanks to Anders Lordahl & Scotty Logan for the idea
def guess_entity_software(e):
    for elt in chain(
        e.findall(".//{%s}SingleSignOnService" % NS['md']), e.findall(".//{%s}AssertionConsumerService" % NS['md'])
    ):
        location = elt.get('Location')
        if location:
            if (
                'Shibboleth.sso' in location
                or 'profile/SAML2/POST/SSO' in location
                or 'profile/SAML2/Redirect/SSO' in location
                or 'profile/Shibboleth/SSO' in location
            ):
                return 'Shibboleth'
            if location.endswith('saml2/idp/SSOService.php') or 'saml/sp/saml2-acs.php' in location:
                return 'SimpleSAMLphp'
            if location.endswith('user/authenticate'):
                return 'KalturaSSP'
            if location.endswith('adfs/ls') or location.endswith('adfs/ls/'):
                return 'ADFS'
            if '/oala/' in location or 'login.openathens.net' in location:
                return 'OpenAthens'
            if (
                '/idp/SSO.saml2' in location
                or '/sp/ACS.saml2' in location
                or 'sso.connect.pingidentity.com' in location
            ):
                return 'PingFederate'
            if 'idp/saml2/sso' in location:
                return 'Authentic2'
            if 'nidp/saml2/sso' in location:
                return 'Novell Access Manager'
            if 'affwebservices/public/saml2sso' in location:
                return 'CASiteMinder'
            if 'FIM/sps' in location:
                return 'IBMTivoliFIM'
            if (
                'sso/post' in location
                or 'sso/redirect' in location
                or 'saml2/sp/acs' in location
                or 'saml2/ls' in location
                or 'saml2/acs' in location
                or 'acs/redirect' in location
                or 'acs/post' in location
                or 'saml2/sp/ls/' in location
            ):
                return 'PySAML'
            if 'engine.surfconext.nl' in location:
                return 'SURFConext'
            if 'opensso' in location:
                return 'OpenSSO'
            if 'my.salesforce.com' in location:
                return 'Salesforce'

    entity_id = e.get('entityID')
    if '/shibboleth' in entity_id:
        return 'Shibboleth'
    if entity_id.endswith('/metadata.php'):
        return 'SimpleSAMLphp'
    if '/openathens' in entity_id:
        return 'OpenAthens'

    return 'other'


def is_text(x: Any) -> bool:
    return isinstance(x, six.string_types) or isinstance(x, six.text_type)


def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i : i + n]


class DirAdapter(BaseAdapter):
    """
    An implementation of the requests Adapter interface that returns a the files in a directory. Used to simplify
    the code paths in pyFF and allows directories to be treated as yet another representation of a collection of metadata.
    """

    def send(self, request, **kwargs):
        resp = Response()
        (_, _, _dir) = request.url.partition('://')
        if _dir is None or len(_dir) == 0:
            raise ValueError("not a directory url: {}".format(request.url))
        resp.raw = six.BytesIO(six.b(_dir))
        resp.status_code = 200
        resp.reason = "OK"
        resp.headers = {}
        resp.url = request.url

        return resp

    def close(self):
        pass


def url_get(url: str, verify_tls: Optional[bool] = False) -> Response:
    """
    Download an URL using a cache and return the response object
    :param url:
    :return:
    """

    s: Union[Session, CachedSession]
    if 'file://' in url:
        s = requests.session()
        s.mount('file://', FileAdapter())
    elif 'dir://' in url:
        s = requests.session()
        s.mount('dir://', DirAdapter())
    else:
        retry = Retry(total=3, backoff_factor=0.5)
        adapter = HTTPAdapter(max_retries=retry)
        s = CachedSession(
            cache_name="pyff_cache",
            backend=config.request_cache_backend,
            expire_after=config.request_cache_time,
            old_data_on_error=True,
        )
        s.mount('http://', adapter)
        s.mount('https://', adapter)

    headers = {'User-Agent': "pyFF/{}".format(__version__), 'Accept': '*/*'}
    _etag = None
    if _etag is not None:
        headers['If-None-Match'] = _etag
    try:
        r = s.get(url, headers=headers, verify=verify_tls, timeout=config.request_timeout)
    except IOError as ex:
        s = requests.Session()
        r = s.get(url, headers=headers, verify=verify_tls, timeout=config.request_timeout)

    if six.PY2:
        r.encoding = "utf-8"

    log.debug("url_get({}) returns {} chrs encoded as {}".format(url, len(r.content), r.encoding))

    if config.request_override_encoding is not None:
        r.encoding = config.request_override_encoding

    return r


def safe_b64e(data: Union[str, bytes]) -> str:
    if not isinstance(data, bytes):
        data = data.encode("utf-8")
    return base64.b64encode(data).decode('ascii')


def safe_b64d(s: str) -> bytes:
    return base64.b64decode(s)


# data:&lt;class 'type'&gt;;base64,
# data:<class 'type'>;base64,


def img_to_data(data: bytes, content_type: str) -> Optional[str]:
    """Convert a file (specified by a path) into a data URI."""
    mime_type, options = cgi.parse_header(content_type)
    data64 = None
    if len(data) > config.icon_maxsize:
        return None

    try:
        from PIL import Image
    except ImportError:
        Image = None

    if Image is not None:
        try:
            im = Image.open(io.BytesIO(data))
            if im.format not in ('PNG', 'SVG'):
                out = io.BytesIO()
                im.save(out, format="PNG")
                data64 = safe_b64e(out.getvalue())
                assert data64
                mime_type = "image/png"
        except BaseException as ex:
            log.warning(f'Exception when making Image: {ex}')
            log.debug(traceback.format_exc())

    if data64 is None or len(data64) == 0:
        data64 = safe_b64e(data)
    return 'data:{};base64,{}'.format(mime_type, data64)


def short_id(data):
    hasher = hashlib.sha1(data)
    return base64.urlsafe_b64encode(hasher.digest()[0:10]).rstrip('=')


def unicode_stream(data: str) -> io.BytesIO:
    return six.BytesIO(data.encode('UTF-8'))


def b2u(data: Union[str, bytes, Tuple, List, Set]) -> Union[str, bytes, Tuple, List, Set]:
    if is_text(data):
        return data
    elif isinstance(data, six.binary_type):
        return data.decode("utf-8")
    elif isinstance(data, tuple) or isinstance(data, list):
        return [b2u(item) for item in data]
    elif isinstance(data, set):
        return set([b2u(item) for item in data])
    return data


def json_serializer(o):
    if isinstance(o, datetime):
        return o.__str__()
    if isinstance(o, CaseInsensitiveDict):
        return dict(o.items())
    if isinstance(o, BaseException):
        return str(o)
    if hasattr(o, 'to_json') and hasattr(o.to_json, '__call__'):
        return o.to_json()
    if isinstance(o, threading.Thread):
        return o.name

    raise ValueError("Object {} of type {} is not JSON-serializable via this function".format(repr(o), type(o)))


class Lambda(object):
    def __init__(self, cb: Callable, *args, **kwargs):
        self._cb = cb
        self._args = [a for a in args]
        self._kwargs = kwargs or {}

    def __call__(self, *args, **kwargs):
        args = [a for a in args]
        args.extend(self._args)
        kwargs.update(self._kwargs)
        return self._cb(*args, **kwargs)


@contextlib.contextmanager
def non_blocking_lock(lock=threading.Lock(), exception_class=ResourceException, args=("Resource is busy",)):
    if not lock.acquire(blocking=False):
        raise exception_class(*args)
    try:
        yield lock
    finally:
        lock.release()


def make_default_scheduler():
    if config.scheduler_job_store == 'redis':
        jobstore = RedisJobStore(host=config.redis_host, port=config.redis_port)
    elif config.scheduler_job_store == 'memory':
        jobstore = MemoryJobStore()
    else:
        raise ValueError("unknown or unsupported job store type '{}'".format(config.scheduler_job_store))
    return BackgroundScheduler(
        executors={'default': ThreadPoolExecutor(config.worker_pool_size)},
        jobstores={'default': jobstore},
        job_defaults={'misfire_grace_time': config.update_frequency},
    )


class MappingStack(Mapping):
    def __init__(self, *args):
        self._m = list(args)

    def __contains__(self, item):
        return any([item in d for d in self._m])

    def __getitem__(self, item):
        for d in self._m:
            log.debug("----")
            log.debug(repr(d))
            log.debug(repr(item))
            log.debug("++++")
            if item in d:
                return d[item]
        return None

    def __iter__(self):
        for d in self._m:
            for item in d:
                yield item

    def __len__(self) -> int:
        return sum([len(d) for d in self._m])


class LRUProxyDict(MutableMapping):
    def __init__(self, proxy, *args, **kwargs):
        self._proxy = proxy
        self._cache = LRUCache(**kwargs)

    def __contains__(self, item):
        return item in self._cache or item in self._proxy

    def __getitem__(self, item):
        if item is None:
            raise ValueError("None key")
        v = self._cache.get(item, None)
        if v is not None:
            return v
        v = self._proxy.get(item, None)
        if v is not None:
            self._cache[item] = v
        return v

    def __setitem__(self, key, value):
        self._proxy[key] = value
        self._cache[key] = value

    def __delitem__(self, key):
        self._proxy.pop(key, None)
        self._cache.pop(key, None)

    def __iter__(self):
        return self._proxy.__iter__()

    def __len__(self):
        return len(self._proxy)


def find_matching_files(d, extensions):
    for top, dirs, files in os.walk(d):
        for dn in dirs:
            if dn.startswith("."):
                dirs.remove(dn)

        for nm in files:
            (_, _, ext) = nm.rpartition('.')
            if ext in extensions:
                fn = os.path.join(top, nm)
                yield fn


def is_past_ttl(last_seen, ttl=config.cache_ttl):
    fuzz = ttl
    now = int(time.time())
    if config.randomize_cache_ttl:
        fuzz = random.randrange(1, ttl)
    return now > int(last_seen) + fuzz


class Watchable(object):
    class Watcher(object):
        def __init__(self, cb, args, kwargs):
            self.cb = cb
            self.args = args
            self.kwargs = kwargs

        def __call__(self, *args, **kwargs):
            kwargs_copy = copy(kwargs)
            args_copy = copy(list(args))
            kwargs_copy.update(self.kwargs)
            args_copy.extend(self.args)
            return self.cb(*args_copy, **kwargs_copy)

        def __cmp__(self, other):
            return other.cb == self.cb

    def __init__(self):
        self.watchers = []

    def add_watcher(self, cb, *args, **kwargs):
        self.watchers.append(Watchable.Watcher(cb, args, kwargs))

    def remove_watcher(self, cb, *args, **kwargs):
        self.watchers.remove(Watchable.Watcher(cb))

    def notify(self, *args, **kwargs):
        kwargs['watched'] = self
        for cb in self.watchers:
            try:
                cb(*args, **kwargs)
            except BaseException as ex:
                log.debug(traceback.format_exc())
                log.warning(f'Callback {cb} failed: {ex}')


def utc_now() -> datetime:
    """ Return current time with tz=UTC """
    return datetime.now(tz=timezone.utc)
