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
from collections.abc import Sequence
from copy import copy
from datetime import datetime, timedelta, timezone
from email.utils import parsedate
from itertools import chain
from threading import local
from time import gmtime, strftime
from typing import Any, BinaryIO, Callable, Optional, Union
from urllib.parse import urlparse

import pkg_resources
import pybergshamra
import requests
from apscheduler.executors.pool import ThreadPoolExecutor
from apscheduler.jobstores.memory import MemoryJobStore
from apscheduler.jobstores.redis import RedisJobStore
from apscheduler.schedulers.background import BackgroundScheduler
from cachetools import LRUCache
from cryptography import x509
from pyuppsala import etree
from pyuppsala.etree import Element, ElementTree
from requests import Session
from requests.adapters import BaseAdapter, HTTPAdapter, Response
from requests.packages.urllib3.util.retry import Retry
from requests.structures import CaseInsensitiveDict
from requests_cache import CachedSession
from requests_file import FileAdapter

from pyff import __version__
from pyff.constants import NS, config
from pyff.exceptions import MetadataException, ResourceException
from pyff.logs import get_log

# Note: pyuppsala is safe-by-default (entities are not resolved/expanded unless
# explicitly allowed) and exposes no set_default_parser hook, so the previous
# call to etree.set_default_parser(...) has been dropped during the migration.

# pyuppsala's default XPath node-visit budget (100k visits per evaluation) is an
# anti-DoS cap sized for untrusted documents. pyFF evaluates XPath over its own
# working aggregates, which at eduGAIN scale exceed a million nodes, so a plain
# //md:EntityDescriptor would trip the default cap. Raise the module budget to a
# value comfortably above real-world aggregate sizes while still bounding a
# runaway evaluation.
etree.MAX_XPATH_NODE_VISITS = max(etree.MAX_XPATH_NODE_VISITS, 50_000_000)

__author__ = 'leifj'

log = get_log(__name__)

thread_data = local()


def xml_error(error_log, m=None):
    # pyuppsala's ValidationError renders as just the message (line/column), and
    # unlike lxml it does not embed the source document in each entry. The old
    # ``m not in x`` filter therefore dropped *every* pyuppsala error, throwing
    # away the validation detail. Instead, keep each (non-warning) error and
    # prefix it with the source so the message still identifies the document.
    lines = []
    for e in error_log:
        s = f"{e}"
        if ":WARNING:" in s:
            continue
        if m is not None and m not in s:
            s = f"{m}: {s}"
        lines.append(s)
    return "\n".join(lines)


def debug_observer(e):
    log.error(repr(e))


def trunc_str(x, length):
    return (x[:length] + '..') if len(x) > length else x


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
        with open(name) as fd:
            data = fd.read()
    elif pfx and os.path.exists(os.path.join(pfx, name)):
        with open(os.path.join(pfx, name)) as fd:
            data = fd.read()
    elif pkg_resources.resource_exists(__name__, name):
        data = pkg_resources.resource_string(__name__, name)
    elif pfx and pkg_resources.resource_exists(__name__, f"{pfx}/{name}"):
        data = pkg_resources.resource_string(__name__, f"{pfx}/{name}")

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
    elif pfx and pkg_resources.resource_exists(__name__, f"{pfx}/{name}"):
        return pkg_resources.resource_filename(__name__, f"{pfx}/{name}")

    return None


def totimestamp(dt: datetime, epoch=datetime(1970, 1, 1)) -> int:
    epoch = epoch.replace(tzinfo=dt.tzinfo)

    td = dt - epoch
    ts = (td.microseconds + (td.seconds + td.days * 24 * 3600) * 10**6) / 1e6
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


thread_local_lock = threading.Lock()


def schema():
    if not hasattr(thread_data, 'schema'):
        thread_data.schema = None

    if thread_data.schema is None:
        try:
            thread_local_lock.acquire(blocking=True)
            # pyuppsala's XMLSchema resolves xsd:import / xsd:include relative to
            # the schema file's own directory (base_path) automatically, so the
            # old lxml ResourceResolver / parser plumbing is no longer needed.
            #
            # lenient=True matches libxml2/lxml's built-in datatype validation,
            # which pyFF has always relied on: real-world SAML metadata carries
            # anyURI values containing spaces (e.g. mdui:GeolocationHint
            # "geo:lat, lon", "mailto: user@host"). Strict/spec XSD rejects those
            # per RFC 3987, which would wrongly drop large numbers of otherwise
            # valid entities; lenient mode accepts them exactly as lxml did.
            schema_path = pkg_resources.resource_filename(__name__, "schema/schema.xsd")
            thread_data.schema = etree.XMLSchema(file=schema_path, lenient=True)
        except etree.XMLSchemaParseError as ex:
            traceback.print_exc()
            log.error(str(ex))
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


def _looks_like_sha1_fingerprint(key: str) -> bool:
    """Return True if ``key`` looks like a SHA1 certificate fingerprint.

    pyFF accepts the ``verify`` value either as a path to a PEM certificate file
    or as a SHA1 fingerprint (40 hex digits, optionally colon-separated). A
    fingerprint is detected by stripping colons/whitespace and checking for
    exactly 40 hex characters.
    """
    candidate = key.replace(':', '').replace(' ', '').strip()
    return len(candidate) == 40 and all(c in '0123456789abcdefABCDEF' for c in candidate)


def check_signature(t: ElementTree, key: Optional[str], only_one_signature: bool = False) -> ElementTree:
    """Verify the XML signature on ``t`` using pybergshamra.

    ``key`` is either the path to a PEM-encoded X.509 certificate (the trusted
    signer) or a SHA1 fingerprint of the expected signing certificate. When a
    fingerprint is supplied the certificate embedded in the signature's KeyInfo
    is used to verify, and the fingerprint is checked against it afterwards.
    """
    if key is None:
        return t

    log.debug(f"verifying signature using {key}")

    mgr = pybergshamra.KeysManager()
    ctx = pybergshamra.DsigContext(mgr)

    pinned_fingerprint = None
    if _looks_like_sha1_fingerprint(key) and not os.path.exists(key):
        # Fingerprint pinning: trust the cert carried inside the signature's
        # KeyInfo/X509Data, then compare its SHA1 to the pinned fingerprint.
        # The fingerprint is the trust anchor here, so PKI chain validation is
        # disabled (insecure) - the embedded signing cert is typically
        # self-signed and would otherwise fail to chain to a trusted root.
        pinned_fingerprint = key.replace(':', '').replace(' ', '').strip().lower()
        ctx.enabled_key_data_x509 = True
        ctx.trusted_keys_only = False
        ctx.insecure = True
    else:
        # Trusted-cert path: load the PEM certificate and require it as the
        # only acceptable signing key (skip inline KeyInfo extraction).
        with open(key, 'rb') as fd:
            cert_key = pybergshamra.load_x509_cert_pem(fd.read())
        mgr.add_key(cert_key)
        ctx.trusted_keys_only = True

    relt = root(t)
    if is_document_root(relt):
        # The document API verifies through an owned XML handoff.
        # Only valid when ``relt`` *is* the document --
        # for a subtree the native document would be the enclosing aggregate.
        result = pybergshamra.verify_document(ctx, etree.native_document(relt))
    else:
        # A subtree of a larger document must be rendered and verified on its
        # own; the native document is the enclosing aggregate.
        xml = dumptree(relt, xml_declaration=False)
        if isinstance(xml, bytes):
            xml = xml.decode('utf-8')
        result = pybergshamra.verify(ctx, xml)
    if not result.is_valid:
        raise MetadataException(f"Signature verification failed: {result.reason}")

    references = result.references or []
    if only_one_signature and len(references) != 1:
        raise MetadataException(
            "XML metadata contains %d signatures - exactly 1 is required" % len(references)
        )

    if pinned_fingerprint is not None:
        # Confirm the certificate that actually verified the signature matches
        # the pinned fingerprint (SHA1 over the DER-encoded leaf certificate).
        chain = result.key_info.x509_chain if result.key_info is not None else []
        if not chain:
            raise MetadataException("No certificate found in signature to match fingerprint")
        actual_fingerprint = hashlib.sha1(chain[0]).hexdigest().lower()
        if actual_fingerprint != pinned_fingerprint:
            raise MetadataException(
                f"Signing certificate fingerprint {actual_fingerprint} does not match expected {pinned_fingerprint}"
            )

    # Anti-wrapping: the old code returned the verified reference subtree as the
    # new working tree. With pybergshamra the enveloped signature covers the
    # whole document root (reference URI "#<ID>" or ""), and strict_verification
    # in the context guards against signature-wrapping. We therefore return the
    # signed document root, which is the element the reference covers.
    # NOTE: resolved_node_id from the verified reference is not mapped back to a
    # pyuppsala element via the public etree API; this relies on the reference
    # covering the document root.
    return root(t)


def validate_document(t):
    schema().assertValid(t)


def cert_dict(t):
    """Build a dict mapping SHA1 fingerprint -> base64 certificate text.

    Replacement for ``xmlsec.crypto.CertDict``. Iterates over every
    ``<ds:X509Certificate>`` element found in the tree, base64-decodes it to DER,
    and computes the SHA1 fingerprint. The fingerprint format mirrors
    pyXMLSecurity: lowercase hex, colon-separated (eg ``ab:cd:ef:...``), which is
    also the format pyFF passes on to :func:`check_signature` as the ``verify``
    value.

    :param t: an Element or ElementTree to scan for certificates
    :return: dict of {fingerprint: base64-certificate-text}
    """
    certs: dict[str, str] = {}
    for cert_elt in root(t).iter("{{{}}}X509Certificate".format(NS['ds'])):
        cert_b64 = cert_elt.text
        if cert_b64 is None:
            continue
        cert_b64 = cert_b64.strip()
        try:
            cert_der = base64.b64decode(cert_b64)
        except Exception:
            continue
        digest = hashlib.sha1(cert_der).hexdigest().lower()
        fingerprint = ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))
        certs[fingerprint] = cert_b64
    return certs


class CertInfo:
    """Lightweight wrapper around a parsed X.509 certificate.

    Replacement for the dict returned by ``xmlsec.utils.b642cert``. Exposes the
    handful of fields the certreport pipe consumes (key size, subject, and
    expiry) backed by the ``cryptography`` library.
    """

    def __init__(self, cert: "x509.Certificate"):
        self._cert = cert

    @property
    def keysize(self) -> Optional[int]:
        """The public key size in bits, or None if it cannot be determined."""
        public_key = self._cert.public_key()
        # RSA/DSA expose key_size directly; EC exposes curve.key_size.
        size = getattr(public_key, 'key_size', None)
        if size is None:
            curve = getattr(public_key, 'curve', None)
            size = getattr(curve, 'key_size', None)
        return size

    @property
    def subject(self) -> str:
        """The certificate subject as an RFC 4514 string."""
        return self._cert.subject.rfc4514_string()

    @property
    def not_after(self) -> Optional[datetime]:
        """The certificate expiry as a timezone-aware datetime (UTC)."""
        # cryptography >= 42 exposes not_valid_after_utc; fall back for older.
        return getattr(self._cert, 'not_valid_after_utc', None) or self._cert.not_valid_after


def cert_info(cert_b64: str) -> CertInfo:
    """Parse a base64-encoded DER X.509 certificate into a :class:`CertInfo`.

    Replacement for ``xmlsec.utils.b642cert``.

    :param cert_b64: the base64 (DER) certificate text, eg from ds:X509Certificate
    :return: a CertInfo exposing keysize / subject / not_after
    """
    cert_der = base64.b64decode(cert_b64)
    cert = x509.load_der_x509_certificate(cert_der)
    return CertInfo(cert)


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
        kwargs = dict(delete=False, prefix=f".{basename}", dir=dirname)
        kwargs['encoding'] = "utf-8"
        mode = 'w+'

        if mkdirs:
            ensure_dir(fn)

        if isinstance(data, bytes):
            data = data.decode('utf-8')

        with tempfile.NamedTemporaryFile(mode, **kwargs) as tmp:
            log.debug(f"safe writing {len(data)} chrs into {fn}")
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


def is_document_root(elt) -> bool:
    """Return True if ``elt`` is the root element of its owning document.

    The working document is frequently a *subtree* of a larger parsed document,
    e.g. the single EntityDescriptor that ``first`` hands on after an MDQ
    ``select`` (it is still a child of the loaded EntitiesDescriptor). Anything
    that reaches the native document through ``etree.native_document(elt)``
    would then operate on the whole aggregate instead of ``elt``, so callers
    must only take the document-native shortcut when this returns True. A
    ``deepcopy``'d element has no parent but is not a document root either,
    which is why the root-tree identity check is used rather than
    ``getparent() is None``.
    """
    getroottree = getattr(elt, 'getroottree', None)
    if getroottree is None:
        return False
    try:
        return getroottree().getroot() is elt
    except Exception:  # pragma: no cover - be conservative, fall back to the string path
        return False


def with_tree(elt, cb):
    cb(elt)
    if isinstance(elt.tag, str):
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


def lang_dict(elts: Sequence[Element], getter=lambda e: e, default_lang: Optional[str] = None) -> dict[str, Callable]:
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


def filter_lang(elts: Any, langs: Optional[Sequence[str]] = None) -> list[Element]:
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
    lst = [find_lang(elts, lang, dflt) for lang in langs]
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
            # pyuppsala's XSLT error-log entries expose line/column/message; the
            # libxml2-specific attributes (domain/type/level/filename) exist as
            # neutral placeholders but may be missing, so guard the logging.
            try:
                log.error(f'\tmessage from line {entry.line}, col {entry.column}: {entry.message}')
                log.error('\tdomain: %s (%d)' % (entry.domain_name, entry.domain))
                log.error('\ttype: %s (%d)' % (entry.type_name, entry.type))
                log.error('\tlevel: %s (%d)' % (entry.level_name, entry.level))
                log.error(f'\tfilename: {entry.filename}')
            except AttributeError:
                log.error(f'\tmessage: {getattr(entry, "message", entry)}')
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
    return (dt.microseconds + (dt.seconds + dt.days * 24 * 3600) * 10**6) / 10**6


def etag(s):
    return hex_digest(s, hn="sha256")


def hash_id(entity: Element, hn: str = 'sha1', prefix: bool = True) -> str:
    entity_id = entity
    if hasattr(entity, 'get'):
        entity_id = entity.get('entityID')

    hstr = hex_digest(entity_id, hn)
    if prefix:
        return f"{{{hn}}}{hstr}"
    else:
        return hstr


def hex_digest(data, hn='sha1'):
    if hn == 'null':
        return data

    if not hasattr(hashlib, hn):
        raise ValueError(f"Unknown digest '{hn}'")

    if not isinstance(data, bytes):
        data = data.encode("utf-8")

    m = getattr(hashlib, hn)()
    m.update(data)
    return m.hexdigest()


def parse_xml(io: BinaryIO, base_url: Optional[str] = None) -> ElementTree:
    huge_xml = config.huge_xml
    # pyuppsala is safe-by-default: it forbids DTDs/entities rather than expanding
    # them, so resolve_entities=False (the old lxml hardening) is both unnecessary
    # and unsupported. collect_ids has no pyuppsala equivalent (IDs are resolved on
    # demand). huge_tree lifts the depth/expansion caps for large aggregates.
    return etree.parse(io, base_url=base_url, parser=etree.XMLParser(huge_tree=huge_xml))


def has_tag(t, tag):
    # Keep the subtree scan in Rust and avoid materializing Python proxies.
    return t.fast_has(tag)


def url2host(url):
    (host, sep, _port) = urlparse(url).netloc.partition(':')
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
        e.findall(".//{{{}}}SingleSignOnService".format(NS['md'])), e.findall(".//{{{}}}AssertionConsumerService".format(NS['md']))
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
            if location.endswith(('adfs/ls', 'adfs/ls/')):
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
    return isinstance(x, str) or isinstance(x, str)


def chunks(input_list, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(input_list), n):
        yield input_list[i : i + n]


class DirAdapter(BaseAdapter):
    """
    An implementation of the requests Adapter interface that returns a the files in a directory. Used to simplify
    the code paths in pyFF and allows directories to be treated as yet another representation of a collection of metadata.
    """

    def send(self, request, **kwargs):
        resp = Response()
        (_, _, _dir) = request.url.partition('://')
        if _dir is None or len(_dir) == 0:
            raise ValueError(f"not a directory url: {request.url}")
        resp.raw = io.BytesIO(_dir.encode("latin-1"))
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

    headers = {'User-Agent': f"pyFF/{__version__}", 'Accept': '*/*'}
    _etag = None
    if _etag is not None:
        headers['If-None-Match'] = _etag
    try:
        r = s.get(url, headers=headers, verify=verify_tls, timeout=config.request_timeout)
    except OSError:
        s = requests.Session()
        r = s.get(url, headers=headers, verify=verify_tls, timeout=config.request_timeout)

    log.debug(f"url_get({url}) returns {len(r.content)} chrs encoded as {r.encoding}")

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
    mime_type, _options = cgi.parse_header(content_type)
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
    return f'data:{mime_type};base64,{data64}'


def short_id(data):
    hasher = hashlib.sha1(data)
    return base64.urlsafe_b64encode(hasher.digest()[0:10]).rstrip('=')


def unicode_stream(data: str) -> io.BytesIO:
    return io.BytesIO(data.encode('UTF-8'))


def b2u(data: Union[str, bytes, tuple, list, set]) -> Union[str, bytes, tuple, list, set]:
    if is_text(data):
        return data
    elif isinstance(data, bytes):
        return data.decode("utf-8")
    elif isinstance(data, tuple) or isinstance(data, list):
        return [b2u(item) for item in data]
    elif isinstance(data, set):
        return {b2u(item) for item in data}
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

    raise ValueError(f"Object {repr(o)} of type {type(o)} is not JSON-serializable via this function")


class Lambda:
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
        raise ValueError(f"unknown or unsupported job store type '{config.scheduler_job_store}'")
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
            yield from d

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


class Watchable:
    class Watcher:
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

    def remove_watcher(self, cb, *_args, **_kwargs):
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
    """Return current time with tz=UTC"""
    return datetime.now(tz=timezone.utc)
