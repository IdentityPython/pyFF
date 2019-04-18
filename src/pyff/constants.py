"""
Useful constants for pyFF. Mostly XML namespace declarations.
"""

import pyconfig
import logging
import getopt
import sys
import os
from . import __version__ as pyff_version


__author__ = 'leifj'

NF_URI = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"

NS = dict(md="urn:oasis:names:tc:SAML:2.0:metadata",
          ds='http://www.w3.org/2000/09/xmldsig#',
          mdui="urn:oasis:names:tc:SAML:metadata:ui",
          mdattr="urn:oasis:names:tc:SAML:metadata:attribute",
          mdrpi="urn:oasis:names:tc:SAML:metadata:rpi",
          shibmd="urn:mace:shibboleth:metadata:1.0",
          xrd='http://docs.oasis-open.org/ns/xri/xrd-1.0',
          pyff='http://pyff.io/NS',
          xml='http://www.w3.org/XML/1998/namespace',
          saml="urn:oasis:names:tc:SAML:2.0:assertion",
          xs="http://www.w3.org/2001/XMLSchema",
          xsi="http://www.w3.org/2001/XMLSchema-instance",
          ser="http://eidas.europa.eu/metadata/servicelist",
          eidas="http://eidas.europa.eu/saml-extensions")

ATTRS = {'collection': 'http://pyff.io/collection',
         'entity-category': 'http://macedir.org/entity-category',
         'role': 'http://pyff.io/role',
         'software': 'http://pyff.io/software',
         'domain': 'http://pyff.io/domain'}

ATTRS_INV = {v: k for k, v in list(ATTRS.items())}

PLACEHOLDER_ICON = 'data:image/gif;base64,R0lGODlhAQABAIABAP///wAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw=='

DIGESTS = ['sha1', 'md5', 'null']


class Config(object):
    google_api_key = pyconfig.setting("pyff.google_api_key", "google+api+key+not+set")
    loglevel = pyconfig.setting("pyff.loglevel", logging.INFO)
    access_log = pyconfig.setting("pyff.access_log", None)
    error_log = pyconfig.setting("pyff.error_log", None)
    logfile = pyconfig.setting("pyff.log", None)
    port = pyconfig.setting("pyff.port", 8080)
    bind_address = pyconfig.setting("pyff.bind_address", "127.0.0.1")
    pid_file = pyconfig.setting("pyff.pid_file", "/var/run/pyff.pid")
    caching_enabled = pyconfig.setting("pyff.caching.enabled", True)
    caching_delay = pyconfig.setting("pyff.caching.delay", 300)
    daemonize = pyconfig.setting("pyff.daemonize", True)
    autoreload = pyconfig.setting("pyff.autoreload", False)
    aliases = pyconfig.setting("pyff.aliases", ATTRS)
    base_dir = pyconfig.setting("pyff.base_dir", None)
    proxy = pyconfig.setting("pyff.proxy", False)
    allow_shutdown = pyconfig.setting("pyff.allow_shutdown", False)
    modules = pyconfig.setting("pyff.modules", [])
    cache_ttl = pyconfig.setting("pyff.cache.ttl", 300)
    default_cache_duration = pyconfig.setting("pyff.default.cache_duration", "PT1H")
    respect_cache_duration = pyconfig.setting("pyff.respect_cache_duration", True)
    info_buffer_size = pyconfig.setting("pyff.info_buffer_size", 10)
    worker_pool_size = pyconfig.setting("pyff.worker_pool_size", 10)
    store_class = pyconfig.setting("pyff.store.class", "pyff.store:MemoryStore")
    update_frequency = pyconfig.setting("pyff.update_frequency", 600)
    cache_frequency = pyconfig.setting("pyff.cache_frequency", 200)
    request_timeout = pyconfig.setting("pyff.request_timeout", 10)
    request_cache_time = pyconfig.setting("pyff.request_cache_time", 300)
    request_cache_backend = pyconfig.setting("pyff.request_cache_backend", None)
    request_override_encoding = pyconfig.setting("pyff.request_override_encoding",
                                                 "utf8")  # set to non to enable chardet guessing
    devel_memory_profile = pyconfig.setting("pyff.devel_memory_profile", False)
    devel_write_xml_to_file = pyconfig.setting("pyff.devel_write_xml_to_file", False)
    ds_template = pyconfig.setting("pyff.ds_template", "ds.html")
    redis_host = pyconfig.setting("pyff.redis_host", "localhost")
    redis_port = pyconfig.setting("pyff.redis_port", 6379)
    rq_queue = pyconfig.setting("pyff.rq_queue", "pyff")
    cache_chunks = pyconfig.setting("pyff.cache_chunks", 10)
    pipeline = pyconfig.setting("pyff.pipeline", os.environ.get("PYFF_PIPELINE"))


config = Config()


def parse_options(program, docs, short_args, long_args):
    try:
        opts, args = getopt.getopt(sys.argv[1:], short_args, long_args)
    except getopt.error as msg:
        print(msg)
        print(docs)
        sys.exit(2)

    if config.loglevel is None:
        config.loglevel = logging.INFO

    if config.aliases is None:
        config.aliases = dict()

    if config.modules is None:
        config.modules = []

    try:  # pragma: nocover
        for o, a in opts:
            if o in ('-h', '--help'):
                print(docs)
                sys.exit(0)
            elif o == '--loglevel':
                config.loglevel = getattr(logging, a.upper(), None)
                if not isinstance(config.loglevel, int):
                    raise ValueError('Invalid log level: %s' % config.loglevel)
            elif o == '--logfile':
                config.logfile = a
            elif o in ('--log', '-l'):
                config.error_log = a
                config.access_log = a
            elif o in '--error-log':
                config.error_log = a
            elif o in '--access-log':
                config.access_log = a
            elif o in ('--host', '-H'):
                config.bind_address = a
            elif o in ('--port', '-P'):
                config.port = int(a)
            elif o in ('--pidfile', '-p'):
                config.pid_file = a
            elif o in ('--no-caching', '-C'):
                config.caching_enabled = False
            elif o in ('--caching-delay', 'D'):
                config.caching_delay = int(o)
            elif o in ('--foreground', '-f'):
                config.daemonize = False
            elif o in ('--autoreload', '-a'):
                config.autoreload = True
            elif o in '--frequency':
                config.update_frequency = int(a)
            elif o in ('-A', '--alias'):
                (a, colon, uri) = a.partition(':')
                assert (colon == ':')
                if a and uri:
                    config.aliases[a] = uri
            elif o in '--dir':
                config.base_dir = a
            elif o in '--proxy':
                config.proxy = True
            elif o in '--allow_shutdown':
                config.allow_shutdown = True
            elif o in ('-m', '--module'):
                config.modules.append(a)
            elif o in '--version':
                print("{} version {}".format(program, pyff_version))
                sys.exit(0)
            else:
                raise ValueError("Unknown option '%s'" % o)

    except Exception as ex:
        print(ex)
        print(docs)
        sys.exit(3)

    return args