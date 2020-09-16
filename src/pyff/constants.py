"""
Useful constants for pyFF. Mostly XML namespace declarations.
"""


from distutils.util import strtobool
import pyconfig
import logging
import getopt
import sys
import os
import six
import json
import re

from . import __version__ as pyff_version


__author__ = 'leifj'

#: The default nameFormat URI in pyFF is always urn:oasis:names:tc:SAML:2.0:attrname-format:uri
NF_URI = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"

#: These are the namespace prefixes pyFF knows about.
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

#: These are the attribute aliases pyFF knows about. These are used to build URI paths, populate the index
#: and simplify lookup expressions involving boolean or set logic.
ATTRS = {'collection': 'http://pyff.io/collection',
         'entity-category': 'http://macedir.org/entity-category',
         'role': 'http://pyff.io/role',
         'software': 'http://pyff.io/software',
         'domain': 'http://pyff.io/domain'}

ATTRS_INV = {v: k for k, v in list(ATTRS.items())}

PLACEHOLDER_ICON = 'data:image/gif;base64,R0lGODlhAQABAIABAP///wAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw=='

DIGESTS = ['sha1', 'md5', 'null']


def as_string(o):
    if type(o) not in six.string_types:
        o = str(o)
    return o


def as_int(o):
    return int(o)


def as_loglevel(o):
    if type(o) in six.string_types:
        if hasattr(logging, str(o)):
            o = getattr(logging, str(o))
        raise ValueError("No such loglevel: {}".format(repr(o)))
    return o


def as_list_of_string(o):
    if type(o) in six.string_types:
        o = re.findall(r'[^,:\s]+', o)
    return o


def as_dict_of_string(o):
    if type(o) in six.string_types:
        o = json.loads(o)
    return o


def as_bool(o):
    if type(o) not in ('bool', ):
        o = bool(strtobool(str(o)))
    return o


class EnvSetting(object):

    def __init__(self, name, default, typeconv=as_string):
        self.name = name
        self.typeconv = typeconv
        self._fallback = pyconfig.setting('pyff.{}'.format(name), default, allow_default=True)

    def __get__(self, instance, owner):
        v = os.environ.get("PYFF_{}".format(self.name.upper().replace('.','_').replace('-','_')), self._fallback.__get__(instance, owner))
        if v is not None:
            v = self.typeconv(v)

        return v


def setting(name, default, typeconv=as_string):
    return EnvSetting(name, default, typeconv=typeconv)


class Config(object):
    """
    The :py:const:`pyff.constants:config` object is a singleton instance of this Class and contains all
    configuration parameters available to pyFF. Each parameter can be set directly, via :py:mod:`pyconfig`
    or via environment variables by prefixing the setting name in upper case with "PYFF_". The setting
    called "loglevel" then becomes "PYFF_LOGLEVEL" etc. Any occurence of '.' or '-' is also transscribed
    to '_' when the setting is referenced as an environment variable.
    """

    google_api_key = setting("google_api_key", None)
    loglevel = setting("loglevel", logging.WARN, as_loglevel)
    access_log = setting("access_log", None)
    error_log = setting("error_log", None)
    logfile = setting("log", None)
    port = setting("port", 8080, as_int)
    bind_address = setting("bind_address", "127.0.0.1")
    pid_file = setting("pid_file", "/var/run/pyff.pid")
    caching_enabled = setting("caching.enabled", True)
    caching_delay = setting("caching.delay", 300, as_int)
    daemonize = setting("daemonize", True)
    autoreload = setting("autoreload", False, as_bool)
    aliases = setting("aliases", ATTRS, as_dict_of_string)
    base_dir = setting("base_dir", None)
    proxy = setting("proxy", False, as_bool)
    public_url = setting("public_url", None, as_string)
    allow_shutdown = setting("allow_shutdown", False, as_bool)
    modules = setting("modules", [], as_list_of_string)
    cache_ttl = setting("cache_ttl", 300, as_int)
    randomize_cache_ttl = setting("randomize_cache_ttl", True, as_bool)
    cache_size = setting("cache.size", 3000, as_int)
    default_cache_duration = setting("default_cache_duration", "PT1H")
    respect_cache_duration = setting("respect_cache_duration", True, as_bool)
    info_buffer_size = setting("info_buffer_size", 10, as_int)
    worker_pool_size = setting("worker_pool_size", 10, as_int)
    store_class = setting("store.class", "pyff.store:MemoryStore")
    store_clear = setting("store.clear", False, as_bool)
    icon_store_clear = setting("icon_store.clear", False, as_bool)
    icon_maxsize = setting("icon_maxsize", 31*1024, as_int)  # 32k is the biggest data: uri size
    resource_store_class = setting('resource_store.class', "pyff.fetch:MemoryResourceStore")
    icon_store_class = setting("icon_store.class", "pyff.store:MemoryIconStore")
    store_name = setting("store.name", "pyff")
    update_frequency = setting("update_frequency", 0, as_int)
    request_timeout = setting("request_timeout", 10, as_int)
    request_cache_time = setting("request_cache_time", 300, as_int)
    request_cache_backend = setting("request_cache_backend", 'memory', as_string)
    request_override_encoding = setting("request_override_encoding", "utf8")  # set to non to enable chardet guessing
    devel_memory_profile = setting("devel_memory_profile", False, as_bool)
    devel_write_xml_to_file = setting("devel_write_xml_to_file", False, as_bool)
    ds_template = setting("ds_template", "ds.html")
    redis_host = setting("redis_host", "localhost")
    redis_port = setting("redis_port", 6379, as_int)
    load_icons = setting("load_icons", False, as_bool)
    cache_ttl_icons = setting("cache_ttl_icons", 24*3600, as_int)
    load_icons_async = setting("load_icons_async", False, as_bool)  # this is unstable - apscheduler is unpredictable
    pipeline = setting("pipeline", None)
    scheduler_job_store = setting("scheduler_job_store", "memory", as_string)
    langs = setting("langs", 'en', as_list_of_string)

    @property
    def base_url(self):
        if self.public_url:
            return self.public_url
        return "http://{}{}".format(config.bind_address, "" if config.port == 80 else ":{}".format(config.port))


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
            elif o in ('--error-log', ):
                config.error_log = a
            elif o in ('--access-log', ):
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
            elif o in ('--frequency', ):
                config.update_frequency = int(a)
            elif o in ('-A', '--alias'):
                (a, colon, uri) = a.partition(':')
                assert (colon == ':')
                if a and uri:
                    config.aliases[a] = uri
            elif o in ('--dir', ):
                config.base_dir = a
            elif o in ('--proxy', ):
                config.proxy = True
            elif o in ('--allow_shutdown', ):
                config.allow_shutdown = True
            elif o in ('-m', '--module'):
                config.modules.append(a)
            elif o in ('--version', ):
                print("{} version {}".format(program, pyff_version))
                sys.exit(0)
            else:
                raise ValueError("Unknown option '%s'" % o)

    except Exception as ex:
        print(ex)
        print(docs)
        sys.exit(3)

    return args
