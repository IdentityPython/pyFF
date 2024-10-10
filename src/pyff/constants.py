"""
Useful constants for pyFF. Mostly XML namespace declarations.
"""

import getopt
import json
import logging
import os
import re
import sys
from str2bool import str2bool

import pyconfig
import six

from pyff import __version__ as pyff_version

__author__ = 'leifj'

#: The default nameFormat URI in pyFF is always urn:oasis:names:tc:SAML:2.0:attrname-format:uri
NF_URI = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"

#: These are the namespace prefixes pyFF knows about.
NS = dict(
    md="urn:oasis:names:tc:SAML:2.0:metadata",
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
    eidas="http://eidas.europa.eu/saml-extensions",
    ti="https://seamlessaccess.org/NS/trustinfo",
    idpdisc="urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol",
)

#: These are the attribute aliases pyFF knows about. These are used to build URI paths, populate the index
#: and simplify lookup expressions involving boolean or set logic.
ATTRS = {
    'collection': 'http://pyff.io/collection',
    'entity-category': 'http://macedir.org/entity-category',
    'role': 'http://pyff.io/role',
    'software': 'http://pyff.io/software',
    'domain': 'http://pyff.io/domain',
}

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
    if type(o) not in ('bool',):
        o = bool(str2bool(str(o)))
    return o


class BaseSetting(object):
    def __init__(
        self,
        name,
        default=None,
        deprecated=False,
        cmdline=['pyff', 'pyffd'],
        typeconv=as_string,
        info='',
        long=None,
        short=None,
        hidden=False,
    ):
        self.name = name
        self.default = default
        self.deprecated = deprecated
        self.cmdline = cmdline
        self.info = info
        self.short = short
        self.typeconv = typeconv
        self.value = None
        self.long = long
        self.hidden = hidden
        self.fallback = pyconfig.setting('pyff.{}'.format(self.name), default, allow_default=True)

    @property
    def default_fmt(self):
        if self.default:
            return "[{}]".format(str(self.default))
        else:
            return ''

    @property
    def short_name(self):
        return self.short

    @property
    def long_name(self):
        if self.long is not None:
            return self.long
        else:
            return self.name

    def __lt__(self, other):
        return self.name.__lt__(other.name)

    def __gt__(self, other):
        return self.name.__gt__(other.name)

    def __get__(self, instance, owner):
        v = self.value
        if v is None:
            v = os.environ.get(
                "PYFF_{}".format(self.name.upper().replace('.', '_').replace('-', '_')),
                self.fallback.__get__(instance, owner),
            )
        if v is not None:
            v = self.typeconv(v)

        return v

    def __set__(self, instance, value):
        self.value = value

    def short_spec(self):
        if self.short:
            if (hasattr(self, 'typeconv') and self.typeconv == as_bool) or isinstance(self, InvertedSetting):
                return self.short
            else:
                return '{}:'.format(self.short)
        else:
            return ''

    def long_spec(self):
        long_name = self.long_name
        if hasattr(self, 'typeconv') and self.typeconv == as_bool:
            return '{}'.format(long_name)
        else:
            return '{}='.format(long_name)


class EnvSetting(BaseSetting):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class ListSetting(BaseSetting):
    def __init__(self, *args, **kwargs):
        self.args = kwargs.pop('settings')
        super().__init__(*args, **kwargs)

    def __get__(self, instance, owner):
        if len(self.args) > 0:
            return self.args[0].__get__(instance, owner)
        else:
            return None

    def __set__(self, instance, value):
        for item in self.args:
            item.__set__(value)


class InvertedSetting(BaseSetting):
    def __init__(self, *args, **kwargs):
        self.setting = kwargs.pop('invert')
        super().__init__(*args, **kwargs)

    def __get__(self, instance, owner):
        return not self.setting.__get__()

    def __set__(self, instance, value):
        self.setting.__set__(not value)


class DummySetting(BaseSetting):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def __get__(self, instance, owner):
        pass

    def __set__(self, instance, value):
        pass


def S(*args: object, **kwargs: object) -> BaseSetting:
    return EnvSetting(*args, **kwargs)


def N(*args: object, **kwargs: object) -> BaseSetting:
    return InvertedSetting(*args, **kwargs)


class Config(object):
    """
    The :py:const:`pyff.constants:config` object is a singleton instance of this Class and contains all
    configuration parameters available to pyFF. Each parameter can be set directly, via :py:mod:`pyconfig`
    or via environment variables by prefixing the setting name in upper case with "PYFF_". The setting
    called "loglevel" then becomes "PYFF_LOGLEVEL" etc. Any occurrence of '.' or '-' is also transcribed
    to '_' when the setting is referenced as an environment variable.


    Content Negotiation

    content_negotiation_policy is one of three values:

    1. extension - current default, inspect the path and if it ends in an extension, e.g. .xml or .json, always
    strip off the extension to get the entityID and if no accept header or a wildcard header, then use the extension
    to determine the return Content-Type.

    2. adaptive - only if no accept header or if a wildcard, then inspect the path and if it ends in an extension
    strip off the extension to get the entityID and use the extension to determine the return Content-Type.

    3. header - future default, do not inspect the path for an extension and use only the Accept header to determine
    the return Content-Type.

    """

    info = DummySetting("help", info="Show this message", short='h', typeconv=as_bool)
    version = DummySetting('version', info="Show pyff version information", short='v', typeconv=as_bool)
    module = DummySetting("module", info="load additional plugins from the specified module", short='m')
    alias = DummySetting('alias', info="add an alias to the server - argument must be on the form alias=uri", short='A')

    # deprecated settings
    google_api_key = S("google_api_key", deprecated=True)
    caching_delay = S("caching_delay", default=300, typeconv=as_int, short='D', deprecated=True)
    proxy = S("proxy", default=False, typeconv=as_bool, deprecated=True)
    public_url = S("public_url", typeconv=as_string, deprecated=True)
    allow_shutdown = S("allow_shutdown", default=False, typeconv=as_bool, deprecated=True)
    ds_template = S("ds_template", default="ds.html", deprecated=True)

    loglevel = S("loglevel", default='WARN', info="set the loglevel")

    access_log = S("access_log", cmdline=['pyffd'], info="a log target (file) to use for access logs")

    error_log = S("error_log", cmdline=['pyffd'], info="a log target (file) to use for access logs")

    logfile = ListSetting(
        'log',
        settings=[error_log, access_log],
        short='l',
        cmdline=['pyffd'],
        info="a log target (file) to be used for both access and error logs",
    )

    port = S("port", default=8080, cmdline=['pyffd'], typeconv=as_int, short='P', info="set the port number to bind to")

    host = S(
        "host", default="127.0.0.1", short='H', cmdline=['pyffd'], info="set the local address (interface) to bind to"
    )

    pid_file = S(
        "pid_file", default="/var/run/pyff.pid", short='p', cmdline=['pyffd'], info="write the pid to this file"
    )

    caching_enabled = S("caching_enabled", default=True, typeconv=as_bool, info="enable caching?")

    no_caching = N('no_caching', invert=caching_enabled, short='C', info="disable all caches")

    daemonize = S("daemonize", default=True, cmdline=['pyffd'], info="run in background")

    foreground = N('foreground', invert=daemonize, short='f', cmdline=['pyffd'], info="run in foreground")

    autoreload = S(
        "autoreload",
        default=False,
        typeconv=as_bool,
        short='a',
        cmdline=['pyffd'],
        info="automatically restart the server when code changes?",
    )

    aliases = S(
        "aliases",
        default=ATTRS,
        typeconv=as_dict_of_string,
        cmdline=['pyffd'],
        hidden=True,
        info="a set of aliases to add to the server",
    )

    base_dir = S("base_dir", info="change to this directory before executing the pipeline")
    compat_dir = S("dir", hidden=True, info="cf base_dir")

    modules = S("modules", default=[], typeconv=as_list_of_string, hidden=True, info="modules providing plugins")

    cache_ttl = S("cache_ttl", default=300, typeconv=as_int, info="number of seconds to hold cache objects")

    randomize_cache_ttl = S(
        "randomize_cache_ttl",
        default=True,
        typeconv=as_bool,
        info="add random fuzz to avoid hammering on cached icon URLs?",
    )

    cache_size = S("cache.size", long="cache_size", default=3000, typeconv=as_int, info="the size of the cache")

    default_cache_duration = S(
        "default_cache_duration", default="PT1H", info="the default saml metadata @cacheDuration"
    )

    respect_cache_duration = S(
        "respect_cache_duration",
        default=True,
        typeconv=as_bool,
        info="respect the @cacheDuration attribute in saml metadata?",
    )

    info_buffer_size = S(
        "info_buffer_size", default=10, typeconv=as_int, info="how much history to keep about each metadata URL"
    )

    worker_pool_size = S(
        "worker_pool_size", default=1, cmdline=['pyffd'], typeconv=as_int, info="how many gunicorn workers to run"
    )

    threads = S("threads", default=10, cmdline=['pyffd'], typeconv=as_int, info="how many gunicorn threads to run")

    store_class = S("store_class", default="pyff.store:MemoryStore", info="the <pyff.store:Store> implementation")

    store_clear = S(
        "store.clear",
        long="store_clear",
        default=False,
        typeconv=as_bool,
        info="empty the store before executing the pipeline?",
    )

    icon_store_clear = S(
        "icon_store.clear", long="icon_store_clear", default=False, typeconv=as_bool, info="empty the icon store?"
    )

    icon_maxsize = S(
        "icon_maxsize", default=31 * 1024, typeconv=as_int, info="the maximum size icon to keep in store"
    )  # 32k is the biggest data: uri size

    icon_store_class = S(
        "icon_store.class", long="icon_store_class", default="pyff.store:MemoryIconStore", info="the <IconStore> to use"
    )

    store_name = S("store.name", long="store_name", default="pyff", info="the name of the store (mostly for redis)")

    update_frequency = S(
        "frequency",
        default=300,
        typeconv=as_int,
        cmdline=['pyffd'],
        short='F',
        info="how often (seconds) to run the update pipeline",
    )

    worker_timeout = S(
        'worker_timeout',
        default=1200,
        typeconv=as_int,
        cmdline=['pyffd'],
        info="how long (seconds) to allow a gunicorn worker to run",
    )

    request_timeout = S(
        "request_timeout",
        default=10,
        cmdline=['pyffd'],
        typeconv=as_int,
        info="the outgoing http request timeout (in seconds)",
    )

    request_cache_time = S(
        "request_cache_time", default=300, typeconv=as_int, info="how long (seconds) to keep request cache objects"
    )

    request_cache_backend = S(
        "request_cache_backend", default='memory', typeconv=as_string, info="the requests-cache backend to use"
    )

    request_override_encoding = S(
        "request_override_encoding", default="utf8", info="set to None to enable chardet guessing"
    )

    devel_memory_profile = S(
        "devel_memory_profile", default=False, typeconv=as_bool, cmdline=['pyffd'], info="launch a memory profiler?"
    )

    devel_write_xml_to_file = S(
        "devel_write_xml_to_file", default=False, typeconv=as_bool, info="write entities xml files for debugging?"
    )

    redis_host = S("redis_host", default="localhost", info="the host where redis lives")

    redis_port = S("redis_port", default=6379, typeconv=as_int, info="the port where redis lives")

    load_icons = S("load_icons", default=False, typeconv=as_bool, info="preload icons and include as data: URIs?")

    cache_ttl_icons = S(
        "cache_ttl_icons",
        default=24 * 3600,
        typeconv=as_int,
        info="how long (seconds) to keep icons before reloading them",
    )

    load_icons_async = S("load_icons_async", default=False, typeconv=as_bool, info="load icons asyncronously?")

    pipeline = S("pipeline", info="the yaml pipeline file")

    scheduler_job_store = S(
        "scheduler_job_store",
        default="memory",
        typeconv=as_string,
        info="use a persistent job store when running multiple workers",
    )

    langs = S("langs", default='en', typeconv=as_list_of_string, info="the default language code(s)")

    huge_xml = S("huge_xml", default=False, typeconv=as_bool, info="enable on huge_xml support in lxml?")

    content_negotiation_policy = S(
        "content_negotiation_policy", default="extension", typeconv=as_string, info="cf section on content negotiation"
    )

    xinclude = S("xinclude", default=True, typeconv=as_bool, info="process xinclude statements?")

    logger = S('logger', typeconv=as_string, info="python logger config - overides all other logging directives")

    local_copy_dir = S(
        'local_copy_dir',
        typeconv=as_string,
        info="the directory where local backup copies of metadata is stored",
        default="/var/run/pyff/backup",
    )

    @property
    def base_url(self):
        if self.public_url:
            return self.public_url
        return "http://{}{}".format(config.host, "" if config.port == 80 else ":{}".format(config.port))

    @staticmethod
    def settings():
        s = list(filter(lambda p: isinstance(p, BaseSetting), vars(Config).values()))
        s.sort()
        return s

    def __str__(self):
        s = "# pyFF configuration\n"
        for p in self.settings():
            s += "{} = {}\n".format(p.name, p.value)
        return s

    def find_setting(self, o):
        for s in self.settings():
            if o == s.short_name or o == s.long_name:
                return s
        return None

    @staticmethod
    def args(prg):
        short = ''
        long = []
        for s in config.settings():
            if s is not None and prg in s.cmdline:
                short += s.short_spec()
                long.append(s.long_spec())
        return short, long

    @staticmethod
    def help(prg):
        hlp = "Usage: {} [options+] <pipeline file (yaml)>\n\n"
        for s in config.settings():
            if prg in s.cmdline and not s.deprecated and not s.hidden:
                h = " --{}".format(s.long_name)
                if s.short:
                    h += "|-{}".format(s.short)
                hlp += "{:30s} {} {}\n".format(h, s.info, s.default_fmt)
        return hlp


config = Config()


def parse_options(program, docs):
    (short_args, long_args) = config.args(program)
    docs += config.help(program)
    try:
        opts, args = getopt.getopt(sys.argv[1:], short_args, long_args)
    except getopt.error as msg:
        print(msg)
        print(docs)
        sys.exit(2)

    if config.loglevel is None:
        config.loglevel = 'INFO'

    if config.aliases is None or len(config.aliases) == 0:
        config.aliases = dict(metadata=entities)

    if config.modules is None:
        config.modules = []

    try:
        for o, a in opts:
            if o in ('-h', '--help'):
                print(docs)
                sys.exit(0)
            elif o in ('-v', '--version'):
                print("{} version {}".format(program, pyff_version))
                sys.exit(0)
            elif o in ('-A', '--alias'):
                (a, colon, uri) = a.partition(':')
                assert colon == ':'
                if a and uri:
                    config.aliases[a] = uri
            elif o in ('-m', '--module'):
                config.modules.append(a)
            else:
                o = o.lstrip('-')
                s = config.find_setting(o)
                if s is not None:
                    if s.deprecated:
                        print("WARNING: {} is deprecated. Setting this option has no effect!".format(o))
                    else:
                        setattr(s, 'value', a)
                else:
                    raise ValueError("Unknown option {}".format(o))

        if config.compat_dir and not config.base_dir:
            config.base_dir = config.compat_dir

    except Exception as ex:
        print(ex)
        print(docs)
        sys.exit(3)

    return args
