"""
Useful constants for pyFF. Mostly XML namespace declarations.
"""

import os
import sys
import pyconfig
import logging

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
          xsi="http://www.w3.org/2001/XMLSchema-instance")

ATTRS = {'collection': 'http://pyff.io/collection',
         'entity-category': 'http://macedir.org/entity-category',
         'role': 'http://pyff.io/role',
         'domain': 'http://pyff.io/domain'}

DIGESTS = ['sha1', 'md5', 'null']

EVENT_DROP_ENTITY = 'event.drop.entity'
EVENT_RETRY_URL = 'event.retry.url'
EVENT_IMPORTED_METADATA = 'event.imported.metadata'
EVENT_IMPORT_FAIL = 'event.import.failed'
EVENT_REPOSITORY_LIVE = 'event.repository.live'


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
    frequency = pyconfig.setting("pyff.frequency", 600)
    aliases = pyconfig.setting("pyff.aliases", ATTRS)
    base_dir = pyconfig.setting("pyff.base_dir", None)
    proxy = pyconfig.setting("pyff.proxy", False)
    store = pyconfig.setting("pyff.store", None)
    allow_shutdown = pyconfig.setting("pyff.allow_shutdown", False)
    modules = pyconfig.setting("pyff.modules", [])


config = Config()