import os
from abc import ABC
from collections import deque
from typing import Any, List, Mapping

from xmlsec.crypto import CertDict

from .constants import NS
from .logs import get_log
from .resource import Resource
from .utils import find_matching_files, parse_xml, root, unicode_stream, utc_now

__author__ = 'leifj'

log = get_log(__name__)


class ParserException(Exception):
    def __init__(self, msg, wrapped=None, data=None):
        self._wraped = wrapped
        self._data = data
        super(self.__class__, self).__init__(msg)

    def raise_wraped(self):
        raise self._wraped


class PyffParser(ABC):
    def to_json(self):
        return str(self)

    def magic(self, content: str):
        """Return True if this parser is applicable to this content"""
        raise NotImplementedError()

    def parse(self, resource: Resource, content: str) -> Mapping[str, Any]:
        """Initialise/update a resource based on this content, returning information about it
        TODO: Determine what 'parse' actually means

        TODO: Return something more structured than an arbitrary mapping
        """
        raise NotImplementedError()


class NoParser(PyffParser):
    def __init__(self):
        pass

    def __str__(self):
        return "Not a supported type"

    def magic(self, content):
        return True

    def parse(self, resource, content):
        raise ParserException("No matching parser found for %s" % resource.url)


class DirectoryParser(PyffParser):
    def __init__(self, extensions):
        self.extensions = extensions

    def __str__(self):
        return "Directory"

    def magic(self, content: str) -> bool:
        return os.path.isdir(content)

    def parse(self, resource: Resource, content: str):
        resource.children = deque()
        info = dict()
        info['Description'] = 'Directory'
        info['Expiration Time'] = 'never expires'
        n = 0
        for fn in find_matching_files(content, self.extensions):
            resource.add_child("file://" + fn)
            n += 1

        if n == 0:
            raise IOError("no entities found in {}".format(content))

        resource.never_expires = True
        resource.expire_time = None
        resource.last_seen = utc_now().replace(microsecond=0)

        return dict()


class XRDParser(PyffParser):
    def __init__(self):
        pass

    def __str__(self):
        return "XRD"

    def magic(self, content: str) -> bool:
        return 'XRD' in content

    def parse(self, resource: Resource, content: str) -> Mapping[str, Any]:
        info = dict()
        info['Description'] = "XRD links"
        info['Expiration Time'] = 'never expires'
        t = parse_xml(unicode_stream(content))

        relt = root(t)
        for xrd in t.iter("{%s}XRD" % NS['xrd']):
            for link in xrd.findall(".//{%s}Link[@rel='%s']" % (NS['xrd'], NS['md'])):
                link_href = link.get("href")
                certs = CertDict(link)
                fingerprints = list(certs.keys())
                fp = None
                if len(fingerprints) > 0:
                    fp = fingerprints[0]
                log.debug("XRD: {} verified by {}".format(link_href, fp))
                resource.add_child(link_href, verify=fp)
        resource.last_seen = utc_now().replace(microsecond=0)
        resource.expire_time = None
        resource.never_expires = True
        return info


_parsers: List[PyffParser] = [XRDParser(), DirectoryParser(['xml']), NoParser()]


def add_parser(parser):
    _parsers.insert(0, parser)


def parse_resource(resource: Resource, content: str):
    for parser in _parsers:
        if parser.magic(content):
            resource.last_parser = parser
            return parser.parse(resource, content)
