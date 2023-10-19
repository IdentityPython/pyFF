import os
from abc import ABC
from collections import deque
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field
from xmlsec.crypto import CertDict

from pyff.constants import NS
from pyff.logs import get_log
from pyff.resource import Resource,ResourceInfo
from pyff.utils import find_matching_files, parse_xml, root, unicode_stream, utc_now

__author__ = 'leifj'

log = get_log(__name__)


class ParserInfo(BaseModel):
    description: str
    expiration_time: str  # TODO: Change expiration_time into a datetime
    validation_errors: Dict[str, Any] = Field({})

    def to_dict(self):
        def _format_key(k: str) -> str:
            # Turn expiration_time into 'Expiration Time'
            return k.replace('_', ' ').title()

        res = {_format_key(k): v for k, v in self.dict().items()}
        return res

ResourceInfo.model_rebuild()

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

    def parse(self, resource: Resource, content: str) -> ParserInfo:
        """Initialise/update a resource based on this content, returning information about it"""
        raise NotImplementedError()


class NoParser(PyffParser):
    def __init__(self):
        pass

    def __str__(self):
        return "Not a supported type"

    def magic(self, content: str) -> bool:
        return True

    def parse(self, resource: Resource, content: str) -> ParserInfo:
        raise ParserException("No matching parser found for %s" % resource.url)


class DirectoryParser(PyffParser):
    def __init__(self, extensions):
        self.extensions = extensions

    def __str__(self):
        return "Directory"

    def magic(self, content: str) -> bool:
        return os.path.isdir(content)

    def parse(self, resource: Resource, content: str) -> ParserInfo:
        resource.children = deque()
        info = ParserInfo(description='Directory', expiration_time='never expires')
        n = 0
        for fn in find_matching_files(content, self.extensions):
            child_opts = resource.opts.copy(update={'alias': None})
            resource.add_child("file://" + fn, child_opts)
            n += 1

        if n == 0:
            raise IOError("no entities found in {}".format(content))

        resource.never_expires = True
        resource.expire_time = None
        resource.last_seen = utc_now().replace(microsecond=0)

        return info


class XRDParser(PyffParser):
    def __init__(self):
        pass

    def __str__(self):
        return "XRD"

    def magic(self, content: str) -> bool:
        return 'XRD' in content

    def parse(self, resource: Resource, content: str) -> ParserInfo:
        info = ParserInfo(description='XRD links', expiration_time='never expires')
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
                child_opts = resource.opts.copy(update={'alias': None})
                resource.add_child(link_href, child_opts)
        resource.last_seen = utc_now().replace(microsecond=0)
        resource.expire_time = None
        resource.never_expires = True
        return info


_parsers: List[PyffParser] = [XRDParser(), DirectoryParser(['xml']), NoParser()]


def add_parser(parser):
    _parsers.insert(0, parser)


def parse_resource(resource: Resource, content: str) -> Optional[ParserInfo]:
    for parser in _parsers:
        if parser.magic(content):
            resource.last_parser = parser
            return parser.parse(resource, content)
    return None
