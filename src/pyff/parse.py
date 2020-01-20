import os
from .utils import parse_xml, root, first_text, unicode_stream, find_matching_files
from .constants import NS
from .logs import get_log
from xmlsec.crypto import CertDict
from datetime import datetime

__author__ = 'leifj'

log = get_log(__name__)


class ParserException(Exception):
    def __init__(self, msg, wrapped=None, data=None):
        self._wraped = wrapped
        self._data = data
        super(self.__class__, self).__init__(msg)

    def raise_wraped(self):
        raise self._wraped

class PyffParser(object):

    def to_json(self):
        return str(self);


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

    def magic(self, content):
        return os.path.isdir(content)

    def parse(self, resource, content):
        resource.children = []
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
        resource.last_seen = datetime.now()

        return dict()


class XRDParser(PyffParser):
    def __init__(self):
        pass

    def __str__(self):
        return "XRD"

    def magic(self, content):
        return 'XRD' in content


    def parse(self, resource, content):
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
        resource.last_seen = datetime.now()
        resource.expire_time = None
        resource.never_expires = True
        return info


_parsers = [XRDParser(), DirectoryParser(['xml']), NoParser()]


def add_parser(parser):
    _parsers.insert(0, parser)


def parse_resource(resource, content):
    for parser in _parsers:
        if parser.magic(content):
            resource.last_parser = parser
            return parser.parse(resource, content)
