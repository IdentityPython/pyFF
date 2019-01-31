import os
from .utils import parse_xml, root, first_text, unicode_stream
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


class NoParser(object):
    def __init__(self):
        pass

    def magic(self, content):
        return True

    def parse(self, resource, content):
        raise ParserException("No matching parser found for %s" % resource.url)


class DirectoryParser(object):
    def __init__(self, ext):
        self.ext = ext

    def magic(self, content):
        return os.path.isdir(content)

    def _find_matching_files(self, d):
        log.debug("find files in {}".format(repr(d)))
        for top, dirs, files in os.walk(d):
            for dn in dirs:
                if dn.startswith("."):
                    dirs.remove(dn)

            for nm in files:
                if nm.endswith(self.ext):
                    fn = os.path.join(top, nm)
                    yield fn

    def parse(self, resource, content):
        resource.children = []
        n = 0
        for fn in self._find_matching_files(content):
            resource.add_child("file://" + fn)
            n += 1

        if n == 0:
            raise IOError("no entities found in {}".format(content))

        return dict()


class XRDParser(object):
    def __init__(self):
        pass

    def magic(self, content):
        return 'XRD' in content

    def parse(self, resource, content):
        info = dict()
        info['Description'] = "XRD links from {}".format(resource.url)
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
        resource.last_seen = datetime.now
        resource.expire_time = None
        return info



_parsers = [XRDParser(), DirectoryParser('.xml'), NoParser()]


def add_parser(parser):
    _parsers.insert(0, parser)


def parse_resource(resource, content):
    for parser in _parsers:
        if parser.magic(content):
            return parser.parse(resource, content)
