import os
from .utils import parse_xml, root, first_text, dumptree
from .constants import NS
from .logs import log
from xmlsec.crypto import CertDict
from datetime import datetime
from six import StringIO

__author__ = 'leifj'


class ParserException(Exception):
    def __init__(self, msg, wrapped=None, data=None):
        self._wraped = wrapped
        self._data = data
        super(self.__class__, self).__init__(msg)

    def raise_wraped(self):
        raise self._wraped


class NoParser():
    def magic(self, content):
        return True

    def parse(self, resource, content):
        raise ParserException("No matching parser found for %s" % resource.url)


class DirectoryParser():
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


class XRDParser():
    def __init__(self):
        pass

    def magic(self, content):
        return 'XRD' in content

    def parse(self, resource, content):
        info = dict()
        info['Description'] = "XRD links from {}".format(resource.url)
        t = parse_xml(StringIO(content.encode('utf8')))
        relt = root(t)
        for xrd in t.iter("{%s}XRD" % NS['xrd']):
            for link in xrd.findall(".//{%s}Link[@rel='%s']" % (NS['xrd'], NS['md'])):
                link_href = link.get("href")
                certs = CertDict(link)
                fingerprints = certs.keys()
                fp = None
                if len(fingerprints) > 0:
                    fp = fingerprints[0]
                log.debug("XRD: {} verified by {}".format(link_href, fp))
                resource.add_child(link_href, verify=fp)
        resource.last_seen = datetime.now
        resource.expire_time = None
        return info


class MDServiceListParser():
    def __init__(self):
        pass

    def magic(self, content):
        return 'MetadataServiceList' in content

    def parse(self, resource, content):
        info = dict()
        info['Description'] = "eIDAS MetadataServiceList from {}".format(resource.url)
        t = parse_xml(StringIO(content.encode('utf8')))
        relt = root(t)
        info['Version'] = relt.get('Version', '0')
        info['IssueDate'] = relt.get('IssueDate')
        info['IssuerName'] = first_text(relt, "{%s}IssuerName" % NS['ser'])
        info['SchemeIdentifier'] = first_text(relt, "{%s}SchemeIdentifier" % NS['ser'])
        info['SchemeTerritory'] = first_text(relt, "{%s}SchemeTerritory" % NS['ser'])
        for mdl in relt.iter("{%s}MetadataList" % NS['ser']):
            for ml in mdl.iter("{%s}MetadataLocation" % NS['ser']):
                location = ml.get('Location')
                if location:
                    certs = CertDict(ml)
                    fingerprints = certs.keys()
                    fp = None
                    if len(fingerprints) > 0:
                        fp = fingerprints[0]

                    ep = ml.find("{%s}Endpoint" % NS['ser'])
                    if ep is not None and fp is not None:
                        log.debug("MetadataServiceList[{}]: {} verified by {}".format(info['SchemeTerritory'],
                                  location, fp))
                        resource.add_child(location,
                                           verify=fp,
                                           eidas_territory=mdl.get('Territory'),
                                           eidas_endpoint_type=ep.get('EndpointType'))

        log.debug("Done parsing eIDAS MetadataServiceList")
        resource.last_seen = datetime.now
        resource.expire_time = None
        return info


_parsers = [XRDParser(), MDServiceListParser(), DirectoryParser('.xml'), NoParser()]


def add_parser(parser):
    _parsers.insert(0, parser)


def parse_resource(resource, content):
    for parser in _parsers:
        if parser.magic(content):
            return parser.parse(resource, content)
