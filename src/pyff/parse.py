
import os

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

    def _find_matching_files(self, dir):
        for top, dirs, files in os.walk(dir):
            for dn in dirs:
                if dn.startswith("."):
                    dirs.remove(dn)

            for nm in files:
                if nm.endswith(self.ext):
                    fn = os.path.join(top, nm)
                    yield fn

    def parse(self, resource, content):
        resource.children = []
        for fn in self._find_matching_files(dir):
            resource.add_child("file://"+fn)

        return dict()


_parsers = [DirectoryParser('.xml'), NoParser()]

def add_parser(parser):
    _parsers.insert(0,parser)

def parse_resource(resource, content):
    for parser in _parsers:
        if parser.magic(content):
            return parser.parse(resource, content)