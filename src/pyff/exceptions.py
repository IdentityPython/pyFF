__author__ = 'leifj'


class MetadataException(Exception):
    pass


class MetadataExpiredException(MetadataException):
    pass


class PyffException(Exception):
    pass


class ResourceException(Exception):
    def __init__(self, msg, wrapped=None, data=None):
        self._wraped = wrapped
        self._data = data
        super(self.__class__, self).__init__(msg)

    def raise_wraped(self):
        raise self._wraped
