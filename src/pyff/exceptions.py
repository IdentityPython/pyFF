__author__ = 'leifj'
import six


class PyffException(BaseException):
    def __init__(self, msg, wrapped=None, data=None):
        self._wrapped = wrapped
        self._data = data
        if six.PY2:
            super(self.__class__, self).__init__(msg)
        else:
            super().__init__(msg)

    def raise_wrapped(self):
        raise self._wrapped


class ResourceException(PyffException):
    pass


class MetadataException(ResourceException):
    pass


class MetadataExpiredException(MetadataException):
    pass
