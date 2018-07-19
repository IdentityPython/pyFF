"""

This is the implementation of the active repository of SAML metadata. The 'local' and 'remote' pipes operate on this.

"""

from __future__ import absolute_import, unicode_literals
from lxml import etree
from .logs import log
from .samlmd import entitiesdescriptor
from .utils import root, load_callable
from .constants import NS, config
from .fetch import ResourceManager

etree.set_default_parser(etree.XMLParser(resolve_entities=False))


class MDRepository():
    """A class representing a set of SAML Metadata. Instances present as dict-like objects where
    the keys are URIs and values are EntitiesDescriptor elements containing sets of metadata.
    """

    def __init__(self):
        # if not isinstance(self.min_cache_ttl, int):
        #     try:
        #         self.min_cache_ttl = duration2timedelta(self.min_cache_ttl).total_seconds()
        #     except Exception as ex:
        #         log.error(ex)
        #         self.min_cache_ttl = 300
        self.store = None
        self.rm = ResourceManager()
        self.store_class = load_callable(config.store_class)
        self.store = None

    def sane(self):
        """A very basic test for sanity. An empty metadata set is probably not a sane output of any process.

:return: True iff there is at least one EntityDescriptor in the active set.
        """
        return len(self.store.collections()) > 0

    def _lookup(self, member, store=None):
        if store is None:
            store = self.store

        if member is None:
            member = "entities"

        if type(member) is str or type(member) is unicode:
            if '!' in member:
                (src, xp) = member.split("!")
                if len(src) == 0:
                    src = None
                return self.lookup(src, xp=xp, store=store)

        log.debug("calling store lookup %s" % member)
        return store.lookup(member)

    def lookup(self, member, xp=None, store=None):
        """
Lookup elements in the working metadata repository

:param member: A selector (cf below)
:type member: basestring
:param xp: An optional xpath filter
:type xp: basestring
:param store: the store to operate on
:return: An interable of EntityDescriptor elements
:rtype: etree.Element


**Selector Syntax**

    - selector "+" selector
    - [sourceID] "!" xpath
    - attribute=value or {attribute}value
    - entityID
    - source (typically @Name from an EntitiesDescriptor set but could also be an alias)

The first form results in the intersection of the results of doing a lookup on the selectors. The second form
results in the EntityDescriptor elements from the source (defaults to all EntityDescriptors) that match the
xpath expression. The attribute-value forms resuls in the EntityDescriptors that contain the specified entity
attribute pair. If non of these forms apply, the lookup is done using either source ID (normally @Name from
the EntitiesDescriptor) or the entityID of single EntityDescriptors. If member is a URI but isn't part of
the metadata repository then it is fetched an treated as a list of (one per line) of selectors. If all else
fails an empty list is returned.

        """
        if store is None:
            store = self.store

        l = self._lookup(member, store=store)
        if hasattr(l, 'tag'):
            l = [l]
        elif hasattr(l, '__iter__'):
            l = list(l)

        if xp is None:
            return l
        else:
            log.debug("filtering %d entities using xpath %s" % (len(l), xp))
            t = entitiesdescriptor(l, 'dummy', lookup_fn=self.lookup)
            if t is None:
                return []
            l = root(t).xpath(xp, namespaces=NS, smart_strings=False)
            log.debug("got %d entities after filtering" % len(l))
            return l
