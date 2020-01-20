import random

from .store import make_store_instance, make_icon_store_instance
from .utils import is_text, make_default_scheduler
from .resource import Resource, IconHandler
from .logs import get_log
from .samlmd import entitiesdescriptor, root
from .constants import config

log = get_log(__name__)


class MDRepository():
    """A class representing a set of SAML metadata and the resources from where this metadata was loaded.
    """

    def __init__(self, scheduler=None):
        random.seed(self)
        self.rm = Resource()  # root
        if scheduler is None:
            scheduler = make_default_scheduler()
            scheduler.start()
        self.scheduler = scheduler
        self.store = make_store_instance()
        self.icon_store = make_icon_store_instance()
        self.rm.add_watcher(self.store, scheduler=self.scheduler)
        if config.load_icons:
            self.rm.add_watcher(self.icon_store, scheduler=self.scheduler)

    def _lookup(self, member, store=None):
        if store is None:
            store = self.store

        if member is None:
            member = "entities"

        if is_text(member):
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
