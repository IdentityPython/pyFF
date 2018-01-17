"""

This is the implementation of the active repository of SAML metadata. The 'local' and 'remote' pipes operate on this.

"""

from __future__ import absolute_import, unicode_literals
from .stats import get_metadata_info
import operator
from lxml import etree
import ipaddr
from . import merge_strategies
from .logs import log
from .samlmd import entitiesdescriptor, find_merge_strategy, find_entity, iter_entities, entity_simple_summary
from .utils import root, MetadataException, avg_domain_distance, load_callable
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

    def search(self, query=None, path=None, page=None, page_limit=10, entity_filter=None, related=None):
        """
:param query: A string to search for.
:param path: The repository collection (@Name) to search in - None for search in all collections
:param page:  When using paged search, the page index
:param page_limit: When using paged search, the maximum entry per page
:param entity_filter: An optional lookup expression used to filter the entries before search is done.
:param related: an optional '+'-separated list of related domain names for prioritizing search results

Returns a list of dict's for each EntityDescriptor present in the metadata store such
that any of the DisplayName, ServiceName, OrganizationName or OrganizationDisplayName
elements match the query (as in contains the query as a substring).

The dict in the list contains three items:

:title: A displayable string, useful as a UI label
:value: The entityID of the EntityDescriptor
:id: A sha1-ID of the entityID - on the form {sha1}<sha1-hash-of-entityID>
        """

        match_query = bool(len(query) > 0)

        if isinstance(query, basestring):
            query = [query.lower()]

        def _strings(elt):
            lst = []
            for attr in ['{%s}DisplayName' % NS['mdui'],
                         '{%s}ServiceName' % NS['md'],
                         '{%s}OrganizationDisplayName' % NS['md'],
                         '{%s}OrganizationName' % NS['md'],
                         '{%s}Keywords' % NS['mdui'],
                         '{%s}Scope' % NS['shibmd']]:
                lst.extend([s.text for s in elt.iter(attr)])
            lst.append(elt.get('entityID'))
            return filter(lambda item: item is not None, lst)

        def _ip_networks(elt):
            return [ipaddr.IPNetwork(x.text) for x in elt.iter('{%s}IPHint' % NS['mdui'])]

        def _match(qq, elt):
            for q in qq:
                q = q.strip()
                if ':' in q or '.' in q:
                    try:
                        nets = _ip_networks(elt)
                        for net in nets:
                            if ':' in q and ipaddr.IPv6Address(q) in net:
                                return net
                            if '.' in q and ipaddr.IPv4Address(q) in net:
                                return net
                    except ValueError:
                        pass

                if q is not None and len(q) > 0:
                    tokens = _strings(elt)
                    for tstr in tokens:
                        for tpart in tstr.split():
                            if tpart.lower().startswith(q):
                                return tstr
            return None

        f = []
        if path is not None and path not in f:
            f.append(path)
        if entity_filter is not None and entity_filter not in f:
            f.append(entity_filter)
        mexpr = None
        if f:
            mexpr = "+".join(f)

        log.debug("match using '%s'" % mexpr)
        res = []
        for e in self.lookup(mexpr):
            d = None
            if match_query:
                m = _match(query, e)
                if m is not None:
                    d = entity_simple_summary(e)
                    ll = d['title'].lower()
                    if m != ll and not query[0] in ll:
                        d['title'] = "%s - %s" % (d['title'], m)
            else:
                d = entity_simple_summary(e)

            if d is not None:
                if related is not None:
                    d['ddist'] = avg_domain_distance(related, d['domains'])
                else:
                    d['ddist'] = 0

                res.append(d)

        res.sort(key=operator.itemgetter('title'))
        res.sort(key=operator.itemgetter('ddist'), reverse=True)

        if page is not None:
            total = len(res)
            begin = (page - 1) * page_limit
            end = begin + page_limit
            more = (end < total)
            return res[begin:end], more, total
        else:
            return res

    def sane(self):
        """A very basic test for sanity. An empty metadata set is probably not a sane output of any process.

:return: True iff there is at least one EntityDescriptor in the active set.
        """
        return len(self.store.collections()) > 0

    def find(self, t, member):
        relt = root(t)
        if type(member) is str or type(member) is unicode:
            if '!' in member:
                (src, xp) = member.split("!")
                return relt.xpath(xp, namespaces=NS, smart_strings=False)
            else:
                lst = []
                for e in iter_entities(relt):
                    if e.get('entityID') == member:
                        lst.append(e)
                return lst
        raise MetadataException("unknown format for filtr member: %s" % member)

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
            t = self.entity_set(l, 'dummy')
            if t is None:
                return []
            l = root(t).xpath(xp, namespaces=NS, smart_strings=False)
            log.debug("got %d entities after filtering" % len(l))
            return l

    def entity_set(self,
                   entities,
                   name,
                   lookup_fn=None,
                   cache_duration=None,
                   valid_until=None,
                   validate=True,
                   copy=True):
        """
:param entities: a set of entities specifiers (lookup is used to find entities from this set)
:param name: the @Name attribute
:param cache_duration: an XML timedelta expression, eg PT1H for 1hr
:param valid_until: a relative time eg 2w 4d 1h for 2 weeks, 4 days and 1hour from now.
:param lookup_fn: a callable used to lookup entities by entityID

Produce an EntityDescriptors set from a list of entities. Optional Name, cacheDuration and validUntil are affixed.
        """

        return entitiesdescriptor(entities, name,
                                  lookup_fn=self.lookup,
                                  cache_duration=cache_duration,
                                  valid_until=valid_until,
                                  validate=validate,
                                  copy=copy)

    def summary(self, uri):
        """
:param uri: An EntitiesDescriptor URI present in the MDRepository
:return: an information dict

Returns a dict object with basic information about the EntitiesDescriptor
        """
        seen = set()
        info = dict()

        info['Duplicates'] = []
        sz = 0

        for e in self.store.lookup(uri):
            entity_id = e.get('entityID')
            if entity_id in seen:
                info['Duplicates'].append(entity_id)
            else:
                seen.add(entity_id)
                sz += 1

        info['Size'] = str(sz)

        info.update(get_metadata_info(uri))
        if 'Validation Errors' in info and info['Validation Errors']:
            info['Status'] = 'danger'

        info.setdefault('Status', 'default')
        return info

    def delete(self, t):
        """
        :param t: The set of entities to remove from the store

        Completely remove all entities in t from the store.
        """
        for e in iter_entities(t):
            self.store.delete(e)

    def merge(self, t, nt, strategy=merge_strategies.replace_existing, strategy_name=None):
        """
:param t: The EntitiesDescriptor element to merge *into*
:param nt:  The EntitiesDescriptor element to merge *from*
:param strategy: A callable implementing the merge strategy pattern
:param strategy_name: The name of a strategy to import. Overrides the callable if present.
:return:

Two EntitiesDescriptor elements are merged - the second into the first. For each element
in the second collection that is present (using the @entityID attribute as key) in the
first the strategy callable is called with the old and new EntityDescriptor elements
as parameters. The strategy callable thus must implement the following pattern:

:old_e: The EntityDescriptor from t
:e: The EntityDescriptor from nt
:return: A merged EntityDescriptor element

Before each call to strategy old_e is removed from the MDRepository index and after
merge the resultant EntityDescriptor is added to the index before it is used to
replace old_e in t.
        """
        if strategy_name is not None:
            strategy = find_merge_strategy(strategy_name)

        for e in iter_entities(nt):
            entity_id = e.get("entityID")
            # we assume ddup:ed tree
            old_e = find_entity(t, entity_id)
            new = strategy(old_e, e)
            if new is not None:
                self.store.update(new)
