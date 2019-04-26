from six import StringIO
from copy import deepcopy
import re
from redis import Redis
from .constants import NS, ATTRS, ATTRS_INV
from .decorators import cached
from .logs import get_log
from .constants import config
from .utils import root, dumptree, parse_xml, hex_digest, hash_id, valid_until_ts, \
    avg_domain_distance, ts_now, load_callable, is_text, b2u
from .samlmd import EntitySet, iter_entities, entity_attribute_dict, is_sp, is_idp, entity_info, \
    object_id, find_merge_strategy, find_entity, entity_simple_summary, entitiesdescriptor
from whoosh.fields import Schema, TEXT, ID, KEYWORD, STORED, BOOLEAN
from whoosh import writing
from . import merge_strategies
import ipaddr
import operator
import six

log = get_log(__name__)

DINDEX = ('sha1', 'sha256', 'null')


def make_store_instance():
    new_store = load_callable(config.store_class)
    return new_store()


class SAMLStoreBase(object):
    def lookup(self, key):
        raise NotImplementedError()

    def clone(self):
        return self

    def __iter__(self):
        for e in self.lookup("entities"):
            log.debug("**** yield entityID=%s" % e.get('entityID'))
            yield e

    def size(self, a=None, v=None):
        raise NotImplementedError()

    def collections(self):
        raise NotImplementedError()

    def update(self, t, tid=None, ts=None, merge_strategy=None):
        raise NotImplementedError()

    def reset(self):
        raise NotImplementedError()

    def entity_ids(self):
        return set(e.get('entityID') for e in self.lookup('entities'))

    def _select(self, member=None):
        if member is None:
            member = "entities"

        if is_text(member):
            if '!' in member:
                (src, xp) = member.split("!")
                if len(src) == 0:
                    src = None
                return self.select(src, xp=xp)

        log.debug("calling store lookup %s" % member)
        return self.lookup(member)

    def select(self, member, xp=None):
        """
        Select a set of metadata elements and return an EntityDescriptor with the result of the select.

        :param member: A selector (cf below)
        :type member: basestring
        :param xp: An optional xpath filter
        :type xp: basestring
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
        l = self._select(member)
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
                self.update(new)

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

        if isinstance(query, six.string_types):
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
            return [item for item in lst if item is not None]

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
                    d['matched'] = m
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


class EmptyStore(SAMLStoreBase):

    def lookup(self, key):
        return list()

    def __init__(self):
        pass

    def update(self, **kwargs):
        return 0

    def size(self, **kwargs):
        return 0

    def collections(self):
        return []

    def reset(self):
        pass

    def entity_ids(self):
        return set()

    def select(self, **kwargs):
        return list()

    def search(self, **kwargs):
        return list()

    def merge(self, *args, **kwargs):
        return list()


class WhooshStore(SAMLStoreBase):

    def __init__(self):
        self.schema = Schema(scopes=KEYWORD(),
                             descr=TEXT(),
                             service_name=TEXT(),
                             service_descr=TEXT(),
                             keywords=KEYWORD())
        self.schema.add("object_id", ID(stored=True, unique=True))
        self.schema.add("entity_id", ID(stored=True, unique=True))
        for a in list(ATTRS.keys()):
            self.schema.add(a, KEYWORD())
        self._collections = set()
        from whoosh.filedb.filestore import RamStorage, FileStorage
        self.storage = RamStorage()
        self.storage.create()
        self.index = self.storage.create_index(self.schema)
        self.objects = dict()
        self.infos = dict()

    def dump(self):
        ix = self.storage.open_index()
        print(ix.schema)
        from whoosh.query import Every
        with ix.searcher() as searcher:
            for result in ix.searcher().search(Every('object_id')):
                print(result)

    def _index_prep(self, info):
        if 'entity_attributes' in info:
            for a, v in list(info.pop('entity_attributes').items()):
                info[a] = v
        for a, v in list(info.items()):
            if type(v) is not list and type(v) is not tuple:
                info[a] = [info.pop(a)]

            if a in ATTRS_INV:
                info[ATTRS_INV[a]] = info.pop(a)

        for a in list(info.keys()):
            if a not in self.schema.names():
                del info[a]

        for a, v in list(info.items()):
            info[a] = [six.text_type(vv) for vv in v]

    def _index(self, e, tid=None):
        info = entity_info(e)
        if tid is not None:
            info['collection_id'] = tid
        self._index_prep(info)
        id = six.text_type(object_id(e))
        # mix in tid here
        self.infos[id] = info
        self.objects[id] = e
        ix = self.storage.open_index()
        with ix.writer() as writer:
            writer.add_document(object_id=id, **info)
            writer.mergetype = writing.CLEAR

    def update(self, t, tid=None, ts=None, merge_strategy=None):
        relt = root(t)
        assert (relt is not None)
        ne = 0

        if relt.tag == "{%s}EntityDescriptor" % NS['md']:
            self._index(relt)
            ne += 1
        elif relt.tag == "{%s}EntitiesDescriptor" % NS['md']:
            if tid is None:
                tid = relt.get('Name')
            self._collections.add(tid)
            for e in iter_entities(t):
                self._index(e, tid=tid)
                ne += 1

        return ne

    def collections(self):
        return b2u(self._collections)

    def reset(self):
        self.__init__()

    def size(self, a=None, v=None):
        if a is None:
            return len(list(self.objects.keys()))
        elif a is not None and v is None:
            return len(self.attribute(a))
        else:
            return len(self.lookup("{!s}={!s}".format(a, v)))

    def _attributes(self):
        ix = self.storage.open_index()
        with ix.reader() as reader:
            for n in reader.indexed_field_names():
                if n in ATTRS:
                    yield b2u(ATTRS[n])

    def attributes(self):
        return b2u(list(self._attributes()))

    def attribute(self, a):
        if a in ATTRS_INV:
            n = ATTRS_INV[a]
            ix = self.storage.open_index()
            with ix.searcher() as searcher:
                return b2u(list(searcher.lexicon(n)))
        else:
            return []

    def lookup(self, key, raw=True, field="entity_id"):
        if key == 'entities' or key is None:
            if raw:
                return b2u(list(self.objects.values()))
            else:
                return b2u(list(self.infos.values()))

        from whoosh.qparser import QueryParser
        key = key.strip('+')
        key = key.replace('+', ' AND ')
        for uri, a in list(ATTRS_INV.items()):
            key = key.replace(uri, a)
        key = " {!s} ".format(key)
        key = re.sub("([^=]+)=(\S+)", "\\1:\\2", key)
        key = re.sub("{([^}]+)}(\S+)", "\\1:\\2", key)
        key = key.strip()

        qp = QueryParser("object_id", schema=self.schema)
        q = qp.parse(key)
        lst = set()
        with self.index.searcher() as searcher:
            results = searcher.search(q, limit=None)
            for result in results:
                if raw:
                    lst.add(self.objects[result['object_id']])
                else:
                    lst.add(self.infos[result['object_id']])

        return b2u(list(lst))


class MemoryStore(SAMLStoreBase):
    def __init__(self):
        self.md = dict()
        self.index = dict()
        self.entities = dict()

        for hn in DINDEX:
            self.index.setdefault(hn, {})
        self.index.setdefault('attr', {})

    def __str__(self):
        return repr(self.index)

    def clone(self):
        return deepcopy(self)

    def size(self, a=None, v=None):
        if a is None:
            return len(self.entities)
        elif a is not None and v is None:
            return len(list(self.index.setdefault('attr', {}).setdefault(a, {}).keys()))
        else:
            return len(self.index.setdefault('attr', {}).setdefault(a, {}).get(v, []))

    def attributes(self):
        return list(self.index.setdefault('attr', {}).keys())

    def attribute(self, a):
        return list(self.index.setdefault('attr', {}).setdefault(a, {}).keys())

    def _modify(self, entity, modifier):

        def _m(idx, vv):
            getattr(idx.setdefault(vv, EntitySet()), modifier)(entity)

        for hn in DINDEX:
            _m(self.index[hn], hash_id(entity, hn, False))

        attr_idx = self.index.setdefault('attr', {})
        for attr, values in list(entity_attribute_dict(entity).items()):
            vidx = attr_idx.setdefault(attr, {})
            for v in values:
                _m(vidx, v)

        vidx = attr_idx.setdefault(ATTRS['role'], {})
        if is_idp(entity):
            _m(vidx, "idp")
        if is_sp(entity):
            _m(vidx, "sp")

    def _index(self, entity):
        return self._modify(entity, "add")

    def _unindex(self, entity):
        return self._modify(entity, "discard")

    def _get_index(self, a, v):
        if a in DINDEX:
            return self.index[a].get(v, [])
        else:
            idx = self.index['attr'].setdefault(a, {})
            entities = idx.get(v, None)
            if entities is not None:
                return entities
            else:
                m = re.compile(v)
                entities = []
                for value, ents in list(idx.items()):
                    if m.match(value):
                        entities.extend(ents)
                return entities

    def reset(self):
        self.__init__()

    def collections(self):
        return list(self.md.keys())

    def update(self, t, tid=None, ts=None, merge_strategy=None):
        #log.debug("memory store update: %s: %s" % (repr(t), tid))
        relt = root(t)
        assert (relt is not None)
        ne = 0
        if relt.tag == "{%s}EntityDescriptor" % NS['md']:
            # log.debug("memory store setting entity descriptor")
            self._unindex(relt)
            self._index(relt)
            self.entities[relt.get('entityID')] = relt  # TODO: merge?
            if tid is not None:
                self.md[tid] = [relt.get('entityID')]
            ne += 1
            # log.debug("keys %s" % self.md.keys())
        elif relt.tag == "{%s}EntitiesDescriptor" % NS['md']:
            if tid is None:
                tid = relt.get('Name')
            lst = []
            for e in iter_entities(t):
                self.update(e)
                lst.append(e.get('entityID'))
                ne += 1
            self.md[tid] = lst

        return ne

    def lookup(self, key):
        #log.debug("memory store lookup: %s" % key)
        return self._lookup(key)

    def _lookup(self, key):
        if key == 'entities' or key is None:
            return list(self.entities.values())
        if '+' in key:
            key = key.strip('+')
            # log.debug("lookup intersection of '%s'" % ' and '.join(key.split('+')))
            hits = None
            for f in key.split("+"):
                f = f.strip()
                if hits is None:
                    hits = set(self._lookup(f))
                else:
                    other = self._lookup(f)
                    hits.intersection_update(other)

                if not hits:
                    #log.debug("empty intersection")
                    return []

            if hits is not None and hits:
                return list(hits)
            else:
                return []

        m = re.match("^(.+)=(.+)$", key)
        if m:
            return self._lookup("{%s}%s" % (m.group(1), str(m.group(2)).rstrip("/")))

        m = re.match("^{(.+)}(.+)$", key)
        if m:
            res = set()
            for v in str(m.group(2)).rstrip("/").split(';'):
                # log.debug("... adding %s=%s" % (m.group(1),v))
                res.update(self._get_index(m.group(1), v))
            return list(res)

        if key in self.entities:
            return [self.entities[key]]

        if key in self.md:
            log.debug("entities list %s: %d" % (key, len(self.md[key])))
            lst = []
            for entityID in self.md[key]:
                lst.extend(self.lookup(entityID))
            log.debug("returning {} entities".format(len(lst)))
            return lst

        return []


class RedisStore(SAMLStoreBase):
    from .decorators import deprecated

    @deprecated(reason="The RedisStore has seen almost no use and is not able to track API changes")
    def __init__(self, version=ts_now(), default_ttl=3600 * 24 * 4, respect_validity=True):
        self.rc = Redis(charset="utf-8")
        self.default_ttl = default_ttl
        self.respect_validity = respect_validity

    def _expiration(self, relt):
        ts = ts_now() + self.default_ttl
        if self.respect_validity:
            return valid_until_ts(relt, ts)

    def reset(self):
        self.rc.flushdb()

    def _drop_empty_av(self, attr, tag, ts):
        an = "#%s" % attr
        for c in self.rc.smembers(an):
            tn = "%s#members" % c
            self.rc.zremrangebyscore(tn, "-inf", ts)
            if not self.rc.zcard(tn) > 0:
                log.debug("dropping empty %s %s" % (attr, c))
                self.rc.srem(an, c)

    def update_entity(self, relt, t, tid, ts, p=None):
        if p is None:
            p = self.rc
        p.set("%s#metadata" % tid, dumptree(t))
        self._get_metadata.invalidate(tid)  # invalidate the parse-cache entry
        if ts is not None:
            p.expireat("%s#metadata" % tid, ts)
        nfo = dict(expires=ts)
        nfo.update(**relt.attrib)
        p.hmset(tid, nfo)
        if ts is not None:
            p.expireat(tid, ts)

    def membership(self, gid, mid, ts, p=None):
        if p is None:
            p = self.rc
        p.zadd("%s#members" % gid, mid, ts)
        # p.zadd("%s#groups", mid, gid, ts)
        p.sadd("#collections", gid)

    def attributes(self):
        return b2u(self.rc.smembers("#attributes"))

    def attribute(self, an):
        return b2u(self.rc.zrangebyscore("%s#values" % an, ts_now(), "+inf"))

    def collections(self):
        return b2u(self.rc.smembers("#collections"))

    def update(self, t, tid=None, ts=None, merge_strategy=None):  # TODO: merge ?
        #log.debug("redis store update: %s: %s" % (t, tid))
        relt = root(t)
        ne = 0
        if ts is None:
            ts = int(ts_now() + 3600 * 24 * 4)  # 4 days is the arbitrary default expiration
        if relt.tag == "{%s}EntityDescriptor" % NS['md']:
            if tid is None:
                tid = relt.get('entityID')
            with self.rc.pipeline() as p:
                self.update_entity(relt, t, tid, ts, p)
                entity_id = relt.get("entityID")
                if entity_id is not None:
                    self.membership("entities", entity_id, ts, p)
                for ea, eav in list(entity_attribute_dict(relt).items()):
                    for v in eav:
                        # log.debug("%s=%s" % (ea, v))
                        self.membership("{%s}%s" % (ea, v), tid, ts, p)
                        p.zadd("%s#values" % ea, v, ts)
                    p.sadd("#attributes", ea)

                for hn in ('sha1', 'sha256', 'md5'):
                    tid_hash = hex_digest(tid, hn)
                    p.set("{%s}%s#alias" % (hn, tid_hash), tid)
                    if ts is not None:
                        p.expireat(tid_hash, ts)
                p.execute()
            ne += 1
        elif relt.tag == "{%s}EntitiesDescriptor" % NS['md']:
            if tid is None:
                tid = relt.get('Name')
            ts = self._expiration(relt)
            with self.rc.pipeline() as p:
                self.update_entity(relt, t, tid, ts, p)
                for e in iter_entities(t):
                    ne += self.update(e, ts=ts)
                    entity_id = e.get("entityID")
                    if entity_id is not None:
                        self.membership(tid, entity_id, ts, p)
                        self.membership("entities", entity_id, ts, p)
                p.execute()
        else:
            raise ValueError("Bad metadata top-level element: '%s'" % root(t).tag)

        return ne

    def _members(self, k):
        mem = []
        if self.rc.exists("%s#members" % k):
            for entity_id in self.rc.zrangebyscore("%s#members" % k, ts_now(), "+inf"):
                mem.extend(self.lookup(entity_id))
        return mem

    @cached(ttl=30)
    def _get_metadata(self, key):
        return root(parse_xml(six.BytesIO(self.rc.get("%s#metadata" % key))))

    def lookup(self, key):
        log.debug("redis store lookup: %s" % key)
        if isinstance(key, six.binary_type):
            key = key.decode("utf-8")

        if '+' in key:
            hk = hex_digest(key)
            if not self.rc.exists("%s#members" % hk):
                self.rc.zinterstore("%s#members" % hk, ["%s#members" % k for k in key.split('+')], 'min')
                self.rc.expire("%s#members" % hk, 30)  # XXX bad juju - only to keep clients from hammering
            return b2u(self.lookup(hk))

        m = re.match("^(.+)=(.+)$", key)
        if m:
            return self.lookup("{%s}%s" % (m.group(1), m.group(2)))

        m = re.match("^{(.+)}(.+)$", key)
        if m and ';' in m.group(2):
            hk = hex_digest(key)
            if not self.rc.exists("%s#members" % hk):
                self.rc.zunionstore("%s#members" % hk,
                                    ["{%s}%s#members" % (m.group(1), v) for v in str(m.group(2)).split(';')], 'min')
                self.rc.expire("%s#members" % hk, 30)  # XXX bad juju - only to keep clients from hammering
            return b2u(self.lookup(hk))
        elif self.rc.exists("%s#alias" % key):
            return b2u(self.lookup(self.rc.get("%s#alias" % key)))
        elif self.rc.exists("%s#metadata" % key):
            return [b2u(self._get_metadata(key))]
        else:
            return b2u(self._members(key))

    def size(self):
        return self.rc.zcount("entities#members", ts_now(), "+inf")
