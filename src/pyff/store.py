import json
import operator
import os
import re
import shutil
import time
from datetime import datetime, timedelta
from io import BytesIO
from threading import ThreadError

import ipaddress
import six
from cachetools.func import ttl_cache
from redis_collections import Dict, Set
from whoosh.fields import ID, KEYWORD, NGRAMWORDS, Schema
from whoosh.filedb.filestore import FileStorage
from whoosh.qparser import MultifieldParser, QueryParser
from whoosh.writing import CLEAR

from pyff import merge_strategies
from pyff.constants import ATTRS, ATTRS_INV, NS, config
from pyff.logs import get_log
from pyff.resource import IconHandler
from pyff.samlmd import (
    EntitySet,
    discojson,
    entitiesdescriptor,
    entity_attribute_dict,
    entity_icon_url,
    entity_simple_info,
    entity_simple_summary,
    find_entity,
    find_merge_strategy,
    is_idp,
    is_sp,
    iter_entities,
    object_id,
)
from pyff.utils import (
    LRUProxyDict,
    avg_domain_distance,
    b2u,
    dumptree,
    hash_id,
    hex_digest,
    is_past_ttl,
    is_text,
    load_callable,
    parse_xml,
    redis,
    root,
)

log = get_log(__name__)

DINDEX = ('sha1', 'sha256', 'null')


def make_store_instance(*args, **kwargs):
    new_store = load_callable(config.store_class)
    return new_store(*args, **kwargs)


def make_icon_store_instance(*args, **kwargs):
    new_store = load_callable(config.icon_store_class)
    return new_store(*args, **kwargs)


class Unpickled(object):
    def _pickle(self, data):
        return data

    def _unpickle(self, data):
        return data


class StringSet(Set):
    _pickle = Unpickled._pickle
    _unpickle = Unpickled._unpickle
    _pickle_3 = _pickle
    _unpickle_3 = _unpickle
    _pickle_value = _pickle
    _unpickle_value = _unpickle
    _pickle_key = _pickle
    _unpickle_key = _unpickle


class StringDict(Dict):
    _pickle = Unpickled._pickle
    _unpickle = Unpickled._unpickle
    _pickle_3 = _pickle
    _unpickle_3 = _unpickle
    _pickle_value = _pickle
    _unpickle_value = _unpickle
    _pickle_key = _pickle
    _unpickle_key = _unpickle


class JSONDict(Dict):
    _pickle_key = Unpickled._pickle
    _unpickle_key = Unpickled._unpickle

    def _pickle(self, x):
        return json.dumps(x)

    def _unpickle(self, x):
        return json.loads(b2u(x))

    _pickle_3 = _pickle
    _unpickle_3 = _unpickle
    _pickle_value = _pickle
    _unpickle_value = _unpickle


class XMLDict(Dict):
    _pickle_key = Unpickled._pickle
    _unpickle_key = Unpickled._unpickle

    def _pickle(self, data):
        return dumptree(data)

    def _unpickle(self, pickled_data):
        return root(parse_xml(BytesIO(pickled_data)))

    _pickle_3 = _pickle
    _unpickle_3 = _unpickle
    _pickle_value = _pickle
    _unpickle_value = _unpickle


class IconStore(object):
    def __init__(self):
        pass

    def size(self):
        raise NotImplementedError()

    def lookup(self, uri):
        raise NotImplementedError()

    def update(self, uri, img, info=None):
        raise NotImplementedError()

    def reset(self):
        raise NotImplementedError()

    def is_valid(self, url):
        return True

    def __call__(self, *args, **kwargs):
        watched = kwargs.pop('watched', None)
        scheduler = kwargs.pop('scheduler', None)
        log.debug("about to schedule icon refresh on {} using {}".format(self, scheduler.state))
        if watched is not None and scheduler is not None:
            urls = []
            for r in watched.walk():
                log.debug("looking at {}".format(r.url))
                if r.t is not None:
                    for e in iter_entities(r.t):
                        ico = entity_icon_url(e)
                        if ico is not None and 'url' in ico and not ico['url'].startswith('data:'):
                            urls.append(ico)
            if config.load_icons_async:
                now = datetime.now()
                start = now + timedelta(seconds=20)
                job = scheduler.add_job(
                    IconStore._load_icons,
                    args=[self, urls],
                    id="load_icons",
                    next_run_time=start,
                    name="load_icons",
                    max_instances=1,
                    coalesce=False,
                )
                log.debug(job)
            else:
                self._load_icons(urls)

    def _load_icons(self, urls):
        tbs = []
        for u in [ico['url'] for ico in urls]:
            if not self.is_valid(u):
                tbs.append(u)

        log.debug("fetching {} icons".format(len(tbs)))
        if len(tbs) > 0:
            icon_handler = IconHandler(icon_store=self, name="Icons")
            icon_handler.schedule(tbs)
            try:
                icon_handler.done.acquire()
                icon_handler.done.wait()
            finally:
                icon_handler.done.release()
            icon_handler.fetcher.stop()
            icon_handler.fetcher.join()


class MemoryIconStore(IconStore):
    def __init__(self):
        super().__init__()
        self.icons = {}

    def lookup(self, uri):
        return self.icons.get(uri, None)

    def update(self, uri, img, info=None):
        self.icons[uri] = img

    def reset(self):
        self.icons = {}

    def size(self):
        return len(self.icons)


class RedisIconStore(IconStore):
    def __init__(self, **kwargs):
        super().__init__()
        self._name = kwargs.pop('name', config.store_name)
        self._redis = kwargs.pop('redis', redis())
        clear = bool(kwargs.pop('clear', config.store_clear))
        self._setup()
        if clear:
            self.reset()

    def _setup(self):
        if not self._redis:
            self._redis = redis()  # XXX test cases won't get correctly unpicked because of this
        self.icons = LRUProxyDict(
            JSONDict(key="{}_icons".format(self._name), redis=self._redis, writeback=True), maxsize=config.cache_size
        )

    def lookup(self, uri):
        nfo = self.icons.get(uri, None)
        if nfo is not None and 'data' in nfo:
            return nfo['data']
        return None

    def is_valid(self, url):
        nfo = self.icons.get(url, None)
        if nfo is None or 'last_seen' not in nfo or is_past_ttl(int(nfo['last_seen']), ttl=config.cache_ttl_icons):
            return False
        return True

    def update(self, uri, img, info=None):
        self.icons[uri] = dict(data=img, info=info, last_seen=int(time.time()))

    def __getstate__(self):
        return dict(_name=self._name, _redis=None)

    def __setstate__(self, state):
        state.setdefault('_redis', None)
        self.__dict__.update(state)
        self._setup()

    def reset(self):
        self._redis.delete("{}_icons".format(self._name))

    def size(self):
        return len(self.icons)


class SAMLStoreBase(object):
    def lookup(self, key):
        raise NotImplementedError()

    def __iter__(self):
        for e in self.lookup("entities"):
            log.debug("**** yield entityID=%s" % e.get('entityID'))
            yield e

    def size(self, a=None, v=None):
        raise NotImplementedError()

    def collections(self):
        raise NotImplementedError()

    def update(self, t, tid=None, etag=None, lazy=True):
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

    def __call__(self, *args, **kwargs):
        watched = kwargs.pop('watched', None)
        scheduler = kwargs.pop('scheduler', None)
        if watched is not None and scheduler is not None:
            for r in watched.walk():
                if r.t is None and len(r.children) > 0:
                    r.t = entitiesdescriptor(list(filter(lambda c: c is not None, [c.t for c in r.children])), name=r.name, validate=True, filter_invalid=True)
                if r.t is not None:
                    self.update(r.t, tid=r.name, etag=r.etag)
                else:
                    log.debug(f'Nothing to update for resource {r.name} with {len(r.children)} children')

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

    def search(self, query=None, path=None, entity_filter=None, related=None):
        """
        :param query: A string to search for.
        :param path: The repository collection (@Name) to search in - None for search in all collections
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
            for attr in [
                '{%s}DisplayName' % NS['mdui'],
                '{%s}ServiceName' % NS['md'],
                '{%s}OrganizationDisplayName' % NS['md'],
                '{%s}OrganizationName' % NS['md'],
                '{%s}Keywords' % NS['mdui'],
                '{%s}Scope' % NS['shibmd'],
            ]:
                lst.extend([s.text for s in elt.iter(attr)])
            lst.append(elt.get('entityID'))
            return [item for item in lst if item is not None]

        def _ip_networks(elt):
            return [ipaddress.ip_network(x.text) for x in elt.iter('{%s}IPHint' % NS['mdui'])]

        def _match(qq, elt):
            for q in qq:
                q = q.strip()
                if ':' in q or '.' in q:
                    try:
                        nets = _ip_networks(elt)
                        for net in nets:
                            if ipaddress.ip_address(q) in net:
                                return net
                    except ValueError:
                        pass

                if q is not None and len(q) > 0:
                    tokens = _strings(elt)
                    for tstr in tokens:
                        if q in tstr.lower():
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

        return res


class EmptyStore(SAMLStoreBase):
    def lookup(self, key):
        return list()

    def __init__(self, *args, **kwargs):
        pass

    def update(self, *args, **kwargs):
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


class RedisWhooshStore(SAMLStoreBase):  # TODO: This needs a gc mechanism for keys (uuids)
    def json_dict(self, name):
        return LRUProxyDict(
            JSONDict(key='{}_{}'.format(self._name, name), redis=self._redis, writeback=True), maxsize=config.cache_size
        )

    def xml_dict(self, name):
        return LRUProxyDict(
            XMLDict(key='{}_{}'.format(self._name, name), redis=self._redis, writeback=True), maxsize=config.cache_size
        )

    def __init__(self, *args, **kwargs):
        self._dir = kwargs.pop('directory', '.whoosh')
        clear = bool(kwargs.pop('clear', config.store_clear))
        self._name = kwargs.pop('name', config.store_name)
        self._redis = kwargs.pop('redis', redis())
        if clear:
            shutil.rmtree(self._dir)
        now = datetime.now()
        self._last_index_time = now
        self._last_modified = now
        self._setup()
        if clear:
            self.reset()

    def _setup(self):
        self._redis = getattr(self, '_redis', None)
        if not self._redis:
            self._redis = redis()  # XXX test cases won't get correctly unpicked because of this
        self.schema = Schema(content=NGRAMWORDS(stored=False))
        self.schema.add("object_id", ID(stored=True, unique=True))
        self.schema.add("entity_id", ID(stored=True, unique=True))
        self.schema.add('sha1', ID(stored=True, unique=True))
        for a in list(ATTRS.keys()):
            self.schema.add(a, KEYWORD())
        self.objects = self.xml_dict('objects')
        self.parts = self.json_dict('parts')
        self.storage = FileStorage(os.path.join(self._dir, self._name))
        try:
            self.index = self.storage.open_index(schema=self.schema)
        except BaseException as ex:
            log.warning(ex)
            self.storage.create()
            self.index = self.storage.create_index(self.schema)
            self._reindex()

    def __getstate__(self):
        state = dict()
        for p in ('_dir', '_name', '_last_index_time', '_last_modified'):
            state[p] = getattr(self, p)
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)
        self._setup()

    def __call__(self, *args, **kwargs):
        watched = kwargs.pop('watched', None)
        scheduler = kwargs.pop('scheduler', None)
        if watched is not None and scheduler is not None:
            super(RedisWhooshStore, self).__call__(watched=watched, scheduler=scheduler)
            log.debug("indexing using {}".format(scheduler))
            if scheduler is not None:  # and self._last_modified > self._last_index_time and :
                scheduler.add_job(
                    RedisWhooshStore._reindex,
                    args=[self],
                    max_instances=1,
                    coalesce=True,
                    misfire_grace_time=2 * config.update_frequency,
                )

    def _reindex(self):
        log.debug("indexing the store...")
        self._last_index_time = datetime.now()
        seen = set()
        refs = set([b2u(s) for s in self.objects.keys()])
        parts = self.parts.values()
        for ref in refs:
            for part in parts:
                if ref in part['items']:
                    seen.add(ref)

        ix = self.storage.open_index()
        lock = ix.lock("reindex")
        try:
            log.debug("waiting for index lock")
            lock.acquire(True)
            log.debug("got index lock")
            with ix.writer() as writer:
                for ref in refs:
                    if ref not in seen:
                        log.debug("removing unseen ref {}".format(ref))
                        del self.objects[ref]
                        del self.parts[ref]

                log.debug("updating index")
                for e in self.objects.values():
                    info = self._index_prep(entity_simple_info(e))
                    ref = object_id(e)
                    writer.add_document(object_id=ref, **info)

                writer.mergetype = CLEAR
        finally:
            try:
                log.debug("releasing index lock")
                lock.release()
            except ThreadError as ex:
                pass

    def dump(self):
        ix = self.storage.open_index()
        from whoosh.query import Every

        with ix.searcher() as searcher:
            for result in ix.searcher().search(Every('object_id')):
                print(result)

    def _index_prep(self, info):
        res = dict()
        if 'entity_attributes' in info:
            for a, v in list(info.pop('entity_attributes').items()):
                info[a] = v

        content = " ".join(
            filter(
                lambda x: x is not None,
                [info.get(x, '') for x in ('service_name', 'title', 'domain', 'keywords', 'scopes')],
            )
        )
        res['content'] = content.strip()
        for a, v in info.items():
            k = a
            if a in ATTRS_INV:
                k = ATTRS_INV[a]

            if k in self.schema.names():
                if type(v) in (list, tuple):
                    res[k] = " ".join([vv.lower() for vv in v])
                elif type(v) in six.string_types:
                    res[k] = info[a].lower()
        res['sha1'] = hash_id(info['entity_id'], prefix=False)
        return res

    def update(self, t, tid=None, etag=None, lazy=True):
        relt = root(t)
        assert relt is not None

        if relt.tag == "{%s}EntityDescriptor" % NS['md']:
            ref = object_id(relt)
            parts = None
            if ref in self.parts:
                parts = self.parts[ref]
            if etag is not None and (parts is None or parts.get('etag', None) != etag):
                self.parts[ref] = {'id': relt.get('entityID'), 'etag': etag, 'count': 1, 'items': [ref]}
                self.objects[ref] = relt
                self._last_modified = datetime.now()
        elif relt.tag == "{%s}EntitiesDescriptor" % NS['md']:
            if tid is None:
                tid = relt.get('Name')
            if etag is None:
                etag = hex_digest(dumptree(t, pretty_print=False), 'sha256')
            parts = None
            if tid in self.parts:
                parts = self.parts[tid]
            if parts is None or parts.get('etag', None) != etag:
                items = set()
                for e in iter_entities(t):
                    ref = object_id(e)
                    items.add(ref)
                    self.objects[ref] = e
                self.parts[tid] = {'id': tid, 'count': len(items), 'etag': etag, 'items': list(items)}
                self._last_modified = datetime.now()

        if not lazy:
            self._reindex()

    @ttl_cache(ttl=config.cache_ttl, maxsize=config.cache_size)
    def collections(self):
        return [b2u(ref) for ref in self.parts.keys()]

    def reset(self):
        for k in ('{}_{}'.format(self._name, 'parts'), '{}_{}'.format(self._name, 'objects')):
            self._redis.delete('{}_{}'.format(self._name, 'parts'))
            self._redis.delete('{}_{}'.format(self._name, 'objects'))

    def size(self, a=None, v=None):
        if a is None:
            return len(self.objects.keys())
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

    def _prep_key(self, key):
        # import pdb; pdb.set_trace()
        key = key.strip('+')
        key = key.replace('+', ' AND ')
        key = key.replace('-', ' AND NOT ')
        for uri, a in list(ATTRS_INV.items()):
            key = key.replace(uri, a)
        key = " {!s} ".format(key)
        key = re.sub("([^=]+)=(\S+)", "\\1:\\2", key)
        key = re.sub("{([^}]+)}(\S+)", "\\1:\\2", key)
        key = key.strip()

        return key

    def _entities(self):
        lst = set()
        for ref_data in self.parts.values():
            for ref in ref_data['items']:
                e = self.objects.get(ref, None)
                if e is not None:
                    lst.add(e)

        return b2u(list(lst))

    @ttl_cache(ttl=config.cache_ttl, maxsize=config.cache_size)
    def lookup(self, key):
        if key == 'entities' or key is None:
            return self._entities()

        bkey = six.b(key)
        if bkey in self.objects:
            return [self.objects.get(bkey)]

        if bkey in self.parts:
            res = []
            part = self.parts.get(bkey)
            for item in part['items']:
                res.extend(self.lookup(item))
            return res

        key = self._prep_key(key)
        qp = QueryParser("object_id", schema=self.schema)
        q = qp.parse(key)
        lst = set()
        with self.index.searcher() as searcher:
            results = searcher.search(q, limit=None)
            for result in results:
                e = self.objects.get(result['object_id'], None)
                if e is not None:
                    lst.add(e)

        return b2u(list(lst))

    @ttl_cache(ttl=config.cache_ttl, maxsize=config.cache_size)
    def search(self, query=None, path=None, entity_filter=None, related=None):
        if entity_filter:
            query = "{!s} AND {!s}".format(query, entity_filter)
        query = self._prep_key(query)
        qp = MultifieldParser(['content', 'domain'], schema=self.schema)
        q = qp.parse(query)
        lst = set()
        with self.index.searcher() as searcher:
            results = searcher.search(q, limit=None)
            log.debug(results)
            for result in results:
                lst.add(result['object_id'])

        res = list()
        for ref in lst:
            e = self.objects.get(ref, None)
            if e is not None:
                res.append(discojson(e))
        return res


class MemoryStore(SAMLStoreBase):
    def __init__(self, *args, **kwargs):
        self.md = dict()
        self.index = dict()
        self.entities = dict()

        for hn in DINDEX:
            self.index.setdefault(hn, {})
        self.index.setdefault('attr', {})

    def __str__(self):
        return repr(self.index)

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

    def update(self, t, tid=None, etag=None, lazy=True):
        relt = root(t)
        assert relt is not None
        if relt.tag == "{%s}EntityDescriptor" % NS['md']:
            self._unindex(relt)
            self._index(relt)
            self.entities[relt.get('entityID')] = relt  # TODO: merge?
            if tid is not None:
                self.md[tid] = [relt.get('entityID')]
        elif relt.tag == "{%s}EntitiesDescriptor" % NS['md']:
            if tid is None:
                tid = relt.get('Name')
            lst = []
            for e in iter_entities(t):
                self.update(e)
                lst.append(e.get('entityID'))
            self.md[tid] = lst

    def lookup(self, key):
        return self._lookup(key)

    def _lookup(self, key):
        if key == 'entities' or key is None:
            return list(self.entities.values())

        if key in self.entities:
            return [self.entities[key]]

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
                    # log.debug("empty intersection")
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

        if key in self.md:
            log.debug("entities list %s: %d" % (key, len(self.md[key])))
            lst = []
            for entityID in self.md[key]:
                lst.extend(self.lookup(entityID))
            log.debug("returning {} entities".format(len(lst)))
            return lst

        return []
