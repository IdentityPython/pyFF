
from six import StringIO
import time
from copy import deepcopy
import re
from redis import Redis
from .constants import NS, ATTRS, ATTRS_INV
from .decorators import cached
from .logs import log
from .utils import root, dumptree, parse_xml, hex_digest, hash_id, valid_until_ts
from .samlmd import EntitySet, iter_entities, entity_attribute_dict, is_sp, is_idp, entity_info, object_id
from whoosh.fields import Schema, TEXT, ID, KEYWORD, STORED, BOOLEAN
from whoosh import writing
import six

def _now():
    return int(time.time())


DINDEX = ('sha1', 'sha256', 'null')


class StoreBase(object):
    def lookup(self, key):
        raise NotImplementedError()

    def clone(self):
        return self

    def __iter__(self):
        for e in self.lookup("entities"):
            log.debug("**** yield entityID=%s" % e.get('entityID'))
            yield e

    def periodic(self, stats):
        pass

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


class WhooshStore(StoreBase):

    def __init__(self):
        self.schema = Schema(scopes=KEYWORD(),
                             descr=TEXT(),
                             service_name=TEXT(),
                             service_descr=TEXT(),
                             keywords=KEYWORD())
        self.schema.add("object_id", ID(stored=True, unique=True))
        self.schema.add("entity_id", ID(stored=True, unique=True))
        for a in ATTRS.keys():
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
            for a,v in info.pop('entity_attributes').items():
                info[a] = v
        for a,v in info.items():
            if type(v) is not list and type(v) is not tuple:
               info[a] = [info.pop(a)]

            if a in ATTRS_INV:
                info[ATTRS_INV[a]] = info.pop(a)

        for a in info.keys():
            if not a in self.schema.names():
                del info[a]

        for a,v in info.items():
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
        return self._collections

    def reset(self):
        self.__init__()

    def size(self, a=None, v=None):
        if a is None:
            return len(self.objects.keys())
        elif a is not None and v is None:
            return len(self.attribute(a))
        else:
            return len(self.lookup("{!s}={!s}".format(a,v)))

    def _attributes(self):
        ix = self.storage.open_index()
        with ix.reader() as reader:
            for n in reader.indexed_field_names():
                if n in ATTRS:
                    yield ATTRS[n]

    def attributes(self):
        return list(self._attributes())

    def attribute(self, a):
        if a in ATTRS_INV:
            n = ATTRS_INV[a]
            ix = self.storage.open_index()
            with ix.searcher() as searcher:
                return list(searcher.lexicon(n))
        else:
            return []

    def lookup(self, key, raw=True, field="entity_id"):
        if key == 'entities' or key is None:
            if raw:
                return self.objects.values()
            else:
                return self.infos.values()

        from whoosh.qparser import QueryParser
        #import pdb; pdb.set_trace()
        key = key.strip('+')
        key = key.replace('+', ' AND ')
        for uri,a in ATTRS_INV.items():
            key = key.replace(uri,a)
        key = " {!s} ".format(key)
        key = re.sub("([^=]+)=(\S+)","\\1:\\2",key)
        key = re.sub("{([^}]+)}(\S+)", "\\1:\\2", key)
        key = key.strip()

        qp = QueryParser("object_id", schema=self.schema)
        q = qp.parse(key)
        lst = set()
        with self.index.searcher() as searcher:
            results = searcher.search(q,limit=None)
            for result in results:
                if raw:
                    lst.add(self.objects[result['object_id']])
                else:
                    lst.add(self.infos[result['object_id']])

        return list(lst)


class MemoryStore(StoreBase):
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
            return len(self.index.setdefault('attr', {}).setdefault(a, {}).keys())
        else:
            return len(self.index.setdefault('attr', {}).setdefault(a, {}).get(v, []))

    def attributes(self):
        return self.index.setdefault('attr', {}).keys()

    def attribute(self, a):
        return self.index.setdefault('attr', {}).setdefault(a, {}).keys()

    def _modify(self, entity, modifier):

        def _m(idx, vv):
            getattr(idx.setdefault(vv, EntitySet()), modifier)(entity)

        for hn in DINDEX:
            _m(self.index[hn], hash_id(entity, hn, False))

        attr_idx = self.index.setdefault('attr', {})
        for attr, values in entity_attribute_dict(entity).items():
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
                for value, ents in idx.items():
                    if m.match(value):
                        entities.extend(ents)
                return entities

    def reset(self):
        self.__init__()

    def collections(self):
        return self.md.keys()

    def update(self, t, tid=None, ts=None, merge_strategy=None):
        # log.debug("memory store update: %s: %s" % (repr(t), tid))
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
        # log.debug("memory store lookup: %s" % key)
        return self._lookup(key)

    def _lookup(self, key):
        if key == 'entities' or key is None:
            return self.entities.values()
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
                    log.debug("empty intersection")
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

        l = self._get_index("null", key)
        if l:
            return list(l)

        if key in self.md:
            # log.debug("entities list %s: %s" % (key, self.md[key]))
            lst = []
            for entityID in self.md[key]:
                lst.extend(self.lookup(entityID))
            return lst

        return []


class RedisStore(StoreBase):
    def __init__(self, version=_now(), default_ttl=3600 * 24 * 4, respect_validity=True):
        self.rc = Redis()
        self.default_ttl = default_ttl
        self.respect_validity = respect_validity

    def _expiration(self, relt):
        ts = _now() + self.default_ttl
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

    def periodic(self, stats):
        now = _now()
        stats['Last Periodic Maintenance'] = now
        log.debug("periodic maintentance...")
        self.rc.zremrangebyscore("members", "-inf", now)
        self._drop_empty_av("collections", "members", now)
        self._drop_empty_av("attributes", "values", now)

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
        return self.rc.smembers("#attributes")

    def attribute(self, an):
        return self.rc.zrangebyscore("%s#values" % an, _now(), "+inf")

    def collections(self):
        return self.rc.smembers("#collections")

    def update(self, t, tid=None, ts=None, merge_strategy=None):  # TODO: merge ?
        log.debug("redis store update: %s: %s" % (t, tid))
        relt = root(t)
        ne = 0
        if ts is None:
            ts = int(_now() + 3600 * 24 * 4)  # 4 days is the arbitrary default expiration
        if relt.tag == "{%s}EntityDescriptor" % NS['md']:
            if tid is None:
                tid = relt.get('entityID')
            with self.rc.pipeline() as p:
                self.update_entity(relt, t, tid, ts, p)
                entity_id = relt.get("entityID")
                if entity_id is not None:
                    self.membership("entities", entity_id, ts, p)
                for ea, eav in entity_attribute_dict(relt).items():
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
            for entity_id in self.rc.zrangebyscore("%s#members" % k, _now(), "+inf"):
                mem.extend(self.lookup(entity_id))
        return mem

    @cached(ttl=30)
    def _get_metadata(self, key):
        return root(parse_xml(StringIO(self.rc.get("%s#metadata" % key))))

    def lookup(self, key):
        log.debug("redis store lookup: %s" % key)
        if '+' in key:
            hk = hex_digest(key)
            if not self.rc.exists("%s#members" % hk):
                self.rc.zinterstore("%s#members" % hk, ["%s#members" % k for k in key.split('+')], 'min')
                self.rc.expire("%s#members" % hk, 30)  # XXX bad juju - only to keep clients from hammering
            return self.lookup(hk)

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
            return self.lookup(hk)
        elif self.rc.exists("%s#alias" % key):
            return self.lookup(self.rc.get("%s#alias" % key))
        elif self.rc.exists("%s#metadata" % key):
            return [self._get_metadata(key)]
        else:
            return self._members(key)

    def size(self):
        return self.rc.zcount("entities#members", _now(), "+inf")
