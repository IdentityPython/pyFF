try:
    from cStringIO import StringIO
except ImportError:
    print(" *** install cStringIO for better performance")
    from StringIO import StringIO

from copy import deepcopy
from datetime import datetime
import re
from iso8601 import iso8601
from redis import Redis
import time
from pyff.constants import NS, ATTRS
from pyff.decorators import cached
from pyff.utils import root, dumptree, duration2timedelta, totimestamp, parse_xml, hex_digest, hash_id, EntitySet, \
    entities_list, url2host, subdomains, has_tag, iter_entities
from pyff.logs import log


def is_idp(entity):
    return has_tag(entity, "{%s}IDPSSODescriptor" % NS['md'])


def is_sp(entity):
    return has_tag(entity, "{%s}SPSSODescriptor" % NS['md'])


def _domains(entity):
    domains = [url2host(entity.get('entityID'))]
    for d in entity.iter("{%s}DomainHint" % NS['mdui']):
        if d.text not in domains:
            domains.append(d.text)
    return domains


def entity_attribute_dict(entity):
    d = {}
    for ea in entity.iter("{%s}EntityAttributes" % NS['mdattr']):
        a = ea.find(".//{%s}Attribute" % NS['saml'])
        if a is not None:
            an = a.get('Name', None)
            if a is not None:
                values = [v.text.strip() for v in a.iter("{%s}AttributeValue" % NS['saml'])]
                d[an] = values

    d[ATTRS['role']] = []

    dlist = []
    for dn in _domains(entity):
        for sub in subdomains(dn):
            dlist.append(sub)

    d[ATTRS['domain']] = dlist

    if is_idp(entity):
        d[ATTRS['role']].append('idp')
    if is_sp(entity):
        d[ATTRS['role']].append('sp')

    return d


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

    def size(self):
        raise NotImplementedError()

    def collections(self):
        raise NotImplementedError()

    def update(self, t, tid=None, ts=None, merge_strategy=None):
        raise NotImplementedError()

    def reset(self):
        raise NotImplementedError()

    def set(self, key, mapping):
        raise NotImplementedError()

    def get(self, key):
        raise NotImplementedError()


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

    def size(self):
        return len(self.entities)

    def attributes(self):
        return self.index.setdefault('attr', {}).keys()

    def attribute(self, a):
        return self.index.setdefault('attr', {}).setdefault(a, {}).keys()

    def _index(self, entity):
        attr_idx = self.index.setdefault('attr', {})
        nd = 0
        for hn in DINDEX:
            hid = hash_id(entity, hn, False)
            # log.debug("computing index %s(%s) = %s" % (hn, entity.get('entityID'), hid))
            self.index[hn].setdefault(hid, EntitySet())
            self.index[hn][hid].add(entity)
            nd += 1

        na = 0
        for attr, values in entity_attribute_dict(entity).iteritems():
            for v in values:
                vidx = attr_idx.setdefault(attr, {})
                vidx.setdefault(v, EntitySet())
                na += 1
                vidx[v].add(entity)

        vidx = attr_idx.setdefault(ATTRS['role'], {})
        if is_idp(entity):
            vidx.setdefault('idp', EntitySet())
            na += 1
            vidx['idp'].add(entity)

        if is_sp(entity):
            vidx.setdefault('sp', EntitySet())
            na += 1
            vidx['sp'].add(entity)

        # log.debug("indexed %s (%d attributes, %d digests)" % (entity.get('entityID'), na, nd))

    def _unindex(self, entity):
        attr_idx = self.index.setdefault('attr', {})
        nd = 0
        for hn in DINDEX:
            # log.debug("computing %s" % hn)
            hid = hash_id(entity, hn, False)
            self.index[hn].setdefault(hid, EntitySet())
            self.index[hn][hid].discard(entity)
            nd += 1

        na = 0
        for attr, values in entity_attribute_dict(entity).iteritems():
            # log.debug("indexing %s on %s" % (attr,entity.get('entityID')))
            for v in values:
                vidx = attr_idx.setdefault(attr, {})
                vidx.setdefault(v, EntitySet())
                na += 1
                vidx[v].discard(entity)

        vidx = attr_idx.setdefault(ATTRS['role'], {})
        if is_idp(entity):
            vidx.setdefault('idp', EntitySet())
            na += 1
            vidx['idp'].discard(entity)

        if is_sp(entity):
            vidx.setdefault('sp', EntitySet())
            na += 1
            vidx['sp'].discard(entity)

        # log.debug("(un)indexed %s (%d attributes, %d digests)" % (entity.get('entityID'), na, nd))

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
                for value, ents in idx.iteritems():
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
        assert(relt is not None)
        ne = 0
        if relt.tag == "{%s}EntityDescriptor" % NS['md']:
            # log.debug("memory store setting entity descriptor")
            self._unindex(relt)
            self._index(relt)
            self.entities[relt.get('entityID')] = relt  # TODO: merge?
            if tid is not None:
                self.md[tid] = relt
            ne += 1
            # log.debug("keys %s" % self.md.keys())
        elif relt.tag == "{%s}EntitiesDescriptor" % NS['md']:
            if tid is None:
                tid = relt.get('Name')
            for e in iter_entities(t):
                self.update(e)
                ne += 1
            self.md[tid] = relt

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
            return self._lookup("{%s}%s" % (m.group(1), m.group(2).rstrip("/")))

        m = re.match("^{(.+)}(.+)$", key)
        if m:
            res = set()
            for v in m.group(2).rstrip("/").split(';'):
                # log.debug("... adding %s=%s" % (m.group(1),v))
                res.update(self._get_index(m.group(1), v))
            return list(res)

        # log.debug("trying null index lookup %s" % key)
        l = self._get_index("null", key)
        if l:
            return list(l)

        # log.debug("trying main index lookup %s: " % key)
        if key in self.md:
            # log.debug("entities list %s: %s" % (key, self.md[key]))
            return entities_list(self.md[key])

        return []


class RedisStore(StoreBase):
    def __init__(self, version=_now(), default_ttl=3600*24*4, respect_validity=True):
        self.rc = Redis()
        self.default_ttl = default_ttl
        self.respect_validity = respect_validity

    def _expiration(self, relt):
        ts = _now()+self.default_ttl

        if self.respect_validity:
            valid_until = relt.get("validUntil", None)
            if valid_until is not None:
                dt = iso8601.parse_date(valid_until)
                if dt is not None:
                    ts = totimestamp(dt)

            cache_duration = relt.get("cacheDuration", None)
            if cache_duration is not None:
                dt = datetime.utcnow() + duration2timedelta(cache_duration)
                if dt is not None:
                    ts = totimestamp(dt)

        return ts

    def reset(self):
        self.rc.flushdb()

    def periodic(self, stats):
        now = _now()
        stats['Last Periodic Maintenance'] = now
        log.debug("periodic maintentance...")
        self.rc.zremrangebyscore("members", "-inf", now)
        for c in self.rc.smembers("#collections"):
            self.rc.zremrangebyscore("%s#members", "-inf", now)
            if not self.rc.zcard("%s#members" % c) > 0:
                log.debug("dropping empty collection %s" % c)
                self.rc.srem("#collections", c)
        for an in self.rc.smembers("#attributes"):
            self.rc.zremrangebyscore("%s#values", "-inf", now)
            if not self.rc.zcard("%s#members" % an) > 0:
                log.debug("dropping empty attribute %s" % an)
                self.rc.srem("#attributes", an)

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
        #p.zadd("%s#groups", mid, gid, ts)
        p.sadd("#collections", gid)

    def attributes(self):
        return self.rc.smembers("#attributes")

    def attribute(self, an):
        return self.rc.zrangebyscore("%s#values" % an, _now(), "+inf")

    def collections(self):
        return self.rc.smembers("#collections")

    def set(self, key, mapping):
        self.rc.hmset(key, mapping)

    def get(self, key):
        return self.rc.hgetall(key)

    def update(self, t, tid=None, ts=None, merge_strategy=None):  # TODO: merge ?
        log.debug("redis store update: %s: %s" % (t, tid))
        relt = root(t)
        ne = 0
        if ts is None:
            ts = int(_now()+3600*24*4)    # 4 days is the arbitrary default expiration
        if relt.tag == "{%s}EntityDescriptor" % NS['md']:
            if tid is None:
                tid = relt.get('entityID')
            with self.rc.pipeline() as p:
                self.update_entity(relt, t, tid, ts, p)
                entity_id = relt.get("entityID")
                if entity_id is not None:
                    self.membership("entities", entity_id, ts, p)
                for ea, eav in entity_attribute_dict(relt).iteritems():
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
                self.rc.zunionstore("%s#members" % hk, ["{%s}%s#members" % (m.group(1), v) for v in m.group(2).split(';')], 'min')
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
