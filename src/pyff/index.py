from collections import MutableSet
import re
from pyff.constants import NS, DIGESTS, ATTRS
from pyff.utils import hash_id, EntitySet

__author__ = 'leifj'


def entity_attribute_dict(entity):
    d = {}
    for ea in entity.findall(".//{%s}EntityAttributes" % NS['mdattr']):
        a = ea.find(".//{%s}Attribute" % NS['saml'])
        if a is not None:
            an = a.get('Name', None)
            if a is not None:
                values = [v.text.strip() for v in a.findall(".//{%s}AttributeValue" % NS['saml'])]
                d[an] = values
    return d


def is_idp(entity):
    return bool(entity.find(".//{%s}IDPSSODescriptor" % NS['md']) is not None)


def is_sp(entity):
    return bool(entity.find(".//{%s}SPSSODescriptor" % NS['md']) is not None)


class MDIndex(object):
    """
    Interface for metadata index providers
    """

    def add(self, entity):
        """
        Index the entity

        :param entity:
        :return:
        """
        pass

    def get(self, a, v):
        """
        Obtains a list of entities that have a=b.

        :param a:
        :param v:
        :return:
        """
        pass

    def remove(self, entity):
        """
        Removes the entity from the index.

        :param entity:
        """
        pass

def _role(e):
    if is_idp(e):
        return 'idp'
    elif is_sp(e):
        return 'sp'
    else:
        return 'unknown'


def entity_index():
    i = OIndex(lambda e: e.get('entityID'))
    for hn in DIGESTS:
        i.add_index(hn, lambda e: hash_id(e, hn, False))
    i.add_index('role', _role)
    i.add_index('')
    return i


class OIndex(object):
    def __init__(self, id_cb):
        self.obj = {}
        self.idx = {'_id': id_cb}

    def add_index(self, name, value_cb):
        self.idx[name] = value_cb
        self.obj[name] = {}
        for o in self._obj('_id'):
            self.add(o, [name])

    def _obj(self, n):
        return self.obj.setdefault(n, {})

    def add(self, o, idx_ns=None):
        if idx_ns is None:
            idx_ns = self.idx.keys()

        for idx_n in idx_ns:
            idx_v = self.idx[idx_n](o)
            idx_o = self._obj(idx_n)
            for old_v in idx_o.keys():
                if o in idx_o[old_v] and old_v != idx_v:
                    idx_o[old_v].discard(o)

            eset = idx_o.setdefault(idx_v, EntitySet())
            eset.add(o)

    def remove(self, o, idx_ns=None):
        if idx_ns is None:
            idx_ns = self.idx.keys()

        for idx_n in idx_ns:
            idx_v = self.idx[idx_n](o)
            eset = self._obj(idx_n).setdefault(idx_v, EntitySet())
            eset.discard(o)

    def get(self, a, v):
        if not a in self.idx:
            raise ValueError("Unknown index: %s" % a)

        entities = self.obj[a].get(v, None)
        if entities is not None:
            return entities
        else:
            m = re.compile(v)
            entities = []
            for value, ents in self.obj[a].iteritems():
                if m.match(value):
                    entities.extend(ents)
            return entities

    def size(self):
        return len(self._obj('_id').keys())

    def keys(self):
        return self.idx.keys()

    def values(self, a):
        return self.idx.setdefault(a, {}).keys()


class MemoryIndex(MDIndex):
    def __init__(self):
        self.index = {}
        for hn in DIGESTS:
            self.index.setdefault(hn, {})
        self.index.setdefault('attr', {})

    def __str__(self):
        return repr(self.index)

    def size(self):
        return len(self.index['null'])

    def attributes(self):
        return self.index.setdefault('attr', {}).keys()

    def attribute(self, a):
        return self.index.setdefault('attr', {}).setdefault(a, {}).keys()

    def add(self, entity):
        attr_idx = self.index.setdefault('attr', {})
        nd = 0
        for hn in DIGESTS:
            hid = hash_id(entity, hn, False)
            #log.debug("computing index %s(%s) = %s" % (hn, entity.get('entityID'), hid))
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

            #log.debug("indexed %s (%d attributes, %d digests)" % (entity.get('entityID'), na, nd))
            #log.debug(self.index)

    def remove(self, entity):
        attr_idx = self.index.setdefault('attr', {})
        nd = 0
        for hn in DIGESTS:
            #log.debug("computing %s" % hn)
            hid = hash_id(entity, hn, False)
            self.index[hn].setdefault(hid, EntitySet())
            self.index[hn][hid].discard(entity)
            nd += 1

        na = 0
        for attr, values in entity_attribute_dict(entity).iteritems():
            #log.debug("indexing %s on %s" % (attr,entity.get('entityID')))
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

            #log.debug("(un)indexed %s (%d attributes, %d digests)" % (entity.get('entityID'),na,nd))

    def get(self, a, v):
        if a in DIGESTS:
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
