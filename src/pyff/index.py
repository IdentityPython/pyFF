import hashlib
from collections import MutableSet
import re
from pyff.constants import NS, DIGESTS, ATTRS
from pyff.logs import log

__author__ = 'leifj'

def hash_id(entity,hn='sha1',prefix=True):
    entityID = entity
    if hasattr(entity,'get'):
        entityID = entity.get('entityID')

    if hn == 'null':
        return entityID

    if not hasattr(hashlib,hn):
        raise ValueError("Unknown digest '%s'" % hn)

    m = getattr(hashlib,hn)()
    m.update(entityID)
    if prefix:
        return "{%s}%s" % (hn,m.hexdigest())
    else:
        return m.hexdigest()

def entity_attribute_dict(entity):
    d = {}
    for ea in entity.findall(".//{%s}EntityAttributes" % NS['mdattr']):
        a = ea.find(".//{%s}Attribute" % NS['saml'])
        if a is not None:
            an = a.get('Name',None)
            if a is not None:
                values = [v.text for v in a.findall(".//{%s}AttributeValue" % NS['saml'])]
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
    def add(self,entity):
        """
        Index the entity

        :param entity:
        :return:
        """
        pass

    def get(self,a,v):
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

class EntitySet(MutableSet):

    def __init__(self,initial=None):
        self._e = dict()
        if initial is not None:
            for e in initial:
                self.add(e)

    def add(self,value):
        self._e[value.get('entityID')] = value

    def discard(self, value):
        del self._e[value.get('entityID')]

    def __iter__(self):
        for e in self._e.values():
            yield e

    def __len__(self):
        return len(self._e.keys())

    def __contains__(self, item):
        return item.get('entityID') in self._e.keys()

class MemoryIndex(MDIndex):

    def __init__(self):
        self.index = {}
        for hn in DIGESTS:
            self.index.setdefault(hn,{})
        self.index.setdefault('attr',{})

    def __str__(self):
        return repr(self.index)

    def size(self):
        return len(self.index['null'])

    def attributes(self):
        return self.index.setdefault('attr',{}).keys()

    def attribute(self,a):
        return self.index.setdefault('attr',{}).setdefault(a,{}).keys()

    def add(self,entity):
        attr_idx = self.index.setdefault('attr',{})
        nd = 0
        for hn in DIGESTS:
            #log.debug("computing %s" % hn)
            id = hash_id(entity,hn,False)
            self.index[hn].setdefault(id,EntitySet())
            self.index[hn][id].add(entity)
            nd += 1

        na = 0
        for attr,values in entity_attribute_dict(entity).iteritems():
            for v in values:
                vidx = attr_idx.setdefault(attr,{})
                vidx.setdefault(v,EntitySet())
                na += 1
                vidx[v].add(entity)

        vidx = attr_idx.setdefault(ATTRS['role'],{})
        if is_idp(entity):
            vidx.setdefault('idp',EntitySet())
            na += 1
            vidx['idp'].add(entity)

        if is_sp(entity):
            vidx.setdefault('sp',EntitySet())
            na += 1
            vidx['sp'].add(entity)

        #log.debug("indexed %s (%d attributes, %d digests)" % (entity.get('entityID'),na,nd))

    def remove(self,entity):
        attr_idx = self.index.setdefault('attr',{})
        nd = 0
        for hn in DIGESTS:
            #log.debug("computing %s" % hn)
            id = hash_id(entity,hn,False)
            self.index[hn].setdefault(id,EntitySet())
            self.index[hn][id].discard(entity)
            nd += 1

        na = 0
        for attr,values in entity_attribute_dict(entity).iteritems():
            #log.debug("indexing %s on %s" % (attr,entity.get('entityID')))
            for v in values:
                vidx = attr_idx.setdefault(attr,{})
                vidx.setdefault(v,EntitySet())
                na += 1
                vidx[v].discard(entity)

        vidx = attr_idx.setdefault(ATTRS['role'],{})
        if is_idp(entity):
            vidx.setdefault('idp',EntitySet())
            na += 1
            vidx['idp'].discard(entity)

        if is_sp(entity):
            vidx.setdefault('sp',EntitySet())
            na += 1
            vidx['sp'].discard(entity)

        #log.debug("(un)indexed %s (%d attributes, %d digests)" % (entity.get('entityID'),na,nd))

    def get(self,a,v):
        if a in DIGESTS:
            return self.index[a].get(v,[])
        else:
            idx = self.index['attr'].setdefault(a,{})
            entities = idx.get(v,None)
            if entities is not None:
                return entities
            else:
                m = re.compile(v)
                entities = []
                for value,ents in idx.iteritems():
                    if m.match(value):
                        entities.extend(ents)
                return entities