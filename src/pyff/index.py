import hashlib
from pyff.constants import NS
from pyff.logs import log

__author__ = 'leifj'

def hash_id(entity,hn='sha1',prefix=True):
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
    return bool(entity.find(".//{%s}IDPSSODescriptor" % NS['md']))

def is_sp(entity):
    return bool(entity.find(".//{%s}SPSSODescriptor" % NS['md']))

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

class MemoryIndex(MDIndex):

    DIGESTS = ['sha1','md5','null']

    def __init__(self):
        self.index = {}
        for hn in MemoryIndex.DIGESTS:
            self.index.setdefault(hn,{})
        self.index.setdefault('attr',{})

    def __str__(self):
        return repr(self.index)

    def size(self):
        return len(self.index['null'])

    def add(self,entity):
        attr_idx = self.index.setdefault('attr',{})
        nd = 0
        for hn in MemoryIndex.DIGESTS:
            #log.debug("computing %s" % hn)
            id = hash_id(entity,hn,False)
            self.index[hn].setdefault(id,[])
            self.index[hn][id].append(entity)
            nd += 1

        na = 0
        for attr,values in entity_attribute_dict(entity).iteritems():
            na += 1
            for v in values:
                vidx = attr_idx.setdefault(attr,{})
                vidx.setdefault(v,[])
                vidx[v].append(entity)

        vidx = attr_idx.setdefault('role',{})
        if is_idp(entity):
            vidx.setdefault('idp',[])
            vidx['idp'].append(entity)

        if is_idp(entity):
            vidx.setdefault('sp',[])
            vidx['sp'].append(entity)


        log.debug("indexed %s (%d attributes, %d digests)" % (entity.get('entityID'),na,nd))

    def get(self,a,v):
        if a in MemoryIndex.DIGESTS:
            return self.index[a].get(v,[])
        else:
            idx = self.index['attr'].setdefault(a,{})
            return idx.get(v,[])