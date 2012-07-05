from UserDict import DictMixin
from lxml import etree
import dm.xmlsec.binding as xmlsec
import os
from copy import deepcopy
import urllib2
from pyff.decorators import retry
import logging

__author__ = 'leifj'

#NS={"md": "urn:oasis:names:tc:SAML:2.0:metadata","ds": "http://www.w3.org/2000/09/xmldsig#"}
NS={"md": "urn:oasis:names:tc:SAML:2.0:metadata"}

class MDRepository(DictMixin):
    def __init__(self):
        self.md = {}

    def parse_metadata(self,fn,verify=None):
        t = etree.parse(fn)
        if verify is not None:
            pass # TODO verify signature
        out = []
        for e in t.xpath("//md:EntityDescriptor",namespaces=NS):
            eid = e.get('entityID')
            if eid is None or len(eid) == 0:
                raise Exception,"Missing entityID in %s" % fn
            self.md[eid] = deepcopy(e)
            out.append(eid)
        return out

    def load_dir(self,dir):
        if not self.md.has_key(dir): #TODO: check cache-time and reload
            eids = []
            for top, dirs, files in os.walk(dir):
                for dn in dirs:
                    if dn.startswith("."):
                        dirs.remove(dn)
                for nm in files:
                    if nm.endswith(".xml"):
                        fn = os.path.join(top, nm)
                        eids.extend(self.parse_metadata(fn))
            self.md[dir] = self.entity_set(eids,dir)
        return self.md[dir]

    def lookup(self,member):
        if "!" in member:
            (src,xpath) = member.split("!")
            if src is None:
                pass
        else:
            return [self.md.get(member,None)]

    def entity_set(self,entities,name,cacheDuration=None,validUntil=None):
        attrs = dict(Name=name,nsmap=NS)
        if cacheDuration is not None:
            attrs['cacheDuration'] = cacheDuration
        if validUntil is not None:
            attrs['validUntil'] = validUntil
        t = etree.Element("{urn:oasis:names:tc:SAML:2.0:metadata}EntitiesDescriptor",**attrs)
        for member in entities:
            for ent in self.lookup(member):
                if ent is not None:
                    t.append(deepcopy(ent))

        return t

    def keys(self):
        return self.md.keys()

    def __getitem__(self, item):
        return self.md[item]

    def __setitem__(self, key, value):
        self.md[key] = value

    def __delitem__(self, key):
        del self.md[key]

    @retry(Exception,tries=10)
    def load_url(self,url=None,verify=None):
        if url is not None:
            logging.info("loading %s ..." % url)
            request = urllib2.Request(url)
            response = urllib2.urlopen(request)
            # TODO figure out what to stick in md
            self.parse_metadata(response,verify)