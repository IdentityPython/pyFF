from datetime import datetime
from UserDict import DictMixin
from lxml import etree
from lxml.builder import ElementMaker
from lxml.etree import DocumentInvalid
import os
import re
from copy import deepcopy
import logging
from pyff.utils import schema
import xmlsec
from pyff.constants import NS
import traceback

__author__ = 'leifj'

def _is_self_signed_err(ebuf):
    for e in ebuf:
        if e['func'] == 'xmlSecOpenSSLX509StoreVerify' and re.match('err=18',e['message']):
            return True
    return False

etree.set_default_parser(etree.XMLParser(resolve_entities=False))

class MDRepository(DictMixin):
    def __init__(self):
        """
        A class representing a set of sets of SAML metadata.
        """
        self.md = {}

    def extensions(self,e):
        ext = e.find("{%s}Extensions" % NS['md'])
        if ext is None:
            e.insert(0,etree.Element("{%s}Extensions" % NS['md']))
            ext = e.find("{%s}Extensions" % NS['md'])
        return ext

    def annotate(self,e,category,title,message,source=None):
        if e.tag != "{urn:oasis:names:tc:SAML:2.0:metadata}EntityDescriptor" and \
           e.tag != "{urn:oasis:names:tc:SAML:2.0:metadata}EntitiesDescriptor":
            raise ValueError("I can only annotate EntityDescriptor or EntitiesDescriptor elements")
        subject = e.get('Name',e.get('entityID',None))
        atom = ElementMaker(nsmap={'atom':'http://www.w3.org/2005/Atom'},namespace='http://www.w3.org/2005/Atom')
        args = [atom.published("%s" % datetime.now().isoformat()),
                atom.link(href=subject,rel="saml-metadata-subject")]
        if source is not None:
                args.append(atom.link(href=source,rel="saml-metadata-source"))
        args.extend([atom.title(title),
                     atom.category(term=category),
                     atom.content(message,type="text/plain")])
        self.extensions(e).insert(0,atom.entry(*args))


    def parse_metadata(self,fn,key=None,url=None,fail_on_error=False):
        """
Parse a piece of XML and split it up into EntityDescriptor elements. Each such element
is stored in the MDRepository instance.

:param fn: a file-like object containing SAML metadata
:param key: a certificate (file) or a SHA1 fingerprint to use for signature verification
        """
        src_desc = "%s" % fn
        if url is not None:
            src_desc = url
        logging.debug("parsing %s" % src_desc)
        try:
            t = etree.parse(fn,parser=etree.XMLParser(resolve_entities=False))
            schema().assertValid(t)
        except DocumentInvalid,ex:
            logging.debug(ex.error_log)
            raise ValueError("XML schema validation failed")
        except Exception,ex:
            logging.DEBUG(schema().error_log)
            logging.error(ex)
            if fail_on_error:
                raise ex
            return []
        if key is not None:
            try:
                logging.debug("verifying signature using %s" % key)
                xmlsec.verify(t,key)
            except Exception,ex:
                tb = traceback.format_exc()
                print tb
                logging.error(ex)
                return []
        if url is None:
            top = t.xpath("//md:EntitiesDescriptor",namespaces=NS)
            if top is not None and len(top) == 1:
                url = top[0].get("Name",None)
        if url is not None:
            self[url] = t
        # we always clean incoming ID
        for e in t.xpath("//md:EntityDescriptor",namespaces=NS):
            if e.attrib.has_key('ID'):
                del e.attrib['ID']
        return t.xpath("//md:EntityDescriptor",namespaces=NS)
        #for e in t.xpath("//md:EntityDescriptor",namespaces=NS):
        #    eid = e.get('entityID')
        #    if eid is None or len(eid) == 0:
        #        raise Exception,"Missing entityID in %s" % fn
        #    #self.md[eid] = deepcopy(e)
        #    out.append(eid)
        #return out

    def load_dir(self,dir,ext=".xml",url=None):
        """
Traverse a directory tree looking for metadata.

:param dir: A directory to walk.
:param ext: Include files with this extension (default .xml)

Files ending in the specified extension are included. Directories starting with '.' are excluded.
        """
        if url is None:
            url = dir
        if not self.md.has_key(dir): #TODO: check cache-time and reload
            entities = []
            for top, dirs, files in os.walk(dir):
                for dn in dirs:
                    if dn.startswith("."):
                        dirs.remove(dn)
                for nm in files:
                    if nm.endswith(ext):
                        fn = os.path.join(top, nm)
                        entities.extend(self.parse_metadata(fn,fail_on_error=True)) #local metadata is assumed to be ok
            self.md[url] = self.entity_set(entities,url)
        return self.md[url]

    def _lookup(self,member,xp=None):
        """
Find a (set of) EntityDescriptor element(s) based on the specified 'member' expression.

:param member: Either an entity, URL or a filter expression.
        """
        if xp is None:
            xp = "//md:EntityDescriptor"
        if member is None:
            lst = []
            for m in self.keys():
                lst.extend(self._lookup(m,xp))
            return lst
        elif hasattr(member,'xpath'):
            return member.xpath(xp,namespaces=NS)
        elif type(member) is str or type(member) is unicode:
            if "!" in member:
                (src,xp) = member.split("!")
                logging.debug("selecting %s filtered by %s" % (src,xp))
                return self._lookup(src,xp)
            else:
                return self._lookup(self.get(member,None),xp)
        elif hasattr(member,'__iter__') and type(member) is not dict:
            if not len(member):
                member = self.keys()
            return [self._lookup(m,xp) for m in member]
        else:
            raise Exception,"What about %s ??" % member

    def lookup(self,member,xp=None):
        logging.debug("lookup %s" % member)
        l = self._lookup(member,xp)
        return list(set(filter(lambda x: x is not None,l)))


    def entity_set(self,entities,name,cacheDuration=None,validUntil=None,validate=True):
        """
Produce an EntityDescriptors set from a list of entities. Optional Name, cacheDuration and validUntil are affixed.

:param entities: a set of entities specifiers (lookup is used to find entities from this set)
:param name: the @Name attribute
:param cacheDuration: an XML timedelta expression, eg PT1H for 1hr
:param validUntil: a relative time eg 2w 4d 1h for 2 weeks, 4 days and 1hour from now.
        """
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

        if validate:
            try:
                schema().assertValid(t)
            except DocumentInvalid,ex:
                logging.debug(ex.error_log)
                raise ValueError("XML schema validation failed")
        return t

    def error_set(self,url,title,ex):
        """
        Creates an "error" EntitiesDescriptor - empty but for an annotation about the error that occured
        """
        t = etree.Element("{urn:oasis:names:tc:SAML:2.0:metadata}EntitiesDescriptor",Name=url,nsmap=NS)
        self.annotate(t,"error",title,ex,source=url)

    def keys(self):
        return self.md.keys()

    def __getitem__(self, item):
        return self.md[item]

    def __setitem__(self, key, value):
        self.md[key] = value

    def __delitem__(self, key):
        del self.md[key]
