"""

This is the implementation of the active repository of SAML metadata. The 'local' and 'remote' pipes operate on this.

"""
from StringIO import StringIO

from datetime import datetime
import hashlib
from UserDict import DictMixin
from lxml import etree
from lxml.builder import ElementMaker
from lxml.etree import DocumentInvalid
import os
import re
from copy import deepcopy
from pyff.logs import log
from pyff.utils import schema, URLFetch, filter_lang
import xmlsec
from pyff.constants import NS
import traceback
import threading
from Queue import Queue


__author__ = 'leifj'

def _is_self_signed_err(ebuf):
    for e in ebuf:
        if e['func'] == 'xmlSecOpenSSLX509StoreVerify' and re.match('err=18',e['message']):
            return True
    return False

etree.set_default_parser(etree.XMLParser(resolve_entities=False))

def _e(error_log):
    return "\n".join(filter(lambda x: ":WARNING:" not in x,["%s" % e for e in error_log]))

class MDRepository(DictMixin):
    def __init__(self):
        """
        A class representing a set of sets of SAML metadata.
        """
        self.md = {}
        self.index = {}
        self.create_time = datetime.now()

    def is_idp(self,entity):
        return bool(entity.find(".//{%s}IDPSSODescriptor" % NS['md']))

    def is_sp(self,entity):
        return bool(entity.find(".//{%s}SPSSODescriptor" % NS['md']))

    def display(self,entity):

        for displayName in filter_lang(entity.findall(".//{%s}DisplayName" % NS['mdui'])):
            return displayName.text

        for serviceName in filter_lang(entity.findall(".//{%s}ServiceName" % NS['md'])):
            return serviceName.text

        for organizationDisplayName in filter_lang(entity.findall(".//{%s}OrganizationDisplayName" % NS['md'])):
            return organizationDisplayName.text

        return entity.get('entityID')

    def __iter__(self):
        for t in [self.md[url] for url in self.md.keys()]:
            for entity in t.findall(".//{%s}EntityDescriptor" % NS['md']):
                yield entity

    def sha1_id(self,entity,prefix=True):
        entityID = entity.get('entityID')
        m = hashlib.sha1()
        m.update(entityID)
        if prefix:
            return "{sha1}%s" % m.hexdigest()
        else:
            return m.hexdigest()

    def stats(self):
        return {
            'number_of_pieces': len(self),
            'create_time': self.create_time
        }

    def search(self,query):
        def _strings(e):
            lst = [e.get('entityID')]
            for attr in ['{%s}OrganizationName' % NS['md'],
                         '{%s}OrganizationDisplayName' % NS['md'],
                         '{%s}DisplayName' % NS['mdui'],
                         '{%s}ServiceName' % NS['md']]:
                lst.extend(e.findall(attr))
            return lst

        def _match(e):
            return len([query in str for str in filter(lambda s: s is not None,_strings(e))]) > 0

        return [{'label': self.display(e),
                 'value': e.get('entityID'),
                 'id': self.sha1_id(e)} for e in filter(_match,self.__iter__())]

    def sane(self):
        return len(self.md) > 0

    def index_lookup(self,id,hash="sha1"):
        idx = self.index.get(hash,None)
        if idx is None:
            return None
        return idx.get(id,None)

    def extensions(self,e):
        ext = e.find("{%s}Extensions" % NS['md'])
        if ext is None:
            e.insert(0,etree.Element("{%s}Extensions" % NS['md']))
            ext = e.find("{%s}Extensions" % NS['md'])
        return ext

    def annotate(self,e,category,title,message,source=None):
        if e.tag != "{%s}EntityDescriptor" % NS['md'] and \
           e.tag != "{%s}EntitiesDescriptor" % NS['md']:
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

    def fetch_metadata(self,resources,qsize=5,timeout=30):
        def producer(q, resources):
            for url,verify,id in resources:
                log.debug("Starting fetcher for %s" % url)
                thread = URLFetch(url,verify,id)
                thread.start()
                q.put(thread, True)

        def consumer(q, njobs):
            nfinished = 0
            while nfinished < njobs:
                try:
                    thread = q.get(True)
                    thread.join(timeout)
                    if thread.ex is None:
                        self.parse_metadata(StringIO(thread.result),key=thread.verify,url=thread.id)
                    else:
                        log.error("Error fetching %s: %s" (thread.url,thread.ex))
                except Exception,ex:
                    traceback.print_exc()
                    log.error("Unexpected error in fetch_metadata: %s. Continuing anyway..." % ex)
                finally:
                    nfinished += 1

        q = Queue(qsize)
        prod_thread = threading.Thread(target=producer, args=(q, resources))
        cons_thread = threading.Thread(target=consumer, args=(q, len(resources)))
        prod_thread.start()
        cons_thread.start()
        prod_thread.join()
        cons_thread.join()

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
        log.debug("parsing %s" % src_desc)
        try:
            t = etree.parse(fn,parser=etree.XMLParser(resolve_entities=False))
            schema().assertValid(t)
        except DocumentInvalid,ex:
            log.debug(_e(ex.error_log))
            raise ValueError("XML schema validation failed")
        except Exception,ex:
            log.debug(_e(schema().error_log))
            log.error(ex)
            if fail_on_error:
                raise ex
            return []
        if key is not None:
            try:
                log.debug("verifying signature using %s" % key)
                xmlsec.verify(t,key)
            except Exception,ex:
                tb = traceback.format_exc()
                print tb
                log.error(ex)
                return []
        if url is None:
            top = t.xpath("//md:EntitiesDescriptor",namespaces=NS)
            if top is not None and len(top) == 1:
                url = top[0].get("Name",None)
        if url is not None:
            self[url] = t
        # we always clean incoming ID
        # compute sha1 index
        idx = self.index.get('sha1',None)
        if idx is None:
            idx = {}
            self.index['sha1'] = idx
        for e in t.findall(".//{%s}EntityDescriptor" % NS['md']):
            if e.attrib.has_key('ID'):
                del e.attrib['ID']
            id = self.sha1_id(e,prefix=False)
            idx[id] = e
            log.debug("indexed %s as %s" % (e.get('entityID'),id))

        #for e in t.xpath("//md:EntityDescriptor",namespaces=NS):
        #    if e.attrib.has_key('ID'):
        #        del e.attrib['ID']
        return t.findall(".//{%s}EntityDescriptor" % NS['md'])

        #return t.xpath("//md:EntityDescriptor",namespaces=NS)
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
                log.debug("resolving %s filtered by %s" % (m,xp))
                lst.extend(self._lookup(m,xp))
            return lst
        elif hasattr(member,'xpath'):
            log.debug("xpath filter %s <- %s" % (xp,member))
            return member.xpath(xp,namespaces=NS)
        elif type(member) is str or type(member) is unicode:
            if "!" in member:
                (src,xp) = member.split("!")
                if len(src) == 0:
                    src = None
                    log.debug("filtering using %s" % xp)
                else:
                    log.debug("selecting %s filtered by %s" % (src,xp))
                return self._lookup(src,xp)
            else:
                log.debug("basic lookup %s (%s)" % (member,{True:'exists',False:'does not exist'}[self.has_key(member)]))
                return self._lookup(self.get(member,None),xp)
        elif hasattr(member,'__iter__') and type(member) is not dict:
            if not len(member):
                member = self.keys()
            return [self._lookup(m,xp) for m in member]
        else:
            raise Exception,"What about %s ??" % member

    def lookup(self,member,xp=None):
        log.debug("lookup %s" % member)
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
        t = etree.Element("{%s}EntitiesDescriptor" % NS['md'],**attrs)
        nent = 0
        seen = {} # TODO make better de-duplication
        for member in entities:
            for ent in self.lookup(member):
                entityID = ent.get('entityID',None)
                if (ent is not None) and (entityID is not None) and (not seen.get(entityID,False)):
                    t.append(deepcopy(ent))
                    seen[entityID] = True
                    nent += 1

        log.debug("selecting %d from %d entities before validation" % (nent,len(entities)))

        if not nent:
            return None

        if validate:
            try:
                schema().assertValid(t)
            except DocumentInvalid,ex:
                log.debug(_e(ex.error_log))
                raise ValueError("XML schema validation failed")
        return t

    def error_set(self,url,title,ex):
        """
        Creates an "error" EntitiesDescriptor - empty but for an annotation about the error that occured
        """
        t = etree.Element("{%s}EntitiesDescriptor" % NS['md'],Name=url,nsmap=NS)
        self.annotate(t,"error",title,ex,source=url)

    def keys(self):
        return self.md.keys()

    def __getitem__(self, item):
        return self.md[item]

    def __setitem__(self, key, value):
        self.md[key] = value

    def __delitem__(self, key):
        del self.md[key]
