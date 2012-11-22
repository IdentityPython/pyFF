"""

This is the implementation of the active repository of SAML metadata. The 'local' and 'remote' pipes operate on this.

"""
from StringIO import StringIO

from datetime import datetime
import hashlib
import urllib
from UserDict import DictMixin
from lxml import etree
from lxml.builder import ElementMaker
from lxml.etree import DocumentInvalid
import os
import re
from copy import deepcopy
from pyff import merge_strategies
import pyff.index
from pyff.logs import log
from pyff.utils import schema, URLFetch, filter_lang, root, duration2timedelta
import xmlsec
from pyff.constants import NS, NF_URI
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
    def __init__(self,index=pyff.index.MemoryIndex(),metadata_cache_enabled=False,min_cache_ttl="PT5M"):
        """
        A class representing a set of sets of SAML metadata.
        """
        self.md = {}
        self.index = index
        self.metadata_cache_enabled = metadata_cache_enabled
        self.min_cache_ttl = min_cache_ttl
        self.respect_cache_duration = True
        self.default_cache_duration = "PT10M"
        self.retry_limit = 5

    def is_idp(self,entity):
        return bool(entity.find(".//{%s}IDPSSODescriptor" % NS['md']) is not None)

    def is_sp(self,entity):
        return bool(entity.find(".//{%s}SPSSODescriptor" % NS['md']) is not None)

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

    def sha1_id(self,e):
        return pyff.index.hash_id(e,'sha1')

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
                 'id': pyff.index.hash_id(e,'sha1')} for e in filter(_match,self.__iter__())]

    def sane(self):
        return len(self.md) > 0

    def extensions(self,e):
        ext = e.find(".//{%s}Extensions" % NS['md'])
        if ext is None:
            ext = etree.Element("{%s}Extensions" % NS['md'])
            e.insert(0,ext)
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
        self.extensions(e).append(atom.entry(*args))

    def entity_attributes(self,e):
        ext = self.extensions(e)
        #log.debug(ext)
        ea = ext.find(".//{%s}EntityAttributes" % NS['mdattr'])
        if ea is None:
            ea = etree.Element("{%s}EntityAttributes" % NS['mdattr'])
            ext.append(ea)
        return ea

    def eattribute(self,e,attr,nf):
        ea = self.entity_attributes(e)
        #log.debug(ea)
        a = ea.xpath(".//saml:Attribute[@NameFormat='%s' and @Name='%s']" % (nf,attr),namespaces=NS)
        if a is None or len(a) == 0:
            a = etree.Element("{%s}Attribute" % NS['saml'])
            a.set('NameFormat',nf)
            a.set('Name',attr)
            ea.append(a)
        else:
            a = a[0]
        #log.debug(etree.tostring(self.extensions(e)))
        return a

    def set_entity_attributes(self,e,d,nf=NF_URI):
        if e.tag != "{%s}EntityDescriptor" % NS['md']:
            raise ValueError("I can only add EntityAttribute(s) to EntityDescriptor elements")

        #log.debug("set %s" % d)
        for attr,value in d.iteritems():
            #log.debug("set %s to %s" % (attr,value))
            a = self.eattribute(e,attr,nf)
            #log.debug(etree.tostring(a))
            velt = etree.Element("{%s}AttributeValue" % NS['saml'])
            velt.text = value
            a.append(velt)
            #log.debug(etree.tostring(a))

    def fetch_metadata(self,resources,qsize=5,timeout=60,stats={}):
        def producer(q,resources):
            for url,verify,id in resources:
                log.debug("Starting fetcher for %s" % url)
                thread = URLFetch(url,verify,id,enable_cache=self.metadata_cache_enabled)
                thread.start()
                q.put(thread, True)

        def consumer(q,njobs,stats):
            nfinished = 0

            def _retry(thread):
                if thread.tries < self.retry_limit:
                    log.info("Retry (%d/%d) fetch %s" % (thread.tries+1,self.retry_limit,thread.url))
                    # retry w/o cache enabled
                    new_thread = URLFetch(thread.url,thread.verify,thread.id,enable_cache=False)
                    new_thread.start()
                    q.put(new_thread,True)
                    return 1
                else:
                    log.error("Retry limitd (%d) reached for %s - giving up" % (self.retry_limit,thread.url))
                    return 0

            while nfinished < njobs:
                info = None
                try:
                    log.debug("waiting for next thread to finish...")
                    thread = q.get(True)
                    thread.join(timeout)

                    info = {
                        'Time Spent': thread.time(),
                        'Status': thread.resp.status,
                    }

                    if thread.ex:
                        info['URL Exception'] = ex
                    else:
                        if thread.result is not None:
                            info['Bytes'] = len(thread.result)
                        info['Cached'] = thread.cached
                        info['Date'] = str(thread.date)
                        info['Last-Modified'] = str(thread.last_modified)

                    if thread.ex is None and thread.result is not None:
                        xml = thread.result.strip()
                        t = self.parse_metadata(StringIO(xml),key=thread.verify,url=thread.id)
                        cacheDuration = self.default_cache_duration
                        if self.respect_cache_duration:
                            cacheDuration = root(t).get('cacheDuration',self.default_cache_duration)
                        offset = duration2timedelta(cacheDuration)

                        if thread.cached:
                            if thread.last_modified + offset < datetime.now() - duration2timedelta(self.min_cache_ttl):
                                nfinished -= _retry(thread)
                            else:
                                log.debug("got cached metadata (last-modified: %s)" % thread.last_modified)
                                ne = self.import_metadata(t,url=thread.id)
                                info['Number of Entities'] = ne
                        else:
                            log.debug("got fresh metadata (date: %s)" % thread.date)
                            ne = self.import_metadata(t,url=thread.id)
                            info['Number of Entities'] = ne
                        info['Cache Expiration Time'] = str(thread.last_modified + offset)
                    else:
                        log.warn("Error fetching %s: %s" % (thread.url,thread.ex))
                        nfinished -= _retry(thread)
                except Exception,ex:
                    traceback.print_exc()
                    log.error("Error fetching %s." % ex)
                    nfinished -= _retry(thread)
                    info['Exception'] = ex
                finally:
                    nfinished += 1
                    if info is not None:
                        stats[thread.url] = info

        q = Queue(qsize)
        prod_thread = threading.Thread(target=producer, args=(q, resources))
        cons_thread = threading.Thread(target=consumer, args=(q, len(resources), stats))
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
            return None
        if key is not None:
            try:
                log.debug("verifying signature using %s" % key)
                xmlsec.verify(t,key)
            except Exception,ex:
                tb = traceback.format_exc()
                print tb
                log.error(ex)
                return None

        return t

    def import_metadata(self,t,url=None):
        if url is None:
            top = t.xpath("//md:EntitiesDescriptor",namespaces=NS)
            if top is not None and len(top) == 1:
                url = top[0].get("Name",None)
        if url is not None:
            self[url] = t
            # we always clean incoming ID
        # add to the index
        ne = 0
        for e in t.findall(".//{%s}EntityDescriptor" % NS['md']):
            if e.attrib.has_key('ID'):
                del e.attrib['ID']
            self.index.add(e)
            ne += 1
        return ne

    def entities(self,t=None):
        if t is None:
            return []
        else:
            return t.findall(".//{%s}EntityDescriptor" % NS['md'])

    def load_dir(self,dir,ext=".xml",url=None):
        """
Traverse a directory tree looking for metadata.

:param dir: A directory to walk.
:param ext: Include files with this extension (default .xml)

Files ending in the specified extension are included. Directories starting with '.' are excluded.
        """
        if url is None:
            url = dir
        if not self.md.has_key(dir):
            entities = []
            for top, dirs, files in os.walk(dir):
                for dn in dirs:
                    if dn.startswith("."):
                        dirs.remove(dn)
                for nm in files:
                    if nm.endswith(ext):
                        fn = os.path.join(top, nm)
                        t = self.parse_metadata(fn,fail_on_error=True)
                        entities.extend(self.entities(t)) #local metadata is assumed to be ok
            self.import_metadata(self.entity_set(entities,url))
        return self.md[url]

    def _lookup(self,member,xp=None):
        """
Find a (set of) EntityDescriptor element(s) based on the specified 'member' expression.

:param member: Either an entity, URL or a filter expression.
        """

        def _hash(hn,str):
            if hn == 'null':
                return str
            if not hasattr(hashlib,hn):
                raise ValueError("Unknown digest mechanism: '%s'" % hn)
            hash_m = getattr(hashlib,hn)
            h = hash_m()
            h.update(str)
            return h.hexdigest()

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
            log.debug("string lookup %s" % member)

            if '+' in member:
                member = member.strip('+')
                log.debug("lookup intersection of '%s'" % ' and '.join(member.split('+')))
                hits = None
                for f in member.split("+"):
                    f = f.strip()
                    if hits is None:
                        hits = set(self._lookup(f,xp))
                    else:
                        other = self._lookup(f,xp)
                        hits.intersection_update(other)

                    if not hits:
                        log.debug("empty intersection")
                        return []

                if hits is not None and hits:
                    return list(hits)
                else:
                    return []

            if "!" in member:
                (src,xp) = member.split("!")
                if len(src) == 0:
                    src = None
                    log.debug("filtering using %s" % xp)
                else:
                    log.debug("selecting %s filtered by %s" % (src,xp))
                return self._lookup(src,xp)

            m = re.match("^\{(.+)\}(.+)$",member)
            if m:
                log.debug("attribute-value match: %s='%s'" % (m.group(1),m.group(2)))
                return self.index.get(m.group(1),m.group(2).rstrip("/"))

            m = re.match("^(.+)=(.+)$",member)
            if m:
                log.debug("attribute-value match: %s='%s'" % (m.group(1),m.group(2)))
                return self.index.get(m.group(1),m.group(2).rstrip("/"))

            log.debug("basic lookup %s" % member)
            for idx in ("null"):
                e = self.index.get(idx,member)
                if e:
                    log.debug("found %s in %s index" % (e,idx))
                    return e

            e = self.get(member,None)
            if e:
                return self._lookup(e,xp)

            if "://" in member: # looks like a URL and wasn't an entity or collection - recurse away!
                log.debug("recursively fetching members from '%s'" % member)
                # note that this supports remote lists which may be more rope than is healthy
                return [self._lookup(line,xp) for line in urllib.urlopen(member).iterlines()]

            return []
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

        log.debug("selecting %d entities from %d entity set(s) before validation" % (nent,len(entities)))

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

    def merge(self,t,nt,strategy=pyff.merge_strategies.replace_existing,strategy_name=None):
        if strategy_name is not None:
            if not '.' in strategy_name:
                strategy_name = "pyff.merge_strategies.%s" % strategy_name
            (mn,sep,fn) = strategy_name.rpartition('.')
            #log.debug("import %s from %s" % (fn,mn))
            module = None
            if '.' in mn:
                (pn,sep,modn) = mn.rpartition('.')
                module = getattr(__import__(pn,globals(),locals(),[modn],-1),modn)
            else:
                module = __import__(mn,globals(),locals(),[],-1)
            strategy = getattr(module,fn) # we might aswell let this fail early if the strategy is wrongly named

        if strategy is None:
            raise ValueError("No merge strategy - refusing to merge")

        for e in nt.findall(".//{%s}EntityDescriptor" % NS['md']):
            entityID = e.get("entityID")
            # we assume ddup:ed tree
            old_e = t.find(".//{%s}EntityDescriptor[@entityID='%s']" % (NS['md'],entityID))
            #log.debug("merging %s into %s" % (e,old_e))
            # update index!

            try:
                self.index.remove(old_e)
                #log.debug("removed old entity from index")
                strategy(old_e,e)
                new_e = t.find(".//{%s}EntityDescriptor[@entityID='%s']" % (NS['md'],entityID))
                self.index.add(new_e) # we don't know which strategy was employed
            except Exception,ex:
                traceback.print_exc()
                self.index.add(old_e)
                raise ex