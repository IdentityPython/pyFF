"""

This is the implementation of the active repository of SAML metadata. The 'local' and 'remote' pipes operate on this.

"""
from StringIO import StringIO
from datetime import datetime
import hashlib
import urllib
from UserDict import DictMixin, UserDict
from lxml import etree
from lxml.builder import ElementMaker
from lxml.etree import DocumentInvalid
import os
import re
from copy import deepcopy
from pyff import merge_strategies
import pyff.index
from pyff.logs import log
from pyff.utils import schema, URLFetch, filter_lang, root, duration2timedelta, template
import xmlsec
from pyff.constants import NS, NF_URI, DIGESTS, EVENT_DROP_ENTITY, EVENT_IMPORTED_METADATA, EVENT_IMPORT_FAIL
import traceback
import threading
from Queue import Queue
import ipaddr

__author__ = 'leifj'


def _is_self_signed_err(ebuf):
    for e in ebuf:
        if e['func'] == 'xmlSecOpenSSLX509StoreVerify' and re.match('err=18', e['message']):
            return True
    return False


etree.set_default_parser(etree.XMLParser(resolve_entities=False))


def _e(error_log, m=None):
    def _f(x):
        if ":WARNING:" in x:
            return False
        if m is not None and not m in x:
            return False
        return True

    return "\n".join(filter(_f, ["%s" % e for e in error_log]))


class MetadataException(Exception):
    pass


class Event(UserDict):
    pass


class Observable(object):
    def __init__(self):
        self.callbacks = []

    def subscribe(self, callback):
        self.callbacks.append(callback)

    def fire(self, **attrs):
        e = Event(attrs)
        e['time'] = datetime.now()
        for fn in self.callbacks:
            fn(e)


class MDRepository(DictMixin, Observable):
    """A class representing a set of SAML Metadata. Instances present as dict-like objects where
    the keys are URIs and values are EntitiesDescriptor elements containing sets of metadata.
    """

    def __init__(self, index=pyff.index.MemoryIndex(), metadata_cache_enabled=False, min_cache_ttl="PT5M"):
        self.md = {}
        self.index = index
        self.metadata_cache_enabled = metadata_cache_enabled
        self.min_cache_ttl = min_cache_ttl
        self.respect_cache_duration = True
        self.default_cache_duration = "PT10M"
        self.retry_limit = 5

        super(MDRepository, self).__init__()

    def is_idp(self, entity):
        """Returns True if the supplied EntityDescriptor has an IDPSSODescriptor Role

:param entity: An EntityDescriptor element
        """
        return bool(entity.find(".//{%s}IDPSSODescriptor" % NS['md']) is not None)

    def is_sp(self, entity):
        """Returns True if the supplied EntityDescriptor has an SPSSODescriptor Role

:param entity: An EntityDescriptor element
        """
        return bool(entity.find(".//{%s}SPSSODescriptor" % NS['md']) is not None)

    def display(self, entity):
        """Utility-method for computing a displayable string for a given entity.

:param entity: An EntityDescriptor element
        """
        for displayName in filter_lang(entity.findall(".//{%s}DisplayName" % NS['mdui'])):
            return displayName.text

        for serviceName in filter_lang(entity.findall(".//{%s}ServiceName" % NS['md'])):
            return serviceName.text

        for organizationDisplayName in filter_lang(entity.findall(".//{%s}OrganizationDisplayName" % NS['md'])):
            return organizationDisplayName.text

        for organizationName in filter_lang(entity.findall(".//{%s}OrganizationName" % NS['md'])):
            return organizationName.text

        return entity.get('entityID')

    def __iter__(self):
        for t in [self.md[url] for url in self.md.keys()]:
            for entity in t.findall(".//{%s}EntityDescriptor" % NS['md']):
                yield entity

    def sha1_id(self, e):
        return pyff.index.hash_id(e, 'sha1')

    def search(self, query=None, path=None, page=None, page_limit=10, entity_filter=None):
        """
:param query: A string to search for.
:param path: The repository collection (@Name) to search in - None for search in all collections
:param page:  When using paged search, the page index
:param page_limit: When using paged search, the maximum entry per page
:param entity_filter: A lookup expression used to filter the entries before search is done.

Returns a list of dict's for each EntityDescriptor present in the metadata store such
that any of the DisplayName, ServiceName, OrganizationName or OrganizationDisplayName
elements match the query (as in contains the query as a substring).

The dict in the list contains three items:

:param label: A displayable string, useful as a UI label
:param value: The entityID of the EntityDescriptor
:param id: A sha1-ID of the entityID - on the form {sha1}<sha1-hash-of-entityID>
        """

        if isinstance(query, basestring):
            query = [query.lower()]

        def _lc_text(e):
            if e.text is None:
                return None
            return e.text.lower()

        def _strings(elt):
            lst = [elt.get('entityID')]
            for attr in ['.//{%s}DisplayName' % NS['mdui'],
                         './/{%s}ServiceName' % NS['md'],
                         './/{%s}OrganizationDisplayName' % NS['md'],
                         './/{%s}OrganizationName' % NS['md'],
                         './/{%s}Scope' % NS['shibmd'],
                         './/{%s}Keywords' % NS['mdui']]:
                lst.extend([_lc_text(x) for x in elt.findall(attr)])
            return filter(lambda s: s is not None, lst)

        def _ip_networks(elt):
            return [ipaddr.IPNetwork(x.text) for x in elt.findall('.//{%s}IPHint' % NS['mdui'])]

        def _match(qq, elt):
            for q in qq:
                if ':' in q or '.' in q:
                    nets = _ip_networks(elt)
                    try:
                        for net in nets:
                            if ':' in q and ipaddr.IPv6Address(q) in net:
                                return True
                            if '.' in q and ipaddr.IPv4Address(q) in net:
                                return True
                    except ValueError, ex:
                        pass
                tokens = _strings(elt)
                for qstr in tokens:
                    #log.debug("looking for '%s' in '%s'" % (q, qstr))
                    if q is not None and len(q) > 0 and q in qstr:
                        return True
            return False

        f = []
        if path is not None and not path in f:
            f.append(path)
        if entity_filter is not None and not entity_filter in f:
            f.append(entity_filter)
        mexpr = None
        if f:
            mexpr = "+".join(f)

        log.debug("match using '%s'" % mexpr)
        res = [{'label': self.display(e),
                'value': e.get('entityID'),
                'tokens': _strings(e),
                'id': pyff.index.hash_id(e, 'sha1')}
               for e in pyff.index.EntitySet(filter(lambda ent: _match(query, ent), self.lookup(mexpr)))]

        res.sort(key=lambda i: i['label'])

        log.debug("search returning %s" % res)

        if page is not None:
            total = len(res)
            begin = (page - 1) * page_limit
            end = begin + page_limit
            more = (end < total)
            return res[begin:end], more, total
        else:
            return res

    def sane(self):
        """A very basic test for sanity. An empty metadata set is probably not a sane output of any process.

:return: True iff there is at least one EntityDescriptor in the active set.
        """
        return len(self.md) > 0

    def extensions(self, e):
        """Return a list of the Extensions elements in the EntityDescriptor

:param e: an EntityDescriptor
:return: a list
        """
        ext = e.find(".//{%s}Extensions" % NS['md'])
        if ext is None:
            ext = etree.Element("{%s}Extensions" % NS['md'])
            e.insert(0, ext)
        return ext

    def annotate(self, e, category, title, message, source=None):
        """Add an ATOM annotation to an EntityDescriptor or an EntitiesDescriptor. This is a simple way to
        add non-normative text annotations to metadata, eg for the purpuse of generating reports.

:param e: An EntityDescriptor or an EntitiesDescriptor element
:param category: The ATOM category
:param title: The ATOM title
:param message: The ATOM content
:param source: An optional source URL. It is added as a <link> element with @rel='saml-metadata-source'
        """
        if e.tag != "{%s}EntityDescriptor" % NS['md'] and e.tag != "{%s}EntitiesDescriptor" % NS['md']:
            raise MetadataException("I can only annotate EntityDescriptor or EntitiesDescriptor elements")
        subject = e.get('Name', e.get('entityID', None))
        atom = ElementMaker(nsmap={'atom': 'http://www.w3.org/2005/Atom'}, namespace='http://www.w3.org/2005/Atom')
        args = [atom.published("%s" % datetime.now().isoformat()),
                atom.link(href=subject, rel="saml-metadata-subject")]
        if source is not None:
            args.append(atom.link(href=source, rel="saml-metadata-source"))
        args.extend([atom.title(title),
                     atom.category(term=category),
                     atom.content(message, type="text/plain")])
        self.extensions(e).append(atom.entry(*args))

    def _entity_attributes(self, e):
        ext = self.extensions(e)
        #log.debug(ext)
        ea = ext.find(".//{%s}EntityAttributes" % NS['mdattr'])
        if ea is None:
            ea = etree.Element("{%s}EntityAttributes" % NS['mdattr'])
            ext.append(ea)
        return ea

    def _eattribute(self, e, attr, nf):
        ea = self._entity_attributes(e)
        #log.debug(ea)
        a = ea.xpath(".//saml:Attribute[@NameFormat='%s' and @Name='%s']" % (nf, attr), namespaces=NS)
        if a is None or len(a) == 0:
            a = etree.Element("{%s}Attribute" % NS['saml'])
            a.set('NameFormat', nf)
            a.set('Name', attr)
            ea.append(a)
        else:
            a = a[0]
            #log.debug(etree.tostring(self.extensions(e)))
        return a

    def set_entity_attributes(self, e, d, nf=NF_URI):

        """Set an entity attribute on an EntityDescriptor

:param e: The EntityDescriptor element
:param d: A dict of attribute-value pairs that should be added as entity attributes
:param nf: The nameFormat (by default "urn:oasis:names:tc:SAML:2.0:attrname-format:uri") to use.
:raise: MetadataException unless e is an EntityDescriptor element
        """
        if e.tag != "{%s}EntityDescriptor" % NS['md']:
            raise MetadataException("I can only add EntityAttribute(s) to EntityDescriptor elements")

        #log.debug("set %s" % d)
        for attr, value in d.iteritems():
            #log.debug("set %s to %s" % (attr,value))
            a = self._eattribute(e, attr, nf)
            #log.debug(etree.tostring(a))
            velt = etree.Element("{%s}AttributeValue" % NS['saml'])
            velt.text = value
            a.append(velt)
            #log.debug(etree.tostring(a))

    def fetch_metadata(self, resources, qsize=5, timeout=120, stats=None, xrd=None, validate=False):
        """Fetch a series of metadata URLs and optionally verify signatures.

:param resources: A list of triples (url,cert-or-fingerprint,id)
:param qsize: The number of parallell downloads to run
:param timeout: The number of seconds to wait (120 by default) for each download
:param stats: A dictionary used for storing statistics. Useful for cherrypy cpstats

The list of triples is processed by first downloading the URL. If a cert-or-fingerprint
is supplied it is used to validate the signature on the received XML. Two forms of XML
is supported: SAML Metadata and XRD.

SAML metadata is (if valid and contains a valid signature) stored under the 'id'
identifier (which defaults to the URL unless provided in the triple.

XRD elements are processed thus: for all <Link> elements that contain a ds;KeyInfo
elements with a X509Certificate and where the <Rel> element contains the string
'urn:oasis:names:tc:SAML:2.0:metadata', the corresponding <URL> element is download
and verified.
        """
        if stats is None:
            stats = {}

        def producer(q, resources, cache=self.metadata_cache_enabled):
            print resources
            for url, verify, id, tries, post in resources:
                log.debug("starting fetcher for '%s'" % url)
                thread = URLFetch(url, verify, id, enable_cache=cache, tries=tries, post=post)
                thread.start()
                q.put(thread, True)

        def consumer(q, njobs, stats, next_jobs=None, resolved=None):
            if next_jobs is None:
                next_jobs = []
            if resolved is None:
                resolved = set()
            nfinished = 0

            while nfinished < njobs:
                info = None
                try:
                    log.debug("waiting for next thread to finish...")
                    thread = q.get(True)
                    thread.join(timeout)

                    if thread.isAlive():
                        raise MetadataException("thread timeout fetching '%s'" % thread.url)

                    info = {
                        'Time Spent': thread.time()
                    }

                    if thread.ex is not None:
                        raise thread.ex
                    else:
                        if thread.result is not None:
                            info['Bytes'] = len(thread.result)
                        else:
                            raise MetadataException("empty response fetching '%s'" % thread.url)
                        info['Cached'] = thread.cached
                        info['Date'] = str(thread.date)
                        info['Last-Modified'] = str(thread.last_modified)
                        info['Tries'] = thread.tries

                    xml = thread.result.strip()

                    if thread.resp is not None:
                        info['Status'] = thread.resp.status

                    t = self.parse_metadata(StringIO(xml),
                                            key=thread.verify,
                                            base_url=thread.url,
                                            validate=validate,
                                            post=thread.post)
                    if t is None:
                        self.fire(type=EVENT_IMPORT_FAIL, url=thread.url)
                        raise MetadataException("no valid metadata found at '%s'" % thread.url)

                    relt = root(t)
                    if relt.tag in ('{%s}XRD' % NS['xrd'], '{%s}XRDS' % NS['xrd']):
                        log.debug("%s looks like an xrd document" % thread.url)
                        for xrd in t.xpath("//xrd:XRD", namespaces=NS):
                            log.debug("xrd: %s" % xrd)
                            for link in xrd.findall(".//{%s}Link[@rel='%s']" % (NS['xrd'], NS['md'])):
                                url = link.get("href")
                                certs = xmlsec.CertDict(link)
                                fingerprints = certs.keys()
                                fp = None
                                if len(fingerprints) > 0:
                                    fp = fingerprints[0]
                                log.debug("fingerprint: %s" % fp)
                                next_jobs.append((url, fp, url, 0, thread.post))

                    elif relt.tag in ('{%s}EntityDescriptor' % NS['md'], '{%s}EntitiesDescriptor' % NS['md']):
                        cacheDuration = self.default_cache_duration
                        if self.respect_cache_duration:
                            cacheDuration = root(t).get('cacheDuration', self.default_cache_duration)
                        offset = duration2timedelta(cacheDuration)

                        if thread.cached:
                            if thread.last_modified + offset < datetime.now() - duration2timedelta(self.min_cache_ttl):
                                raise MetadataException("cached metadata expired")
                            else:
                                log.debug("found cached metadata for '%s' (last-modified: %s)" % (thread.url, thread.last_modified))
                                ne = self.import_metadata(t, url=thread.id)
                                info['Number of Entities'] = ne
                        else:
                            log.debug("got fresh metadata for '%s' (date: %s)" % (thread.url, thread.date))
                            ne = self.import_metadata(t, url=thread.id)
                            info['Number of Entities'] = ne
                        info['Cache Expiration Time'] = str(thread.last_modified + offset)
                        certs = xmlsec.CertDict(relt)
                        cert = None
                        if certs.values():
                            cert = certs.values()[0].strip()
                        resolved.add((thread.url, cert))
                    else:
                        raise MetadataException("unknown metadata type for '%s' (%s)" % (thread.url, relt.tag))
                except Exception, ex:
                    #traceback.print_exc(ex)
                    log.warn("problem fetching '%s' (will retry): %s" % (thread.url, ex))
                    if info is not None:
                        info['Exception'] = ex
                    if thread.tries < self.retry_limit:
                        next_jobs.append((thread.url, thread.verify, thread.id, thread.tries + 1, thread.post))
                    else:
                        #traceback.print_exc(ex)
                        log.error("retry limit exceeded for %s (last error was: %s)" % (thread.url, ex))
                finally:
                    nfinished += 1
                    if info is not None:
                        stats[thread.url] = info

        resources = [(url, verify, rid, 0, post) for url, verify, rid, post in resources]
        resolved = set()
        cache = True
        while len(resources) > 0:
            log.debug("fetching %d resources (%s)" % (len(resources), repr(resources)))
            next_jobs = []
            q = Queue(qsize)
            prod_thread = threading.Thread(target=producer, args=(q, resources, cache))
            cons_thread = threading.Thread(target=consumer, args=(q, len(resources), stats, next_jobs, resolved))
            prod_thread.start()
            cons_thread.start()
            prod_thread.join()
            cons_thread.join()
            log.debug("after fetch: %d jobs to retry" % len(next_jobs))
            if len(next_jobs) > 0:
                resources = next_jobs
                cache = False
            else:
                resources = []

        if xrd is not None:
            with open(xrd, "w") as fd:
                fd.write(template("trust.xrd").render(links=resolved))

    def parse_metadata(self,
                       fn,
                       key=None,
                       base_url=None,
                       fail_on_error=False,
                       filter_invalid=True,
                       validate=True,
                       post=None):
        """Parse a piece of XML and split it up into EntityDescriptor elements. Each such element
        is stored in the MDRepository instance.

:param fn: a file-like object containing SAML metadata
:param key: a certificate (file) or a SHA1 fingerprint to use for signature verification
:param base_url: use this base url to resolve relative URLs for XInclude processing
:param fail_on_error: (default: False)
:param filter_invalid: (default True) remove invalid EntityDescriptor elements rather than raise an errror
:param validate: (default: True) set to False to turn off all XML schema validation
:param post: A callable that will be called to modify the parse-tree before any validation
(but after xinclude processing)
        """
        try:
            t = etree.parse(fn, base_url=base_url, parser=etree.XMLParser(resolve_entities=False))
            t.xinclude()

            if key is not None:
                try:
                    log.debug("verifying signature using %s" % key)
                    refs = xmlsec.verified(t, key)
                    if len(refs) != 1:
                        raise MetadataException("XML metadata contains %d signatures - exactly 1 is required" % len(refs))
                    t = refs[0]  # prevent wrapping attacks
                except Exception, ex:
                    tb = traceback.format_exc()
                    print tb
                    log.error(ex)
                    return None

            if post is not None:
                t = post(t)

            if validate:
                if filter_invalid:
                    for e in t.findall('{%s}EntityDescriptor' % NS['md']):
                        if not schema().validate(e):
                            error = _e(schema().error_log, m=base_url)
                            log.debug("removing '%s': schema validation failed (%s)" % (e.get('entityID'), error))
                            e.getparent().remove(e)
                            self.fire(type=EVENT_DROP_ENTITY, url=base_url, entityID=e.get('entityID'), error=error)
                else:
                    # Having removed the invalid entities this should now never happen...
                    schema().assertValid(t)
        except DocumentInvalid, ex:
            traceback.print_exc()
            log.debug("schema validation failed on '%s': %s" % (base_url, _e(ex.error_log, m=base_url)))
            raise MetadataException("schema validation failed")
        except Exception, ex:
            #log.debug(_e(schema().error_log))
            log.error(ex)
            if fail_on_error:
                raise ex
            return None

        return t

    def _index_entity(self, e):
        #log.debug("adding %s to index" % e.get('entityID'))
        if 'ID' in e.attrib:
            del e.attrib['ID']
        self.index.add(e)

    def import_metadata(self, t, url=None):
        """
:param t: An EntitiesDescriptor element
:param url: An optional URL to used to identify the EntitiesDescriptor in the MDRepository

Import an EntitiesDescriptor element using the @Name attribute (or the supplied url parameter). All
EntityDescriptor elements are stripped of any @ID attribute and are then indexed before the collection
is stored in the MDRepository object.
        """
        if url is None:
            top = t.xpath("//md:EntitiesDescriptor", namespaces=NS)
            if top is not None and len(top) == 1:
                url = top[0].get("Name", None)
        if url is None:
            raise MetadataException("No collection name found")
        self[url] = t
        # we always clean incoming ID
        # add to the index
        ne = 0

        if t is not None:
            if root(t).tag == "{%s}EntityDescriptor" % NS['md']:
                self._index_entity(root(t))
                ne += 1
            else:
                for e in t.findall(".//{%s}EntityDescriptor" % NS['md']):
                    self._index_entity(e)
                    ne += 1

        self.fire(type=EVENT_IMPORTED_METADATA, size=ne, url=url)
        return ne

    def entities(self, t=None):
        """
:param t: An EntitiesDescriptor element

Returns the list of contained EntityDescriptor elements
        """
        if t is None:
            return []
        elif root(t).tag == "{%s}EntityDescriptor" % NS['md']:
            return [root(t)]
        else:
            return t.findall(".//{%s}EntityDescriptor" % NS['md'])

    def load_dir(self, directory, ext=".xml", url=None, validate=False, post=None):
        """
:param directory: A directory to walk.
:param ext: Include files with this extension (default .xml)

Traverse a directory tree looking for metadata. Files ending in the specified extension are included. Directories
starting with '.' are excluded.
        """
        if url is None:
            url = directory
        log.debug("walking %s" % directory)
        if not directory in self.md:
            entities = []
            for top, dirs, files in os.walk(directory):
                for dn in dirs:
                    if dn.startswith("."):
                        dirs.remove(dn)
                for nm in files:
                    log.debug("found file %s" % nm)
                    if nm.endswith(ext):
                        fn = os.path.join(top, nm)
                        try:
                            t = self.parse_metadata(fn, fail_on_error=True, validate=validate, post=post)
                            entities.extend(self.entities(t))  # local metadata is assumed to be ok
                        except Exception, ex:
                            log.error(ex)
            self.import_metadata(self.entity_set(entities, url))
        return self.md[url]

    def _lookup(self, member, xp=None):
        """
:param member: Either an entity, URL or a filter expression.

Find a (set of) EntityDescriptor element(s) based on the specified 'member' expression.
        """

        def _hash(hn, strv):
            if hn == 'null':
                return strv
            if not hasattr(hashlib, hn):
                raise MetadataException("Unknown digest mechanism: '%s'" % hn)
            hash_m = getattr(hashlib, hn)
            h = hash_m()
            h.update(strv)
            return h.hexdigest()

        if xp is None:
            xp = "//md:EntityDescriptor"
        if member is None:
            lst = []
            for m in self.keys():
                log.debug("resolving %s filtered by %s" % (m, xp))
                lst.extend(self._lookup(m, xp))
            return lst
        elif hasattr(member, 'xpath'):
            #log.debug("xpath filter %s <- %s" % (xp, member))
            return member.xpath(xp, namespaces=NS)
        elif type(member) is str or type(member) is unicode:
            log.debug("string lookup %s" % member)

            if '+' in member:
                member = member.strip('+')
                log.debug("lookup intersection of '%s'" % ' and '.join(member.split('+')))
                hits = None
                for f in member.split("+"):
                    f = f.strip()
                    if hits is None:
                        hits = set(self._lookup(f, xp))
                    else:
                        other = self._lookup(f, xp)
                        hits.intersection_update(other)

                    if not hits:
                        log.debug("empty intersection")
                        return []

                if hits is not None and hits:
                    return list(hits)
                else:
                    return []

            if "!" in member:
                (src, xp) = member.split("!")
                if len(src) == 0:
                    src = None
                    log.debug("filtering using %s" % xp)
                else:
                    log.debug("selecting %s filtered by %s" % (src, xp))
                return self._lookup(src, xp)

            m = re.match("^\{(.+)\}(.+)$", member)
            if m is not None:
                log.debug("attribute-value match: %s='%s'" % (m.group(1), m.group(2)))
                return self.index.get(m.group(1), m.group(2).rstrip("/"))

            m = re.match("^(.+)=(.+)$", member)
            if m is not None:
                log.debug("attribute-value match: %s='%s'" % (m.group(1), m.group(2)))
                return self.index.get(m.group(1), m.group(2).rstrip("/"))

            log.debug("basic lookup %s" % member)
            for idx in DIGESTS:
                e = self.index.get(idx, member)
                if e:
                    log.debug("found %s in %s index" % (e, idx))
                    return e

            e = self.get(member, None)
            if e is not None:
                return self._lookup(e, xp)

            e = self.get("%s.xml" % member, None)  # hackish but helps save people from their misstakes
            if e is not None:
                if not "://" in member:  # not an absolute URL
                    log.warn("Found %s.xml as an alias - AVOID extensions in 'select as' statements" % member)
                return self._lookup(e, xp)

            if "://" in member:  # looks like a URL and wasn't an entity or collection - recurse away!
                log.debug("recursively fetching members from '%s'" % member)
                # note that this supports remote lists which may be more rope than is healthy
                return [self._lookup(line, xp) for line in urllib.urlopen(member).iterlines()]

            return []
        elif hasattr(member, '__iter__') and type(member) is not dict:
            if not len(member):
                member = self.keys()
            return [self._lookup(m, xp) for m in member]
        else:
            raise MetadataException("What about %s ??" % member)

    def lookup(self, member, xp=None):
        """
Lookup elements in the working metadata repository

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
    - sourceID (@Name)
    - <URL containing one selector per line>

The first form results in the intersection of the results of doing a lookup on the selectors. The second form
results in the EntityDescriptor elements from the source (defaults to all EntityDescriptors) that match the
xpath expression. The attribute-value forms resuls in the EntityDescriptors that contain the specified entity
attribute pair. If non of these forms apply, the lookup is done using either source ID (normally @Name from
the EntitiesDescriptor) or the entityID of single EntityDescriptors. If member is a URI but isn't part of
the metadata repository then it is fetched an treated as a list of (one per line) of selectors. If all else
fails an empty list is returned.

        """
        l = self._lookup(member, xp)
        return list(set(filter(lambda x: x is not None, l)))

    def entity_set(self, entities, name, cacheDuration=None, validUntil=None, validate=True):
        """
:param entities: a set of entities specifiers (lookup is used to find entities from this set)
:param name: the @Name attribute
:param cacheDuration: an XML timedelta expression, eg PT1H for 1hr
:param validUntil: a relative time eg 2w 4d 1h for 2 weeks, 4 days and 1hour from now.

Produce an EntityDescriptors set from a list of entities. Optional Name, cacheDuration and validUntil are affixed.
        """
        attrs = dict(Name=name, nsmap=NS)
        if cacheDuration is not None:
            attrs['cacheDuration'] = cacheDuration
        if validUntil is not None:
            attrs['validUntil'] = validUntil
        t = etree.Element("{%s}EntitiesDescriptor" % NS['md'], **attrs)
        nent = 0
        seen = {}  # TODO make better de-duplication
        for member in entities:
            for ent in self.lookup(member):
                entity_id = ent.get('entityID', None)
                if (ent is not None) and (entity_id is not None) and (not seen.get(entity_id, False)):
                    t.append(deepcopy(ent))
                    seen[entity_id] = True
                    nent += 1

        log.debug("selecting %d entities from %d entity set(s) before validation" % (nent, len(entities)))

        if not nent:
            return None

        if validate:
            try:
                schema().assertValid(t)
            except DocumentInvalid, ex:
                log.debug(_e(ex.error_log))
                raise MetadataException("XML schema validation failed: %s" % name)
        return t

    def error_set(self, url, title, ex):
        """
Creates an "error" EntitiesDescriptor - empty but for an annotation about the error that occured
        """
        t = etree.Element("{%s}EntitiesDescriptor" % NS['md'], Name=url, nsmap=NS)
        self.annotate(t, "error", title, ex, source=url)

    def keys(self):
        return self.md.keys()

    def __getitem__(self, item):
        return self.md[item]

    def __setitem__(self, key, value):
        self.md[key] = value

    def __delitem__(self, key):
        del self.md[key]

    def summary(self, uri):
        """
:param uri: An EntitiesDescriptor URI present in the MDRepository
:return: an information dict

Returns a dict object with basic information about the EntitiesDescriptor
        """
        seen = dict()
        info = dict()
        t = root(self[uri])
        info['Name'] = t.get('Name', uri)
        info['cacheDuration'] = t.get('cacheDuration', None)
        info['validUntil'] = t.get('validUntil', None)
        info['Duplicates'] = []
        info['Size'] = 0
        for e in self.entities(self[uri]):
            entityID = e.get('entityID')
            if seen.get(entityID, False):
                info['Duplicates'].append(entityID)
            else:
                seen[entityID] = True
            info['Size'] += 1

        return info

    def merge(self, t, nt, strategy=pyff.merge_strategies.replace_existing, strategy_name=None):
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

:param old_e: The EntityDescriptor from t
:param e: The EntityDescriptor from nt
:return: A merged EntityDescriptor element

Before each call to strategy old_e is removed from the MDRepository index and after
merge the resultant EntityDescriptor is added to the index before it is used to
replace old_e in t.
        """
        if strategy_name is not None:
            if not '.' in strategy_name:
                strategy_name = "pyff.merge_strategies.%s" % strategy_name
            (mn, sep, fn) = strategy_name.rpartition('.')
            #log.debug("import %s from %s" % (fn,mn))
            module = None
            if '.' in mn:
                (pn, sep, modn) = mn.rpartition('.')
                module = getattr(__import__(pn, globals(), locals(), [modn], -1), modn)
            else:
                module = __import__(mn, globals(), locals(), [], -1)
            strategy = getattr(module, fn)  # we might aswell let this fail early if the strategy is wrongly named

        if strategy is None:
            raise MetadataException("No merge strategy - refusing to merge")

        for e in nt.findall(".//{%s}EntityDescriptor" % NS['md']):
            entityID = e.get("entityID")
            # we assume ddup:ed tree
            old_e = t.find(".//{%s}EntityDescriptor[@entityID='%s']" % (NS['md'], entityID))
            #log.debug("merging %s into %s" % (e,old_e))
            # update index!

            try:
                self.index.remove(old_e)
                #log.debug("removed old entity from index")
                strategy(old_e, e)
                new_e = t.find(".//{%s}EntityDescriptor[@entityID='%s']" % (NS['md'], entityID))
                if new_e is not None:
                    self.index.add(new_e)  # we don't know which strategy was employed
            except Exception, ex:
                traceback.print_exc()
                self.index.add(old_e)
                raise ex
