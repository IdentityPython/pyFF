"""

This is the implementation of the active repository of SAML metadata. The 'local' and 'remote' pipes operate on this.

"""
try:
    from cStringIO import StringIO
except ImportError:  # pragma: no cover
    print(" *** install cStringIO for better performance")
    from StringIO import StringIO

from copy import deepcopy
from datetime import datetime
from UserDict import UserDict
import os
import re
import traceback
from concurrent import futures

from lxml import etree
from lxml.builder import ElementMaker
from lxml.etree import DocumentInvalid
import operator
import xmlsec
import ipaddr

from . import merge_strategies
from .logs import log
from .utils import schema, filter_lang, root, duration2timedelta, \
    hash_id, MetadataException, find_merge_strategy, entities_list, url2host, subdomains, avg_domain_distance, \
    iter_entities, validate_document, load_url, iso2datetime, xml_error
from .constants import NS, NF_URI, EVENT_DROP_ENTITY, EVENT_IMPORT_FAIL

etree.set_default_parser(etree.XMLParser(resolve_entities=False))


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


class MDRepository(Observable):
    """A class representing a set of SAML Metadata. Instances present as dict-like objects where
    the keys are URIs and values are EntitiesDescriptor elements containing sets of metadata.
    """

    def __init__(self, metadata_cache_enabled=False, min_cache_ttl="PT5M", store=None):
        self.metadata_cache_enabled = metadata_cache_enabled
        self.min_cache_ttl = min_cache_ttl

        if not isinstance(self.min_cache_ttl, int):
            try:
                self.min_cache_ttl = duration2timedelta(self.min_cache_ttl).total_seconds()
            except Exception, ex:
                log.error(ex)
                self.min_cache_ttl = 300
        self.respect_cache_duration = True
        self.default_cache_duration = "PT10M"
        self.retry_limit = 5
        self.store = None

        if store is not None:
            if hasattr(store, '__call__'):
                self.store = store()
            else:
                self.store = store
        else:
            from .store import MemoryStore

            self.store = MemoryStore()
        super(MDRepository, self).__init__()

    def clone(self):
        return MDRepository(metadata_cache_enabled=self.metadata_cache_enabled,
                            min_cache_ttl=self.min_cache_ttl,
                            store=self.store.clone())

    def sha1_id(self, e):
        return hash_id(e, 'sha1')

    def is_idp(self, e):
        return bool(e.find(".//{%s}IDPSSODescriptor" % NS['md']) is not None)

    def is_sp(self, e):
        return bool(e.find(".//{%s}SPSSODescriptor" % NS['md']) is not None)

    def icon(self, entity):
        for icon in filter_lang(entity.iter("{%s}Logo" % NS['mdui'])):
            return icon.text

    def domains(self, entity):
        domains = [url2host(entity.get('entityID'))]
        for d in entity.iter("{%s}DomainHint" % NS['mdui']):
            domains.append(d.text)
        return domains

    def ext_display(self, entity, langs=None):
        """Utility-method for computing a displayable string for a given entity.

        :param entity: An EntityDescriptor element
        """
        display = entity.get('entityID')
        info = ''

        for organizationName in filter_lang(entity.iter("{%s}OrganizationName" % NS['md']), langs=langs):
            info = display
            display = organizationName.text

        for organizationDisplayName in filter_lang(entity.iter("{%s}OrganizationDisplayName" % NS['md']), langs=langs):
            info = display
            display = organizationDisplayName.text

        for serviceName in filter_lang(entity.iter("{%s}ServiceName" % NS['md']), langs=langs):
            info = display
            display = serviceName.text

        for displayName in filter_lang(entity.iter("{%s}DisplayName" % NS['mdui']), langs=langs):
            info = display
            display = displayName.text

        for organizationUrl in filter_lang(entity.iter("{%s}OrganizationURL" % NS['md']), langs=langs):
            info = organizationUrl.text

        for description in filter_lang(entity.iter("{%s}Description" % NS['mdui']), langs=langs):
            info = description.text

        if info == entity.get('entityID'):
            info = ''

        return display, info

    def display(self, entity, langs=None):
        """Utility-method for computing a displayable string for a given entity.

        :param entity: An EntityDescriptor element
        """
        for displayName in filter_lang(entity.iter("{%s}DisplayName" % NS['mdui']), langs=langs):
            return displayName.text

        for serviceName in filter_lang(entity.iter("{%s}ServiceName" % NS['md']), langs=langs):
            return serviceName.text

        for organizationDisplayName in filter_lang(entity.iter("{%s}OrganizationDisplayName" % NS['md']), langs=langs):
            return organizationDisplayName.text

        for organizationName in filter_lang(entity.iter("{%s}OrganizationName" % NS['md']), langs=langs):
            return organizationName.text

        return entity.get('entityID')

    def sub_domains(self, e):
        lst = []
        domains = self.domains(e)
        for d in domains:
            for sub in subdomains(d):
                if not sub in lst:
                    lst.append(sub)
        return lst

    def simple_summary(self, e):
        if e is None:
            return dict()

        title, descr = self.ext_display(e)
        entity_id = e.get('entityID')
        d = dict(title=title,
                 value=entity_id,
                 descr=descr,
                 icon=self.icon(e),
                 entity_id=entity_id,
                 domains=";".join(self.sub_domains(e)),
                 id=hash_id(e, 'sha1'))
        icon_url = self.icon(e)
        if icon_url is not None:
            d['icon_url'] = icon_url

        return d

    def search(self, query=None, path=None, page=None, page_limit=10, entity_filter=None, related=None):
        """
:param query: A string to search for.
:param path: The repository collection (@Name) to search in - None for search in all collections
:param page:  When using paged search, the page index
:param page_limit: When using paged search, the maximum entry per page
:param entity_filter: An optional lookup expression used to filter the entries before search is done.
:param related: an optional '+'-separated list of related domain names for prioritizing search results

Returns a list of dict's for each EntityDescriptor present in the metadata store such
that any of the DisplayName, ServiceName, OrganizationName or OrganizationDisplayName
elements match the query (as in contains the query as a substring).

The dict in the list contains three items:

:param title: A displayable string, useful as a UI label
:param value: The entityID of the EntityDescriptor
:param id: A sha1-ID of the entityID - on the form {sha1}<sha1-hash-of-entityID>
        """

        if isinstance(query, basestring):
            query = [query.lower()]

        def _strings(elt):
            lst = []
            for attr in ['{%s}DisplayName' % NS['mdui'],
                         '{%s}ServiceName' % NS['md'],
                         '{%s}OrganizationDisplayName' % NS['md'],
                         '{%s}OrganizationName' % NS['md'],
                         '{%s}Keywords' % NS['mdui'],
                         '{%s}Scope' % NS['shibmd']]:
                lst.extend([s.text for s in elt.iter(attr)])
            lst.append(elt.get('entityID'))
            return filter(lambda item: item is not None, lst)

        def _ip_networks(elt):
            return [ipaddr.IPNetwork(x.text) for x in elt.iter('{%s}IPHint' % NS['mdui'])]

        def _match(qq, elt):
            for q in qq:
                q = q.strip()
                if ':' in q or '.' in q:
                    try:
                        nets = _ip_networks(elt)
                        for net in nets:
                            if ':' in q and ipaddr.IPv6Address(q) in net:
                                return net
                            if '.' in q and ipaddr.IPv4Address(q) in net:
                                return net
                    except ValueError:
                        pass

                if q is not None and len(q) > 0:
                    tokens = _strings(elt)
                    for tstr in tokens:
                        for tpart in tstr.split():
                            if tpart.lower().startswith(q):
                                return tstr
            return None

        f = []
        if path is not None and path not in f:
            f.append(path)
        if entity_filter is not None and entity_filter not in f:
            f.append(entity_filter)
        mexpr = None
        if f:
            mexpr = "+".join(f)

        if log.isDebugEnabled():
            log.debug("match using '%s'" % mexpr)
        res = []
        for e in self.lookup(mexpr):
            m = _match(query, e)
            if m is not None:
                d = self.simple_summary(e)
                ll = d['title'].lower()
                if m != ll and not query[0] in ll:
                    d['title'] = "%s - %s" % (d['title'], m)

                if related is not None:
                    d['ddist'] = avg_domain_distance(related, d['domains'])
                else:
                    d['ddist'] = 0

                res.append(d)

        res.sort(key=operator.itemgetter('title'))
        res.sort(key=operator.itemgetter('ddist'), reverse=True)

        if log.isDebugEnabled():
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
        return len(self.store.collections()) > 0

    def extensions(self, e):
        """Return a list of the Extensions elements in the EntityDescriptor

:param e: an EntityDescriptor
:return: a list
        """
        ext = e.find("./{%s}Extensions" % NS['md'])
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
        self.store.update(e)

    def _entity_attributes(self, e):
        ext = self.extensions(e)
        ea = ext.find(".//{%s}EntityAttributes" % NS['mdattr'])
        if ea is None:
            ea = etree.Element("{%s}EntityAttributes" % NS['mdattr'])
            ext.append(ea)
        return ea

    def _eattribute(self, e, attr, nf):
        ea = self._entity_attributes(e)
        a = ea.xpath(".//saml:Attribute[@NameFormat='%s' and @Name='%s']" % (nf, attr),
                     namespaces=NS,
                     smart_strings=False)
        if a is None or len(a) == 0:
            a = etree.Element("{%s}Attribute" % NS['saml'])
            a.set('NameFormat', nf)
            a.set('Name', attr)
            ea.append(a)
        else:
            a = a[0]
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

        for attr, value in d.iteritems():
            a = self._eattribute(e, attr, nf)
            velt = etree.Element("{%s}AttributeValue" % NS['saml'])
            velt.text = value
            a.append(velt)

        self.store.update(e)

    def set_pubinfo(self, e, publisher=None):
        if e.tag != "{%s}EntitiesDescriptor" % NS['md']:
            raise MetadataException("I can only set RegistrationAuthority to EntitiesDescriptor elements")
        if publisher is None:
            raise MetadataException("At least publisher must be provided")
        ext = self.extensions(e)
        pi = ext.find(".//{%s}PublicationInfo" % NS['mdrpi'])
        if pi is not None:
            raise MetadataException("A PublicationInfo element is already present")
        pi = etree.Element("{%s}PublicationInfo" % NS['mdrpi'])
        pi.set('publisher', publisher)
        ext.append(pi)

    def set_reginfo(self, e, policy=None, authority=None):
        if e.tag != "{%s}EntityDescriptor" % NS['md']:
            raise MetadataException("I can only set RegistrationAuthority to EntityDescriptor elements")
        if authority is None:
            raise MetadataException("At least authority must be provided")
        if policy is None:
            policy = dict()

        ext = self.extensions(e)
        ri = ext.find(".//{%s}RegistrationInfo" % NS['mdrpi'])
        if ri is not None:
            raise MetadataException("A RegistrationInfo element is already present")

        ri = etree.Element("{%s}RegistrationInfo" % NS['mdrpi'])
        ext.append(ri)
        ri.set('registrationAuthority', authority)
        for lang, policy_url in policy.iteritems():
            rp = etree.Element("{%s}RegistrationPolicy" % NS['mdrpi'])
            rp.text = policy_url
            rp.set('{%s}lang' % NS['xml'], lang)
            ri.append(rp)

    def expiration(self, t):
        relt = root(t)
        if relt.tag in ('{%s}EntityDescriptor' % NS['md'], '{%s}EntitiesDescriptor' % NS['md']):
            cache_duration = self.default_cache_duration
            valid_until = relt.get('validUntil', None)
            if valid_until is not None:
                now = datetime.utcnow()
                vu = iso2datetime(valid_until)
                now = now.replace(microsecond=0)
                vu = vu.replace(microsecond=0, tzinfo=None)
                return vu - now
            elif self.respect_cache_duration:
                cache_duration = relt.get('cacheDuration', self.default_cache_duration)
                return duration2timedelta(cache_duration)

        return None

    def fetch_metadata(self, resources, max_workers=5, stats=None, timeout=120, max_tries=5, validate=False):
        """Fetch a series of metadata URLs and optionally verify signatures.

:param resources: A list of triples (url,cert-or-fingerprint,id, post-callback)
:param max_workers: The maximum number of parallell downloads to run
:param stats: A dictionary used for storing statistics. Useful for cherrypy cpstats
:param validate: Turn on or off schema validation

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
        resources = [(url, verifier, tid, post, True) for url, verifier, tid, post in resources]
        return self._fetch_metadata(resources,
                                    max_workers=max_workers,
                                    stats=stats,
                                    timeout=timeout,
                                    max_tries=max_tries,
                                    validate=validate)

    def _fetch_metadata(self, resources, max_workers=5, stats=None, timeout=120, max_tries=5, validate=False):
        if stats is None:
            stats = dict()
        tries = dict()

        def _process_url(rurl, verifier, tid, post, enable_cache=True):
            tries.setdefault(rurl, 0)

            resource = load_url(rurl, timeout=timeout, enable_cache=enable_cache)
            xml = resource.result.strip()
            retry_resources = []
            info = {
                'Time Spent': resource.time
            }

            tries[rurl] += 1
            info['Tries'] = tries[rurl]

            if resource.result is not None:
                info['Bytes'] = len(resource.result)
            else:
                raise MetadataException("empty response fetching '%s'" % resource.url)

            info['URL'] = rurl
            info['Cached'] = resource.cached
            info['Date'] = str(resource.date)
            info['Last-Modified'] = str(resource.last_modified)
            info['Validation Errors'] = dict()

            if resource.resp is not None:
                info['Status'] = resource.resp.status

            t, offset = self.parse_metadata(StringIO(xml),
                                            key=verifier,
                                            base_url=rurl,
                                            validate=validate,
                                            validation_errors=info['Validation Errors'],
                                            expiration=self.expiration,
                                            post=post)

            relt = root(t)

            if t is None:
                self.fire(type=EVENT_IMPORT_FAIL, url=rurl)
                raise MetadataException("no valid metadata found at '%s'" % rurl)

            expired = False
            if offset is not None:
                expire_time = datetime.now() + offset
                ttl = offset.total_seconds()
                info['Expiration Time'] = str(expire_time)
                info['Cache TTL'] = str(ttl)
                if ttl < self.min_cache_ttl:
                    if tries[rurl] < max_tries:  # try to get fresh md but we'll use what we have anyway
                        retry_resources.append((rurl, verifier, tid, post, False))
                    else:
                        log.error("giving up on %s" % rurl)
                if ttl < 0:
                    expired = True

            if not expired:
                if relt.tag in ('{%s}XRD' % NS['xrd'], '{%s}XRDS' % NS['xrd']):
                    if log.isDebugEnabled():
                        log.debug("%s looks like an xrd document" % rurl)
                    for xrd in t.iter("{%s}XRD" % NS['xrd']):
                        for link in xrd.findall(".//{%s}Link[@rel='%s']" % (NS['xrd'], NS['md'])):
                            link_href = link.get("href")
                            certs = xmlsec.CertDict(link)
                            fingerprints = certs.keys()
                            fp = None
                            if len(fingerprints) > 0:
                                fp = fingerprints[0]
                            if log.isDebugEnabled():
                                log.debug("XRD: '%s' verified by '%s'" % (link_href, fp))
                            tries.setdefault(link_href, 0)
                            if tries[link_href] < max_tries:
                                retry_resources.append((link_href, fp, link_href, post, True))
                elif relt.tag in ('{%s}EntityDescriptor' % NS['md'], '{%s}EntitiesDescriptor' % NS['md']):
                    number_of_entities = self.store.update(t, tid)
                    info['Number of Entities'] = number_of_entities
                else:
                    raise MetadataException("unknown metadata type for '%s' (%s)" % (rurl, relt.tag))

            log.debug(info)
            stats[rurl] = info
            return retry_resources

        while resources:
            with futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_url = dict((executor.submit(_process_url, url, verifier, tid, post, enable_cache), url)
                                     for url, verifier, tid, post, enable_cache in resources)

                next_resources = []
                for future in futures.as_completed(future_to_url):
                    url = future_to_url[future]
                    if future.exception() is not None:
                        log.error('%r generated an exception: %s' % (url, future.exception()))
                    else:
                        next_resources.extend(future.result())
                resources = next_resources
                if log.isDebugEnabled():
                    log.debug("retrying %s" % resources)

    def import_metadata(self, t, name):
        self.store.update(t, name)

    def filter_invalids(self, t, base_url, validation_errors):
        xsd = schema()
        for e in iter_entities(t):
            if not xsd.validate(e):
                error = xml_error(xsd.error_log, m=base_url)
                entity_id = e.get("entityID")
                log.warn("removing '%s': schema validation failed (%s)" % (entity_id, error))
                validation_errors[entity_id] = error
                if e.getparent() is None:
                    return None
                e.getparent().remove(e)
                self.fire(type=EVENT_DROP_ENTITY, url=base_url, entityID=entity_id, error=error)
        return t

    def check_signature(self, t, key):
        if key is not None:
            if log.isDebugEnabled():
                log.debug("verifying signature using %s" % key)
            refs = xmlsec.verified(t, key)
            if len(refs) != 1:
                raise MetadataException(
                    "XML metadata contains %d signatures - exactly 1 is required" % len(refs))
            t = refs[0]  # prevent wrapping attacks

        return t

    def parse_metadata(self,
                       source,
                       key=None,
                       base_url=None,
                       fail_on_error=False,
                       filter_invalid=True,
                       validate=True,
                       validation_errors=None,
                       expiration=None,
                       post=None):
        """Parse a piece of XML and split it up into EntityDescriptor elements. Each such element
        is stored in the MDRepository instance.

:param source: a file-like object containing SAML metadata
:param key: a certificate (file) or a SHA1 fingerprint to use for signature verification
:param base_url: use this base url to resolve relative URLs for XInclude processing
:param fail_on_error: (default: False)
:param filter_invalid: (default True) remove invalid EntityDescriptor elements rather than raise an errror
:param validate: (default: True) set to False to turn off all XML schema validation
:param post: A callable that will be called to modify the parse-tree before any validation
(but after xinclude processing)
        """

        if validation_errors is None:
            validation_errors = dict()

        try:
            parser = etree.XMLParser(resolve_entities=False)
            t = etree.parse(source, base_url=base_url, parser=parser)
            t.xinclude()

            valid_until = None
            if expiration is not None:
                valid_until = expiration(t)

            t = self.check_signature(t, key)

            # get rid of ID as early as possible - probably not unique
            for e in iter_entities(t):
                if e.get('ID') is not None:
                    del e.attrib['ID']

            if post is not None:
                t = post(t)

            if validate:
                if filter_invalid:
                    t = self.filter_invalids(t, base_url=base_url, validation_errors=validation_errors)
                else:  # all or nothing
                    try:
                        validate_document(t)
                    except DocumentInvalid, ex:
                        raise MetadataException("schema validation failed: '%s': %s" %
                                                (base_url, xml_error(ex.error_log, m=base_url)))

        except Exception, ex:
            log.error(ex)
            if fail_on_error:
                raise ex
            return None, None

        if log.isDebugEnabled():
            log.debug("returning %d valid entities" % len(list(iter_entities(t))))

        return t, valid_until

    def load_dir(self, directory, ext=".xml", url=None, validate=False, post=None):
        """
:param directory: A directory to walk.
:param ext: Include files with this extension (default .xml)

Traverse a directory tree looking for metadata. Files ending in the specified extension are included. Directories
starting with '.' are excluded.
        """
        if url is None:
            url = directory

        entities = []
        for top, dirs, files in os.walk(directory):
            for dn in dirs:
                if dn.startswith("."):
                    dirs.remove(dn)
            for nm in files:
                if nm.endswith(ext):
                    if log.isDebugEnabled():
                        log.debug("parsing from file %s" % nm)
                    fn = os.path.join(top, nm)
                    try:
                        t, valid_until = self.parse_metadata(fn, fail_on_error=True, validate=validate, post=post)
                        entities.extend(entities_list(t))  # local metadata is assumed to be ok
                    except Exception, ex:
                        log.error(ex)

        if entities:
            self.store.update(self.entity_set(entities, url, validate=validate))
        else:
            log.info("no entities found in %s" % directory)

    def _lookup(self, member):
        if member is None:
            member = "entities"

        if type(member) is str or type(member) is unicode:
            if '!' in member:
                (src, xp) = member.split("!")
                if len(src) == 0:
                    src = None
                return self.lookup(src, xp)

        log.debug("calling store lookup %s" % member)
        return self.store.lookup(member)

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

        l = self._lookup(member)
        if hasattr(l, 'tag'):
            l = [l]
        elif hasattr(l, '__iter__'):
            l = list(l)

        if xp is None:
            return l
        else:
            if log.isDebugEnabled():
                log.debug("filtering %d entities using xpath %s" % (len(l), xp))
            t = self.entity_set(l, 'dummy')
            if t is None:
                return []
            l = root(t).xpath(xp, namespaces=NS, smart_strings=False)

            if log.isDebugEnabled():
                log.debug("got %d entities after filtering" % len(l))
            return l

    def entity_set(self, entities, name, cacheDuration=None, validUntil=None, validate=True):
        """
:param entities: a set of entities specifiers (lookup is used to find entities from this set)
:param name: the @Name attribute
:param cacheDuration: an XML timedelta expression, eg PT1H for 1hr
:param validUntil: a relative time eg 2w 4d 1h for 2 weeks, 4 days and 1hour from now.

Produce an EntityDescriptors set from a list of entities. Optional Name, cacheDuration and validUntil are affixed.
        """

        # if log.isDebugEnabled():
        #    log.debug("entities: %s" % entities)

        def _a(ent):
            entity_id = ent.get('entityID', None)
            # log.debug("adding %s to set" % entity_id)
            if (ent is not None) and (entity_id is not None) and (entity_id not in seen):
                t.append(deepcopy(ent))
                # log.debug("really adding %s to set" % entity_id)
                seen[entity_id] = True

        attrs = dict(Name=name, nsmap=NS)
        if cacheDuration is not None:
            attrs['cacheDuration'] = cacheDuration
        if validUntil is not None:
            attrs['validUntil'] = validUntil
        t = etree.Element("{%s}EntitiesDescriptor" % NS['md'], **attrs)
        nent = 0
        seen = {}  # TODO make better de-duplication
        for member in entities:
            if hasattr(member, 'tag'):
                _a(member)
                nent += 1
            else:
                for entity in self.lookup(member):
                    _a(entity)
                    nent += 1

        if log.isDebugEnabled():
            log.debug("selecting %d entities before validation" % nent)

        if not nent:
            return None

        if validate:
            try:
                validate_document(t)
            except DocumentInvalid, ex:
                if log.isDebugEnabled():
                    log.debug(xml_error(ex.error_log))
                raise MetadataException("XML schema validation failed: %s" % name)
        return t

    def summary(self, uri):
        """
:param uri: An EntitiesDescriptor URI present in the MDRepository
:return: an information dict

Returns a dict object with basic information about the EntitiesDescriptor
        """
        seen = dict()
        info = dict()
        t = self.store.lookup(uri).next()
        info['Name'] = t.get('Name', uri)
        info['cacheDuration'] = t.get('cacheDuration', None)
        info['validUntil'] = t.get('validUntil', None)
        info['Duplicates'] = []
        info['Size'] = 0
        for e in entities_list(t):
            entity_id = e.get('entityID')
            if seen.get(entity_id, False):
                info['Duplicates'].append(entity_id)
            else:
                seen[entity_id] = True
            info['Size'] += 1

        return info

    def merge(self, t, nt, strategy=merge_strategies.replace_existing, strategy_name=None):
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
            strategy = find_merge_strategy(strategy_name)

        for e in iter_entities(nt):
            entity_id = e.get("entityID")
            # we assume ddup:ed tree
            old_e = t.find(".//{%s}EntityDescriptor[@entityID='%s']" % (NS['md'], entity_id))
            strategy(old_e, e)
            self.store.update(e)
