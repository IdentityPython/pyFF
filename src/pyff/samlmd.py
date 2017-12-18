from __future__ import absolute_import, unicode_literals
from datetime import datetime
from .utils import parse_xml, check_signature, root, validate_document, xml_error, \
    schema, iso2datetime, duration2timedelta, filter_lang, url2host, trunc_str, subdomains, \
    has_tag, hash_id, load_callable, rreplace, dumptree, first_text
from .logs import log
from .constants import config, NS, ATTRS, NF_URI, PLACEHOLDER_ICON
from lxml import etree
from lxml.builder import ElementMaker
from lxml.etree import DocumentInvalid
from itertools import chain
from copy import deepcopy
from .exceptions import *
from six import StringIO
from .parse import add_parser


class EntitySet(object):
    def __init__(self, initial=None):
        self._e = dict()
        if initial is not None:
            for e in initial:
                self.add(e)

    def add(self, value):
        self._e[value.get('entityID')] = value

    def discard(self, value):
        entity_id = value.get('entityID')
        if entity_id in self._e:
            del self._e[entity_id]

    def __iter__(self):
        for e in self._e.values():
            yield e

    def __len__(self):
        return len(self._e.keys())

    def __contains__(self, item):
        return item.get('entityID') in self._e.keys()


def find_merge_strategy(strategy_name):
    if '.' not in strategy_name:
        strategy_name = "pyff.merge_strategies:%s" % strategy_name
    if ':' not in strategy_name:
        strategy_name = rreplace(strategy_name, '.', ':')  # backwards compat for old way of specifying these
    return load_callable(strategy_name)


def parse_saml_metadata(source,
                        key=None,
                        base_url=None,
                        fail_on_error=False,
                        filter_invalid=True,
                        cleanup=None,
                        validate=True,
                        validation_errors=None):
    """Parse a piece of XML and return an EntitiesDescriptor element after validation.

:param source: a file-like object containing SAML metadata
:param key: a certificate (file) or a SHA1 fingerprint to use for signature verification
:param base_url: use this base url to resolve relative URLs for XInclude processing
:param fail_on_error: (default: False)
:param filter_invalid: (default True) remove invalid EntityDescriptor elements rather than raise an errror
:param validate: (default: True) set to False to turn off all XML schema validation
:param validation_errors: A dict that will be used to return validation errors to the caller
:param cleanup: A callable that can be used to pre-process parsed metadata before validation. Use as a clue-bat.
(but after xinclude processing and signature validation)
    """

    if validation_errors is None:
        validation_errors = dict()

    try:
        t = parse_xml(source, base_url=base_url)
        t.xinclude()

        expire_time_offset = metadata_expiration(t)

        t = check_signature(t, key)

        if cleanup is not None:
            t = cleanup(t)
        else:  # at least get rid of ID attribute
            for e in iter_entities(t):
                if e.get('ID') is not None:
                    del e.attrib['ID']

        t = root(t)

        if fail_on_error:
            filter_invalid = False

        if validate:
            if filter_invalid:
                t = filter_invalids_from_document(t, base_url=base_url, validation_errors=validation_errors)
            else:  # all or nothing
                try:
                    validate_document(t)
                except DocumentInvalid as ex:
                    validation_errors[base_url] = xml_error(ex.error_log, m=base_url)
                    raise MetadataException("schema validation failed: [{}] '{}': {}"
                                            .format(base_url, source, xml_error(ex.error_log, m=base_url)))

        if t is not None:
            if t.tag == "{%s}EntityDescriptor" % NS['md']:
                t = entitiesdescriptor([t], base_url, copy=False, validate=True, nsmap=t.nsmap)

    except Exception as ex:
        if fail_on_error:
            raise ex
        log.error(ex)
        return None, None

    log.debug("returning %d valid entities" % len(list(iter_entities(t))))

    return t, expire_time_offset


class SAMLMetadataResourceParser():
    def __init__(self):
        pass

    def magic(self, content):
        return "EntitiesDescriptor" in content or "EntityDescriptor" in content

    def parse(self, resource, content):
        info = dict()
        info['Validation Errors'] = dict()
        t, expire_time_offset = parse_saml_metadata(StringIO(content.encode('utf8')),
                                                    key=resource.opts['verify'],
                                                    base_url=resource.url,
                                                    cleanup=resource.opts['cleanup'],
                                                    fail_on_error=resource.opts['fail_on_error'],
                                                    filter_invalid=resource.opts['filter_invalid'],
                                                    validate=resource.opts['validate'],
                                                    validation_errors=info['Validation Errors'])

        if expire_time_offset is not None:
            expire_time = datetime.now() + expire_time_offset
            resource.expire_time = expire_time
            info['Expiration Time'] = str(expire_time)

        if t is not None:
            resource.t = t
            resource.type = "application/samlmetadata+xml"

        return info


from .parse import add_parser

add_parser(SAMLMetadataResourceParser())


def metadata_expiration(t):
    relt = root(t)
    if relt.tag in ('{%s}EntityDescriptor' % NS['md'], '{%s}EntitiesDescriptor' % NS['md']):
        cache_duration = config.default_cache_duration
        valid_until = relt.get('validUntil', None)
        if valid_until is not None:
            now = datetime.utcnow()
            vu = iso2datetime(valid_until)
            now = now.replace(microsecond=0)
            vu = vu.replace(microsecond=0, tzinfo=None)
            return vu - now
        elif config.respect_cache_duration:
            cache_duration = relt.get('cacheDuration', config.default_cache_duration)
            if not cache_duration:
                cache_duration = config.default_cache_duration
            return duration2timedelta(cache_duration)

    return None


def filter_invalids_from_document(t, base_url, validation_errors):
    xsd = schema()
    for e in iter_entities(t):
        if not xsd.validate(e):
            error = xml_error(xsd.error_log, m=base_url)
            entity_id = e.get("entityID")
            log.warn('removing \'%s\': schema validation failed (%s)' % (entity_id, error))
            validation_errors[entity_id] = error
            if e.getparent() is None:
                return None
            e.getparent().remove(e)
    return t


def entitiesdescriptor(entities,
                       name,
                       lookup_fn=None,
                       cache_duration=None,
                       valid_until=None,
                       validate=True,
                       copy=True,
                       nsmap=None):
    """
:param lookup_fn: a function used to lookup entities by name
:param entities: a set of entities specifiers (lookup is used to find entities from this set)
:param name: the @Name attribute
:param cache_duration: an XML timedelta expression, eg PT1H for 1hr
:param valid_until: a relative time eg 2w 4d 1h for 2 weeks, 4 days and 1hour from now.
:param copy: set to False to avoid making a copy of all the entities in list. This may be dangerous.
:param validate: set to False to skip schema validation of the resulting EntitiesDesciptor element. This is dangerous!

Produce an EntityDescriptors set from a list of entities. Optional Name, cacheDuration and validUntil are affixed.
    """

    if nsmap is None:
        nsmap = dict()

    def _resolve(member, l_fn):
        if hasattr(member, 'tag'):
            return [member]
        else:
            return l_fn(member)

    nsmap.update(NS)
    resolved_entities = set()
    for member in entities:
        for entity in _resolve(member, lookup_fn):
            resolved_entities.add(entity)

    if not resolved_entities:
        return None

    for entity in resolved_entities:
        nsmap.update(entity.nsmap)

    log.debug("selecting %d entities before validation" % len(resolved_entities))

    attrs = dict(Name=name, nsmap=nsmap)
    if cache_duration is not None:
        attrs['cacheDuration'] = cache_duration
    if valid_until is not None:
        attrs['validUntil'] = valid_until
    t = etree.Element("{%s}EntitiesDescriptor" % NS['md'], **attrs)
    for entity in resolved_entities:
        entity_id = entity.get('entityID', None)
        if (entity is not None) and (entity_id is not None):
            ent_insert = entity
            if copy:
                ent_insert = deepcopy(ent_insert)
            t.append(ent_insert)

    if config.devel_write_xml_to_file:
        with open("/tmp/pyff_entities_out.xml", "w") as fd:
            fd.write(dumptree(t))

    if validate:
        try:
            validate_document(t)
        except DocumentInvalid as ex:
            log.debug(xml_error(ex.error_log))
            raise MetadataException("XML schema validation failed: %s" % name)
    return t


def entities_list(t=None):
    """
        :param t: An EntitiesDescriptor or EntityDescriptor element

        Returns the list of contained EntityDescriptor elements
        """
    if t is None:
        return []
    elif root(t).tag == "{%s}EntityDescriptor" % NS['md']:
        return [root(t)]
    else:
        return iter_entities(t)


def iter_entities(t):
    if t is None:
        return []
    return t.iter('{%s}EntityDescriptor' % NS['md'])


def find_entity(t, e_id, attr='entityID'):
    for e in iter_entities(t):
        if e.get(attr) == e_id:
            return e
    return None


# semantics copied from https://github.com/lordal/md-summary/blob/master/md-summary
# many thanks to Anders Lordahl & Scotty Logan for the idea
def guess_entity_software(e):
    for elt in chain(e.findall(".//{%s}SingleSignOnService" % NS['md']),
                     e.findall(".//{%s}AssertionConsumerService" % NS['md'])):
        location = elt.get('Location')
        if location:
            if 'Shibboleth.sso' in location \
                    or 'profile/SAML2/POST/SSO' in location \
                    or 'profile/SAML2/Redirect/SSO' in location \
                    or 'profile/Shibboleth/SSO' in location:
                return 'Shibboleth'
            if location.endswith('saml2/idp/SSOService.php') or 'saml/sp/saml2-acs.php' in location:
                return 'SimpleSAMLphp'
            if location.endswith('user/authenticate'):
                return 'KalturaSSP'
            if location.endswith('adfs/ls') or location.endswith('adfs/ls/'):
                return 'ADFS'
            if '/oala/' in location or 'login.openathens.net' in location:
                return 'OpenAthens'
            if '/idp/SSO.saml2' in location or '/sp/ACS.saml2' in location \
                    or 'sso.connect.pingidentity.com' in location:
                return 'PingFederate'
            if 'idp/saml2/sso' in location:
                return 'Authentic2'
            if 'nidp/saml2/sso' in location:
                return 'Novell Access Manager'
            if 'affwebservices/public/saml2sso' in location:
                return 'CASiteMinder'
            if 'FIM/sps' in location:
                return 'IBMTivoliFIM'
            if 'sso/post' in location \
                    or 'sso/redirect' in location \
                    or 'saml2/sp/acs' in location \
                    or 'saml2/ls' in location \
                    or 'saml2/acs' in location \
                    or 'acs/redirect' in location \
                    or 'acs/post' in location \
                    or 'saml2/sp/ls/' in location:
                return 'PySAML'
            if 'engine.surfconext.nl' in location:
                return 'SURFConext'
            if 'opensso' in location:
                return 'OpenSSO'
            if 'my.salesforce.com' in location:
                return 'Salesforce'

    entity_id = e.get('entityID')
    if '/shibboleth' in entity_id:
        return 'Shibboleth'
    if entity_id.endswith('/metadata.php'):
        return 'SimpleSAMLphp'
    if '/openathens' in entity_id:
        return 'OpenAthens'

    return 'other'


def is_idp(entity):
    return has_tag(entity, "{%s}IDPSSODescriptor" % NS['md'])


def is_sp(entity):
    return has_tag(entity, "{%s}SPSSODescriptor" % NS['md'])


def is_aa(entity):
    return has_tag(entity, "{%s}AttributeAuthorityDescriptor" % NS['md'])


def _domains(entity):
    domains = [url2host(entity.get('entityID'))]
    for d in entity.iter("{%s}DomainHint" % NS['mdui']):
        if d.text not in domains:
            domains.append(d.text)
    return domains


def with_entity_attributes(entity, cb):
    def _stext(e):
        if e.text is not None:
            return e.text.strip()

    for ea in entity.iter("{%s}EntityAttributes" % NS['mdattr']):
        for a in ea.iter("{%s}Attribute" % NS['saml']):
            an = a.get('Name', None)
            if a is not None:
                values = filter(lambda x: x is not None, [_stext(v) for v in a.iter("{%s}AttributeValue" % NS['saml'])])
                cb(an, values)


def _all_domains_and_subdomains(entity):
    dlist = []
    try:
        for dn in _domains(entity):
            for sub in subdomains(dn):
                dlist.append(sub)
    except ValueError:
        pass
    return dlist


def entity_attributes(entity):
    d = {}

    def _u(an, values):
        d[an] = values

    with_entity_attributes(entity, _u)

    return d


def entity_attribute_dict(entity):
    d = {}

    def _u(an, values):
        d[an] = values

    with_entity_attributes(entity, _u)

    d[ATTRS['domain']] = _all_domains_and_subdomains(entity)

    roles = d.setdefault(ATTRS['role'], [])
    if is_idp(entity):
        roles.append('idp')
        eca = ATTRS['entity-category']
        ec = d.setdefault(eca, [])
        if 'http://refeds.org/category/hide-from-discovery' not in ec:
            ec.append('http://pyff.io/category/discoverable')
    if is_sp(entity):
        roles.append('sp')
    if is_aa(entity):
        roles.append('aa')

    if ATTRS['software'] not in d:
        d[ATTRS['software']] = [guess_entity_software(entity)]

    return d


def entity_icon(e, langs=None):
    for ico in filter_lang(e.iter("{%s}Logo" % NS['mdui']), langs=langs):
        return dict(url=ico.text, width=ico.get('width'), height=ico.get('height'))


def privacy_statement_url(entity, langs):
    for url in filter_lang(entity.iter("{%s}PrivacyStatementURL" % NS['mdui']), langs=langs):
        return url.text


def entity_geoloc(entity):
    for loc in entity.iter("{%s}GeolocationHint" % NS['mdui']):
        pos = loc.text[5:].split(",")
        return dict(lat=pos[0], long=pos[1])


def entity_domains(entity):
    domains = []
    for d in entity.iter("{%s}DomainHint" % NS['mdui']):
        if d.text == '.':
            return []
        domains.append(d.text)
    if not domains:
        domains.append(url2host(entity.get('entityID')))
    return domains


def entity_extended_display(entity, langs=None):
    """Utility-method for computing a displayable string for a given entity.

    :param entity: An EntityDescriptor element
    :param langs: The list of languages to search in priority order
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

    return trunc_str(display.strip(), 40), trunc_str(info.strip(), 256)


def entity_display_name(entity, langs=None):
    """Utility-method for computing a displayable string for a given entity.

    :param entity: An EntityDescriptor element
    :param langs: The list of languages to search in priority order
    """
    for displayName in filter_lang(entity.iter("{%s}DisplayName" % NS['mdui']), langs=langs):
        return displayName.text.strip()

    for serviceName in filter_lang(entity.iter("{%s}ServiceName" % NS['md']), langs=langs):
        return serviceName.text.strip()

    for organizationDisplayName in filter_lang(entity.iter("{%s}OrganizationDisplayName" % NS['md']), langs=langs):
        return organizationDisplayName.text.strip()

    for organizationName in filter_lang(entity.iter("{%s}OrganizationName" % NS['md']), langs=langs):
        return organizationName.text.strip()

    return entity.get('entityID').strip()


def sub_domains(e):
    lst = []
    domains = entity_domains(e)
    for d in domains:
        for sub in subdomains(d):
            if sub not in lst:
                lst.append(sub)
    return lst


def entity_scopes(e):
    elt = e.findall('.//{%s}IDPSSODescriptor/{%s}Extensions/{%s}Scope' % (NS['md'], NS['md'], NS['shibmd']))
    if elt is None or len(elt) == 0:
        return None
    return [s.text for s in elt]


def discojson(e, langs=None):
    if e is None:
        return dict()

    title, descr = entity_extended_display(e)
    entity_id = e.get('entityID')

    d = dict(title=title,
             descr=descr,
             auth='saml',
             entityID=entity_id)

    eattr = entity_attribute_dict(e)
    if 'idp' in eattr[ATTRS['role']]:
        d['type'] = 'idp'
        d['hidden'] = 'true'
        if 'http://pyff.io/category/discoverable' in eattr[ATTRS['entity-category']]:
            d['hidden'] = 'false'
    elif 'sp' in eattr[ATTRS['role']]:
        d['type'] = 'sp'

    icon_info = entity_icon(e)
    if icon_info is not None:
        d['entity_icon'] = icon_info.get('url', PLACEHOLDER_ICON)
        d['entity_icon_height'] = icon_info.get('height', 64)
        d['entity_icon_width'] = icon_info.get('width', 64)

    scopes = entity_scopes(e)
    if scopes is not None and len(scopes) > 0:
        d['scope'] = ",".join(scopes)

    keywords = filter_lang(e.iter("{%s}Keywords" % NS['mdui']), langs=langs)
    if keywords is not None:
        lst = [elt.text for elt in keywords]
        if len(lst) > 0:
            d['keywords'] = ",".join(lst)
    psu = privacy_statement_url(e, langs)
    if psu:
        d['privacy_statement_url'] = psu
    geo = entity_geoloc(e)
    if geo:
        d['geo'] = geo

    return d


def sha1_id(e):
    return hash_id(e, 'sha1')


def entity_simple_summary(e):
    if e is None:
        return dict()

    title, descr = entity_extended_display(e)
    entity_id = e.get('entityID')
    d = dict(title=title,
             descr=descr,
             entity_id=entity_id,
             entityID=entity_id,
             domains=";".join(sub_domains(e)),
             id=hash_id(e, 'sha1'))
    icon_info = entity_icon(e)
    if icon_info is not None:
        d['entity_icon'] = icon_info.get('url', PLACEHOLDER_ICON)
        d['icon_url'] = d['entity_icon']
        d['entity_icon_height'] = icon_info.get('height', 64)
        d['entity_icon_width'] = icon_info.get('width', 64)

    psu = privacy_statement_url(e, None)
    if psu:
        d['privacy_statement_url'] = psu

    return d

def entity_orgurl(entity, langs=None):
    for organizationUrl in filter_lang(entity.iter("{%s}OrganizationURL" % NS['md']), langs=langs):
        return organizationUrl.text
    return None


def entity_service_name(entity, langs=None):
    for serviceName in filter_lang(entity.iter("{%s}ServiceName" % NS['md']), langs=langs):
        return serviceName.text


def entity_service_description(entity, langs=None):
    for serviceName in filter_lang(entity.iter("{%s}ServiceDescription" % NS['md']), langs=langs):
        return serviceName.text


def entity_requested_attributes(entity, langs=None):
    return [(a.get('Name'), bool(a.get('isRequired'))) for a in
            filter_lang(entity.iter("{%s}RequestedAttribute" % NS['md']), langs=langs)]


def entity_idp(entity):
    for idp in entity.iter("{%s}IDPSSODescriptor" % NS['md']):
        return idp

    return None


def entity_sp(entity):
    for sp in entity.iter("{%s}SPSSODescriptor" % NS['md']):
        return sp

    return None


def entity_contacts(entity):
    def _contact_dict(contact):
        first_name = first_text(contact, "{%s}GivenName" % NS['md'])
        last_name = first_text(contact, "{%s}SurName" % NS['md'])
        org = first_text(entity, "{%s}OrganizationName" % NS['md']) or first_text(entity,
                                                                                  "{%s}OrganizationDisplayName" % NS[
                                                                                      'md'])
        company = first_text(entity, "{%s}Company" % NS['md'])
        mail = first_text(contact, "{%s}EmailAddress" % NS['md'])
        display_name = "Unknown"
        if first_name and last_name:
            display_name = ' '.join([first_name, last_name])
        elif first_name:
            display_name = first_name
        elif last_name:
            display_name = last_name
        elif mail:
            _, _, display_name = mail.partition(':')

        return dict(type=contact.get('contactType'),
                    first_name=first_name,
                    last_name=last_name,
                    company=company or org,
                    display_name=display_name,
                    mail=mail)

    return [_contact_dict(c) for c in entity.iter("{%s}ContactPerson" % NS['md'])]


def entity_nameid_formats(entity):
    return [nif.text for nif in entity.iter("{%s}NameIDFormat" % NS['md'])]


def entity_info(e, langs=None):
    d = entity_simple_summary(e)
    keywords = filter_lang(e.iter("{%s}Keywords" % NS['mdui']), langs=langs)
    if keywords is not None:
        lst = [elt.text for elt in keywords]
        if len(lst) > 0:
            d['keywords'] = ",".join(lst)

    d['privacy_statement_url'] = privacy_statement_url(e, langs)
    d['geo'] = entity_geoloc(e)
    d['orgurl'] = entity_orgurl(e, langs)
    d['scopes'] = entity_scopes(e)
    d['service_name'] = entity_service_name(e, langs)
    d['service_descr'] = entity_service_description(e, langs)
    d['requested_attributes'] = entity_requested_attributes(e, langs)
    d['entity_attributes'] = entity_attributes(e)
    d['contacts'] = entity_contacts(e)
    d['name_id_formats'] = entity_nameid_formats(e)
    d['is_idp'] = is_idp(e)
    d['is_sp'] = is_sp(e)
    d['is_aa'] = is_aa(e)
    d['xml'] = dumptree(e, xml_declaration=False, pretty_print=True).decode('utf8').replace('<', '&lt;').replace('>',
                                                                                                                 '&gt;')
    if d['is_idp']:
        d['protocols'] = entity_idp(e).get('protocolSupportEnumeration', "").split()

    return d


def entity_extensions(e):
    """Return a list of the Extensions elements in the EntityDescriptor

:param e: an EntityDescriptor
:return: a list
    """
    ext = e.find("./{%s}Extensions" % NS['md'])
    if ext is None:
        ext = etree.Element("{%s}Extensions" % NS['md'])
        e.insert(0, ext)
    return ext


def annotate_entity(e, category, title, message, source=None):
    """Add an ATOM annotation to an EntityDescriptor or an EntitiesDescriptor. This is a simple way to
    add non-normative text annotations to metadata, eg for the purpuse of generating reports.

:param e: An EntityDescriptor or an EntitiesDescriptor element
:param category: The ATOM category
:param title: The ATOM title
:param message: The ATOM content
:param source: An optional source URL. It is added as a <link> element with @rel='saml-metadata-source'
    """
    if e.tag != "{%s}EntityDescriptor" % NS['md'] and e.tag != "{%s}EntitiesDescriptor" % NS['md']:
        raise MetadataException('I can only annotate EntityDescriptor or EntitiesDescriptor elements')
    subject = e.get('Name', e.get('entityID', None))
    atom = ElementMaker(nsmap={'atom': 'http://www.w3.org/2005/Atom'}, namespace='http://www.w3.org/2005/Atom')
    args = [atom.published("%s" % datetime.now().isoformat()),
            atom.link(href=subject, rel="saml-metadata-subject")]
    if source is not None:
        args.append(atom.link(href=source, rel="saml-metadata-source"))
    args.extend([atom.title(title),
                 atom.category(term=category),
                 atom.content(message, type="text/plain")])
    entity_extensions(e).append(atom.entry(*args))


def _entity_attributes(e):
    ext = entity_extensions(e)
    ea = ext.find(".//{%s}EntityAttributes" % NS['mdattr'])
    if ea is None:
        ea = etree.Element("{%s}EntityAttributes" % NS['mdattr'])
        ext.append(ea)
    return ea


def _eattribute(e, attr, nf):
    ea = _entity_attributes(e)
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


def set_entity_attributes(e, d, nf=NF_URI):
    """Set an entity attribute on an EntityDescriptor

:param e: The EntityDescriptor element
:param d: A dict of attribute-value pairs that should be added as entity attributes
:param nf: The nameFormat (by default "urn:oasis:names:tc:SAML:2.0:attrname-format:uri") to use.
:raise: MetadataException unless e is an EntityDescriptor element
    """
    if e.tag != "{%s}EntityDescriptor" % NS['md']:
        raise MetadataException("I can only add EntityAttribute(s) to EntityDescriptor elements")

    for attr, value in d.items():
        a = _eattribute(e, attr, nf)
        velt = etree.Element("{%s}AttributeValue" % NS['saml'])
        velt.text = value
        a.append(velt)


def set_pubinfo(e, publisher=None, creation_instant=None):
    if e.tag != "{%s}EntitiesDescriptor" % NS['md']:
        raise MetadataException("I can only set RegistrationAuthority to EntitiesDescriptor elements")
    if publisher is None:
        raise MetadataException("At least publisher must be provided")

    if creation_instant is None:
        now = datetime.utcnow()
        creation_instant = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    ext = entity_extensions(e)
    pi = ext.find(".//{%s}PublicationInfo" % NS['mdrpi'])
    if pi is not None:
        raise MetadataException("A PublicationInfo element is already present")
    pi = etree.Element("{%s}PublicationInfo" % NS['mdrpi'])
    pi.set('publisher', publisher)
    if creation_instant:
        pi.set('creationInstant', creation_instant)
    ext.append(pi)


def set_reginfo(e, policy=None, authority=None):
    if e.tag != "{%s}EntityDescriptor" % NS['md']:
        raise MetadataException("I can only set RegistrationAuthority to EntityDescriptor elements")
    if authority is None:
        raise MetadataException("At least authority must be provided")
    if policy is None:
        policy = dict()

    ext = entity_extensions(e)
    ri = ext.find(".//{%s}RegistrationInfo" % NS['mdrpi'])
    if ri is not None:
        raise MetadataException("A RegistrationInfo element is already present")

    ri = etree.Element("{%s}RegistrationInfo" % NS['mdrpi'])
    ext.append(ri)
    ri.set('registrationAuthority', authority)
    for lang, policy_url in policy.items():
        rp = etree.Element("{%s}RegistrationPolicy" % NS['mdrpi'])
        rp.text = policy_url
        rp.set('{%s}lang' % NS['xml'], lang)
        ri.append(rp)


def expiration(t):
    relt = root(t)
    if relt.tag in ('{%s}EntityDescriptor' % NS['md'], '{%s}EntitiesDescriptor' % NS['md']):
        cache_duration = config.default_cache_duration
        valid_until = relt.get('validUntil', None)
        if valid_until is not None:
            now = datetime.utcnow()
            vu = iso2datetime(valid_until)
            now = now.replace(microsecond=0)
            vu = vu.replace(microsecond=0, tzinfo=None)
            return vu - now
        elif config.respect_cache_duration:
            cache_duration = relt.get('cacheDuration', config.default_cache_duration)
            return duration2timedelta(cache_duration)

    return None
