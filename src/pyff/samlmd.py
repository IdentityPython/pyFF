import json
import traceback
from base64 import b64decode
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from str2bool import str2bool
from io import BytesIO
from itertools import chain
from typing import Any, Dict, List, Optional, Union

from lxml import etree
from lxml.builder import ElementMaker
from lxml.etree import DocumentInvalid, Element, ElementTree
from pydantic import Field
from xmlsec.crypto import CertDict
from .resource import Resource, ResourceHandler, ResourceOpts

from pyff.constants import ATTRS, NF_URI, NS, config
from pyff.exceptions import *
from pyff.logs import get_log
from pyff.parse import ParserInfo, PyffParser, add_parser
from pyff.resource import Resource, ResourceOpts
from pyff.utils import (
    Lambda,
    b2u,
    check_signature,
    datetime2iso,
    dumptree,
    duration2timedelta,
    filter_lang,
    first_text,
    has_tag,
    hash_id,
    is_text,
    iso2datetime,
    lang_dict,
    load_callable,
    parse_xml,
    root,
    rreplace,
    schema,
    subdomains,
    unicode_stream,
    url2host,
    utc_now,
    validate_document,
    xml_error,
)

log = get_log(__name__)


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
        for e in list(self._e.values()):
            yield e

    def __len__(self):
        return len(list(self._e.keys()))

    def __contains__(self, item):
        return item.get('entityID') in list(self._e.keys())


def find_merge_strategy(strategy_name):
    if '.' not in strategy_name:
        strategy_name = "pyff.merge_strategies:%s" % strategy_name
    if ':' not in strategy_name:
        # TODO: BUG: Parameter 'occurrence' unfilled
        strategy_name = rreplace(strategy_name, '.', ':')  # backwards compat for old way of specifying these
    return load_callable(strategy_name)


def parse_saml_metadata(
    source: BytesIO, opts: ResourceOpts, base_url=None, validation_errors: Optional[Dict[str, Any]] = None,
):
    """Parse a piece of XML and return an EntitiesDescriptor element after validation.

    :param source: a file-like object containing SAML metadata
    :param opts: ResourceOpts instance
    :param base_url: use this base url to resolve relative URLs for XInclude processing
    :param validation_errors: A dict that will be used to return validation errors to the caller

    :return: Tuple with t (ElementTree), trust_info, expire_time_offset, exception
    """

    if validation_errors is None:
        validation_errors = dict()

    try:
        t = parse_xml(source, base_url=base_url)
        if config.xinclude:
            t.xinclude()

        expire_time_offset = metadata_expiration(t)

        t = check_signature(t, opts.verify)

        trust_info = None
        extensions = t.find('{%s}Extensions' % NS['md'])

        if opts.cleanup is not None:
            for cb in opts.cleanup:
                t = cb(t)
        else:  # at least get rid of ID attribute
            for e in iter_entities(t):
                if e.get('ID') is not None:
                    del e.attrib['ID']

        t = root(t)

        filter_invalid = opts.filter_invalid
        if opts.fail_on_error:
            filter_invalid = False

        if opts.validate_schema:
            t = filter_or_validate(
                t, filter_invalid=filter_invalid, base_url=base_url, source=source, validation_errors=validation_errors
            )

        if t is not None:
            if t.tag == "{%s}EntityDescriptor" % NS['md']:
                t = entitiesdescriptor(
                    [t], base_url, copy=False, validate=True, filter_invalid=filter_invalid, nsmap=t.nsmap
                )
            elif t.tag == "{%s}EntitiesDescriptor" % NS['md'] and extensions is not None:
                trust_info = discojson_sp(extensions)

    except Exception as ex:
        log.debug(traceback.format_exc())
        log.error("Error parsing {}: {}".format(base_url, ex))
        if opts.fail_on_error:
            raise ex

        return None, None, None, ex

    log.debug("returning %d valid entities" % len(list(iter_entities(t))))

    return t, trust_info, expire_time_offset, None


class SAMLParserInfo(ParserInfo):
    entities: List[str] = Field([])  # list of entity ids


class SAMLMetadataResourceParser(PyffParser):
    def __init__(self):
        pass

    def __str__(self):
        return "SAML"

    def magic(self, content: str) -> bool:
        return "EntitiesDescriptor" in content or "EntityDescriptor" in content

    def parse(self, resource: Resource, content: str) -> SAMLParserInfo:
        info = SAMLParserInfo(description='SAML Metadata', expiration_time='')
        t, trust_info, expire_time_offset, exception = parse_saml_metadata(
            unicode_stream(content),
            base_url=resource.url,
            opts=resource.opts,
            validation_errors=info.validation_errors,
        )

        if expire_time_offset is not None:
            now = utc_now()
            now = now.replace(microsecond=0)

            expire_time = now + expire_time_offset
            resource.expire_time = expire_time
            info.expiration_time = str(expire_time)

        def _extra_md(_t, info, **kwargs):
            entityID = kwargs.get('entityID')
            if info['alias'] != entityID:
                return _t
            sp_entities = kwargs.get('sp_entities')
            location = kwargs.get('location')
            sp_entity = sp_entities.find("{%s}EntityDescriptor[@entityID='%s']" % (NS['md'], entityID))
            if sp_entity is not None:
                md_source = sp_entity.find("{%s}SPSSODescriptor/{%s}Extensions/{%s}TrustInfo/{%s}MetadataSource[@src='%s']" % (NS['md'], NS['md'], NS['ti'], NS['ti'], location))
                for e in iter_entities(_t):
                    md_source.append(e)
            return etree.Element("{%s}EntitiesDescriptor" % NS['md'])

        if t is not None:
            resource.t = t
            resource.type = "application/samlmetadata+xml"

            for e in iter_entities(t):
                entityID = e.get('entityID')
                info.entities.append(entityID)

                md_source = e.find("{%s}SPSSODescriptor/{%s}Extensions/{%s}TrustInfo/{%s}MetadataSource" % (NS['md'], NS['md'], NS['ti'], NS['ti']))
                if md_source is not None:
                    location = md_source.attrib.get('src')
                    if location is not None:
                        child_opts = resource.opts.copy(update={'alias': entityID})
                        r = resource.add_child(location, child_opts)
                        kwargs = {
                            'entityID': entityID,
                            'sp_entities': t,
                            'location': location,
                        }
                        r.add_via(Lambda(_extra_md, **kwargs))

        if trust_info is not None:
            resource.trust_info = trust_info

        if exception is not None:
            resource.info.exception = exception

        return info


add_parser(SAMLMetadataResourceParser())


class EidasMDParserInfo(ParserInfo):
    version: Optional[str] = None
    issue_date: Optional[str] = None  # TODO: change to datetime?
    next_update: Optional[Union[str, datetime]] = None  # TODO: consistently use datetime
    issuer_name: Optional[str] = None
    scheme_identifier: Optional[str] = None
    scheme_territory: Optional[str] = None

    def to_dict(self):
        def _format_key(k: str) -> str:
            # TODO: Why don't these have space as word separator like the rest of ParserInfo?
            special = {
                'next_update': 'NextUpdate',
                'issue_date': 'IssueDate',
                'issuer_name': 'IssuerName',
                'scheme_identifier': 'SchemeIdentifier',
                'scheme_territory': 'SchemeTerritory',
            }
            if k in special:
                return special[k]
            # Turn expiration_time into 'Expiration Time'
            return k.replace('_', ' ').title()

        res = {_format_key(k): v for k, v in self.dict().items()}
        return res


class MDServiceListParser(PyffParser):
    def __init__(self):
        pass

    def __str__(self):
        return "MDSL"

    def magic(self, content: str) -> bool:
        return 'MetadataServiceList' in content

    def parse(self, resource: Resource, content: str) -> EidasMDParserInfo:
        info = EidasMDParserInfo(description='eIDAS MetadataServiceList', expiration_time='None')
        t = parse_xml(unicode_stream(content))
        if config.xinclude:
            t.xinclude()
        relt = root(t)
        info.version = relt.get('Version', '0')
        info.issue_date = relt.get('IssueDate')
        info.next_update = relt.get('NextUpdate')
        if isinstance(info.next_update, str):
            resource.expire_time = iso2datetime(info.next_update)
        elif config.respect_cache_duration:
            duration = duration2timedelta(config.default_cache_duration)
            if not duration:
                # TODO: what is the right action here?
                raise ValueError(f'Invalid default cache duration: {config.default_cache_duration}')
            info.next_update = utc_now().replace(microsecond=0) + duration
            resource.expire_time = info.next_update

        info.expiration_time = 'None' if not resource.expire_time else resource.expire_time.isoformat()
        info.issuer_name = first_text(relt, "{%s}IssuerName" % NS['ser'])
        info.scheme_identifier = first_text(relt, "{%s}SchemeIdentifier" % NS['ser'])
        info.scheme_territory = first_text(relt, "{%s}SchemeTerritory" % NS['ser'])
        for mdl in relt.iter("{%s}MetadataList" % NS['ser']):
            for ml in mdl.iter("{%s}MetadataLocation" % NS['ser']):
                location = ml.get('Location')
                if location:
                    certs = CertDict(ml)
                    fingerprints = list(certs.keys())
                    fp = None
                    if len(fingerprints) > 0:
                        fp = fingerprints[0]

                    ep = ml.find("{%s}Endpoint" % NS['ser'])
                    if ep is not None and fp is not None:
                        args = dict(
                            country_code=mdl.get('Territory'),
                            hide_from_discovery=str2bool(ep.get('HideFromDiscovery', 'false')),
                        )
                        log.debug(
                            "MDSL[{}]: {} verified by {} for country {}".format(
                                info.scheme_territory, location, fp, args.get('country_code')
                            )
                        )
                        child_opts = resource.opts.copy(update={'alias': None})
                        child_opts.verify = fp
                        r = resource.add_child(location, child_opts)

                        # this is specific post-processing for MDSL files
                        def _update_entities(_t, **kwargs):
                            _country_code = kwargs.get('country_code')
                            _hide_from_discovery = kwargs.get('hide_from_discovery')
                            for e in iter_entities(_t):
                                if _country_code:
                                    set_nodecountry(e, _country_code)
                                if bool(_hide_from_discovery) and is_idp(e):
                                    set_entity_attributes(
                                        e, {ATTRS['entity-category']: 'http://refeds.org/category/hide-from-discovery'}
                                    )
                            return _t

                        r.add_via(Lambda(_update_entities, **args))

        log.debug("Done parsing eIDAS MetadataServiceList")
        resource.last_seen = utc_now().replace(microsecond=0)
        resource.expire_time = None
        return info


add_parser(MDServiceListParser())


def metadata_expiration(t: ElementTree) -> Optional[timedelta]:
    relt = root(t)
    if relt.tag in ('{%s}EntityDescriptor' % NS['md'], '{%s}EntitiesDescriptor' % NS['md']):
        cache_duration = config.default_cache_duration
        valid_until = relt.get('validUntil', None)
        if valid_until is not None:
            now = utc_now().replace(microsecond=0).replace(tzinfo=None)
            vu = iso2datetime(valid_until)
            vu = vu.replace(microsecond=0).replace(tzinfo=None)
            return vu - now
        elif config.respect_cache_duration:
            cache_duration = relt.get('cacheDuration', config.default_cache_duration)
            if not cache_duration:
                cache_duration = config.default_cache_duration
            return duration2timedelta(cache_duration)

    return None


def filter_invalids_from_document(t: ElementTree, base_url, validation_errors) -> ElementTree:
    xsd = schema()
    for e in iter_entities(t):
        if not xsd.validate(e):
            error = xml_error(xsd.error_log, m=base_url)
            entity_id = e.get("entityID", "(Missing entityID)")
            log.warning('removing \'%s\': schema validation failed: %s' % (entity_id, xsd.error_log))
            validation_errors[entity_id] = "{}".format(xsd.error_log)
            if e.getparent() is None:
                return None
            e.getparent().remove(e)
    return t


def filter_or_validate(
    t: ElementTree,
    filter_invalid: bool = False,
    base_url: str = "",
    source=None,
    validation_errors: Optional[Dict[str, Any]] = None,
) -> ElementTree:
    if validation_errors is None:
        validation_errors = {}
    log.debug("Filtering invalids from {}".format(base_url))
    if filter_invalid:
        t = filter_invalids_from_document(t, base_url=base_url, validation_errors=validation_errors)
        for entity_id, err in validation_errors.items():
            log.error(
                "Validation error while parsing {} (from {}). Removed @entityID='{}': {}".format(
                    base_url, source, entity_id, err
                )
            )
    else:  # all or nothing
        log.debug("Validating (one-shot) {}".format(base_url))
        try:
            validate_document(t)
        except DocumentInvalid as ex:
            err = xml_error(ex.error_log, m=base_url)
            validation_errors[base_url] = err
            raise MetadataException("Validation error while parsing {}: (from {}): {}".format(base_url, source, err))

    return t


def resolve_entities(entities, lookup_fn=None, dedup=True):
    """

    :param entities: a set of entities specifiers (lookup is used to find entities from this set)
    :param lookup_fn:  a function used to lookup entities by name
    :return: a set of entities
    """

    def _resolve(m, l_fn):
        if hasattr(m, 'tag'):
            return [m]
        else:
            return l_fn(m)

    if dedup:
        resolved_entities = dict()  # a set won't do since __compare__ doesn't use @entityID
    else:
        resolved_entities = []
    for member in entities:
        for entity in _resolve(member, lookup_fn):
            entity_id = entity.get('entityID', None)
            if entity is not None and entity_id is not None:
                if dedup:
                    resolved_entities[entity_id] = entity
                else:
                    resolved_entities.append(entity)
    if dedup:
        return resolved_entities.values()
    return resolved_entities


def entitiesdescriptor(
    entities,
    name,
    lookup_fn=None,
    cache_duration=None,
    valid_until=None,
    validate=True,
    filter_invalid=True,
    copy=True,
    nsmap=None,
):
    """
    :param lookup_fn: a function used to lookup entities by name - set to None to skip resolving
    :param entities: a set of entities specifiers (lookup is used to find entities from this set)
    :param name: the @Name attribute
    :param cache_duration: an XML timedelta expression, eg PT1H for 1hr
    :param valid_until: a relative time eg 2w 4d 1h for 2 weeks, 4 days and 1hour from now.
    :param copy: set to False to avoid making a copy of all the entities in list. This may be dangerous.
    :param validate: set to False to skip schema validation of the resulting EntitiesDescriptor element. This is dangerous!
    :param filter_invalid: remove invalid EntitiesDescriptor elements from aggregate
    :param nsmap: additional namespace definitions to include in top level EntitiesDescriptor element

    Produce an EntityDescriptors set from a list of entities. Optional Name, cacheDuration and validUntil are affixed.
    """

    if nsmap is None:
        nsmap = dict()

    nsmap.update(NS)

    if lookup_fn is not None:
        entities = resolve_entities(entities, lookup_fn=lookup_fn)

    for entity in entities:
        nsmap.update(entity.nsmap)

    log.debug("selecting %d entities before validation" % len(entities))

    attrs = dict(Name=name, nsmap=nsmap)
    if cache_duration is not None:
        attrs['cacheDuration'] = cache_duration
    if valid_until is not None:
        attrs['validUntil'] = valid_until
    t = etree.Element("{%s}EntitiesDescriptor" % NS['md'], **attrs)
    for entity in entities:
        ent_insert = entity
        if copy:
            ent_insert = deepcopy(ent_insert)
        t.append(ent_insert)

    if config.devel_write_xml_to_file:
        import os

        with open("/tmp/pyff_entities_out-{}.xml".format(os.getpid()), "w") as fd:
            fd.write(b2u(dumptree(t)))

    if validate:
        validation_errors = dict()
        t = filter_or_validate(
            t, filter_invalid=filter_invalid, base_url=name, source="request", validation_errors=validation_errors
        )

        for base_url, err in validation_errors.items():
            log.error("Validation error: @ {}: {}".format(base_url, err))

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
    for elt in chain(
        e.findall(".//{%s}SingleSignOnService" % NS['md']), e.findall(".//{%s}AssertionConsumerService" % NS['md'])
    ):
        location = elt.get('Location')
        if location:
            if (
                'Shibboleth.sso' in location
                or 'profile/SAML2/POST/SSO' in location
                or 'profile/SAML2/Redirect/SSO' in location
                or 'profile/Shibboleth/SSO' in location
            ):
                return 'Shibboleth'
            if location.endswith('saml2/idp/SSOService.php') or 'saml/sp/saml2-acs.php' in location:
                return 'SimpleSAMLphp'
            if location.endswith('user/authenticate'):
                return 'KalturaSSP'
            if location.endswith('adfs/ls') or location.endswith('adfs/ls/'):
                return 'ADFS'
            if '/oala/' in location or 'login.openathens.net' in location:
                return 'OpenAthens'
            if (
                '/idp/SSO.saml2' in location
                or '/sp/ACS.saml2' in location
                or 'sso.connect.pingidentity.com' in location
            ):
                return 'PingFederate'
            if 'idp/saml2/sso' in location:
                return 'Authentic2'
            if 'nidp/saml2/sso' in location:
                return 'Novell Access Manager'
            if 'affwebservices/public/saml2sso' in location:
                return 'CASiteMinder'
            if 'FIM/sps' in location:
                return 'IBMTivoliFIM'
            if (
                'sso/post' in location
                or 'sso/redirect' in location
                or 'saml2/sp/acs' in location
                or 'saml2/ls' in location
                or 'saml2/acs' in location
                or 'acs/redirect' in location
                or 'acs/post' in location
                or 'saml2/sp/ls/' in location
            ):
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
                values = [x for x in [_stext(v) for v in a.iter("{%s}AttributeValue" % NS['saml'])] if x is not None]
                cb(an, values)


def _all_domains_and_subdomains(entity):
    dlist = []
    try:
        for dn in _domains(entity):
            for sub in subdomains(dn):
                if len(sub) > 1:  # TLD
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


def find_in_document(t, member):
    relt = root(t)
    if is_text(member):
        if '!' in member:
            (src, xp) = member.split("!")
            return relt.xpath(xp, namespaces=NS, smart_strings=False)
        else:
            lst = []
            for e in iter_entities(relt):
                if e.get('entityID') == member:
                    lst.append(e)
            return lst
    raise MetadataException("unknown format for filtr member: %s" % member)


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


def gen_icon(e):
    scopes = entity_scopes(e)


def entity_icon_url(e, langs=None):
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


def entity_extended_display_i18n(entity, default_lang=None):

    name_dict = lang_dict(entity.iter("{%s}OrganizationName" % NS['md']), lambda e: e.text, default_lang=default_lang)
    name_dict.update(
        lang_dict(entity.iter("{%s}OrganizationDisplayName" % NS['md']), lambda e: e.text, default_lang=default_lang)
    )
    name_dict.update(lang_dict(entity.iter("{%s}ServiceName" % NS['md']), lambda e: e.text, default_lang=default_lang))
    name_dict.update(
        lang_dict(entity.iter("{%s}DisplayName" % NS['mdui']), lambda e: e.text, default_lang=default_lang)
    )

    desc_dict = lang_dict(entity.iter("{%s}OrganizationURL" % NS['md']), lambda e: e.text, default_lang=default_lang)
    desc_dict.update(
        lang_dict(entity.iter("{%s}Description" % NS['mdui']), lambda e: e.text, default_lang=default_lang)
    )

    return name_dict, desc_dict


def entity_attribute(entity, attribute):
    values = None
    els = entity.findall(
        './/{%s}EntityAttributes/{%s}Attribute[@Name="%s"]/{%s}AttributeValue'
        % (NS['mdattr'], NS['saml'], attribute, NS['saml'])
    )
    if len(els) > 0:
        values = [el.text for el in els]
    return values


def entity_categories(entity):
    cats = None
    cats_els = entity.findall(
        './/{%s}EntityAttributes/{%s}Attribute[@Name="http://macedir.org/entity-category"]/{%s}AttributeValue'
        % (NS['mdattr'], NS['saml'], NS['saml'])
    )
    if len(cats_els) > 0:
        cats = [el.text for el in cats_els]
    return cats


def assurance_cetification(entity):
    certs = None
    certs_els = entity.findall(
        './/{%s}EntityAttributes/{%s}Attribute[@Name="urn:oasis:names:tc:SAML:attribute:assurance-certification"]/{%s}AttributeValue'
        % (NS['mdattr'], NS['saml'], NS['saml'])
    )
    if len(certs_els) > 0:
        certs = [el.text for el in certs_els]
    return certs


def entity_category_support(entity):
    cats = None
    cats_els = entity.findall(
        './/{%s}EntityAttributes/{%s}Attribute[@Name="http://macedir.org/entity-category-support"]/{%s}AttributeValue'
        % (NS['mdattr'], NS['saml'], NS['saml'])
    )
    if len(cats_els) > 0:
        cats = [el.text for el in cats_els]
    return cats


def registration_authority(entity):
    regauth_el = entity.find(".//{%s}RegistrationInfo" % NS['mdrpi'])
    if regauth_el is not None:
        return regauth_el.attrib.get('registrationAuthority')


def discovery_responses(entity):
    responses = None
    responses_els = entity.findall(".//{%s}DiscoveryResponse" % NS['idpdisc'])
    if len(responses_els) > 0:
        responses = [el.attrib.get('Location') for el in responses_els]
    return responses


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
        break

    for organizationDisplayName in filter_lang(entity.iter("{%s}OrganizationDisplayName" % NS['md']), langs=langs):
        info = display
        display = organizationDisplayName.text
        break

    for serviceName in filter_lang(entity.iter("{%s}ServiceName" % NS['md']), langs=langs):
        info = display
        display = serviceName.text
        break

    for displayName in filter_lang(entity.iter("{%s}DisplayName" % NS['mdui']), langs=langs):
        info = display
        display = displayName.text
        break

    for organizationUrl in filter_lang(entity.iter("{%s}OrganizationURL" % NS['md']), langs=langs):
        info = organizationUrl.text
        break

    for description in filter_lang(entity.iter("{%s}Description" % NS['mdui']), langs=langs):
        info = description.text
        break

    if info == entity.get('entityID'):
        info = ''

    return display.strip(), info.strip()


def entity_display_name(entity: Element, langs=None) -> str:
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


def discojson(e, sources=None, langs=None, fallback_to_favicon=False, icon_store=None):
    if e is None:
        return dict()

    title, descr = entity_extended_display(e)
    entity_id = e.get('entityID')
    title_langs, descr_langs = entity_extended_display_i18n(e)
    reg_auth = registration_authority(e)
    categories = entity_attribute(e, "http://macedir.org/entity-category")
    certifications = entity_attribute(e, "urn:oasis:names:tc:SAML:attribute:assurance-certification")
    cat_support = entity_attribute(e, "http://macedir.org/entity-category-support")
    disc_responses = discovery_responses(e)

    d = dict(
        title=title,
        descr=descr,
        title_langs=title_langs,
        descr_langs=descr_langs,
        auth='saml',
        entity_id=entity_id,
        entityID=entity_id,
    )
    if reg_auth is not None:
        d['registrationAuthority'] = reg_auth

    if categories is not None:
        d['entity_category'] = categories

    if certifications is not None:
        d['assurance_certification'] = certifications

    if cat_support is not None:
        d['entity_category_support'] = cat_support

    if sources is not None:
        d['md_source'] = sources

    if disc_responses is not None:
        d["discovery_responses"] = disc_responses

    eattr = entity_attribute_dict(e)
    if 'idp' in eattr[ATTRS['role']]:
        d['type'] = 'idp'
        d['hidden'] = 'true'
        if 'http://pyff.io/category/discoverable' in eattr[ATTRS['entity-category']]:
            d['hidden'] = 'false'
    elif 'sp' in eattr[ATTRS['role']]:
        d['type'] = 'sp'

    scopes = entity_scopes(e)
    if scopes is not None and len(scopes) > 0:
        d['scope'] = ",".join(scopes)
        if len(scopes) == 1:
            d['domain'] = scopes[0]
            d['name_tag'] = (scopes[0].split('.'))[0].upper()

    icon_info = entity_icon_url(e)
    if icon_info is not None:
        if icon_store is not None and 'url' in icon_info:
            ico = icon_store.lookup(icon_info['url'])
            if ico is not None:
                icon_info['url'] = ico
        d['entity_icon_url'] = icon_info

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


def discojson_t(t, resource, icon_store=None):
    md_sources = resource.global_md_sources()
    entities = []
    for en in iter_entities(t):
        entity_id = en.attrib['entityID']
        sources = md_sources[entity_id]
        entity = discojson(en, sources=sources, icon_store=icon_store)
        entities.append(entity)
    return entities


def discojson_sp(e, global_trust_info=None, global_md_sources=None):
    sp = {}

    tinfo_el = e.find('.//{%s}TrustInfo' % NS['ti'])
    if tinfo_el is None:
        return None

    sp['entityID'] = e.get('entityID', None)

    md_sources = e.findall("{%s}SPSSODescriptor/{%s}Extensions/{%s}TrustInfo/{%s}MetadataSource" % (NS['md'], NS['md'], NS['ti'], NS['ti']))

    sp['extra_md'] = {}
    for md_source in md_sources:
        dname_external = {}
        for dname in md_source.iterfind('.//{%s}DisplayName' % NS['ti']):
            lang = dname.attrib['{%s}lang' % NS['xml']]
            dname_external[lang] = dname.text

        for idp in md_source.findall("{%s}EntityDescriptor" % NS['md']):
            idp_json = discojson(idp)
            idp_json['hint'] = dname_external
            sp['extra_md'][idp_json['entityID']] = idp_json

    sp['profiles'] = {}
    # Grab trust profile emements, and translate to json
    for profile_el in tinfo_el.findall('.//{%s}TrustProfile' % NS['ti']):
        name = profile_el.attrib['name']
        strict = profile_el.attrib.get('strict', True)
        strict = strict if type(strict) is bool else strict in ('t', 'T', 'true', 'True')
        sp['profiles'][name] = {'strict': strict, 'entity': [], 'entities': []}

        display_name = {}
        for dname in profile_el.iterfind('.//{%s}DisplayName' % NS['ti']):
            lang = dname.attrib['{%s}lang' % NS['xml']]
            display_name[lang] = dname.text
        sp['profiles'][name]['display_name'] = display_name

        fallback_handler = profile_el.find('.//{%s}FallbackHandler' % NS['ti'])
        if fallback_handler is not None:
            prof = fallback_handler.attrib.get('profile', 'href')
            handler = fallback_handler.text
            sp['profiles'][name]['fallback_handler'] = {'profile': prof, 'handler': handler}

        for entity_el in profile_el.findall('.//{%s}TrustedEntity' % NS['ti']):
            entity_id = entity_el.text
            include = entity_el.attrib.get('include', True)
            include = include if type(include) is bool else include in ('t', 'T', 'true', 'True')
            sp['profiles'][name]['entity'].append({'entity_id': entity_id, 'include': include})

        for entities_el in profile_el.findall('.//{%s}TrustedEntities' % NS['ti']):
            select = entities_el.text
            match = entities_el.attrib.get('match', 'registrationAuthority')
            include = entities_el.attrib.get('include', True)
            include = include if type(include) is bool else include in ('t', 'T', 'true', 'True')
            sp['profiles'][name]['entities'].append({'select': select, 'match': match, 'include': include})

    if global_trust_info is not None and global_md_sources is not None:
        for profileref_el in tinfo_el.findall('.//{%s}TrustProfileRef' % NS['ti']):
            refname = profileref_el.text
            sources = global_md_sources[sp['entityID']]
            for source in sources:
                if refname in global_trust_info[source]:
                    sp['profiles'][refname] = global_trust_info[source][refname]
                    break

    return sp


def discojson_sp_attr(e):

    attribute = "https://refeds.org/entity-selection-profile"
    b64_trustinfos = entity_attribute(e, attribute)
    if b64_trustinfos is None:
        return None

    sp = {}
    sp['entityID'] = e.get('entityID', None)
    sp['profiles'] = {}

    for b64_trustinfo in b64_trustinfos:
        str_trustinfo = b64decode(b64_trustinfo.encode('ascii'))
        trustinfo = json.loads(str_trustinfo.decode('utf8'))
        sp['profiles'].update(trustinfo['profiles'])

    return sp


def discojson_sp_t(req):
    d = []
    t = req.t
    global_tinfo = req.md.rm.global_trust_info()
    global_sources = req.md.rm.global_md_sources()

    for e in iter_entities(t):
        sp = discojson_sp(e, global_trust_info=global_tinfo, global_md_sources=global_sources)
        if sp is not None:
            d.append(sp)

        sp = discojson_sp_attr(e)
        if sp is not None:
            d.append(sp)

    return d


def discojson_sp_attr_t(req):
    d = []
    t = req.t

    for e in iter_entities(t):
        sp = discojson_sp_attr(e)
        if sp is not None:
            d.append(sp)

    return d


def sha1_id(e):
    return hash_id(e, 'sha1')


def entity_simple_summary(e):
    if e is None:
        return dict()

    title, descr = entity_extended_display(e)
    entity_id = e.get('entityID')
    d = dict(
        title=title,
        descr=descr,
        auth='saml',
        entity_id=entity_id,
        entityID=entity_id,
        domains=";".join(sub_domains(e)),
        id=hash_id(e, 'sha1'),
    )

    scopes = entity_scopes(e)
    if scopes is not None and len(scopes) > 0:
        d['scopes'] = " ".join(scopes)

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
    return None


def entity_service_description(entity, langs=None):
    for serviceName in filter_lang(entity.iter("{%s}ServiceDescription" % NS['md']), langs=langs):
        return serviceName.text
    return None


def entity_requested_attributes(entity, langs=None):
    return [
        (a.get('Name'), bool(a.get('isRequired')))
        for a in filter_lang(entity.iter("{%s}RequestedAttribute" % NS['md']), langs=langs)
    ]


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
        org = first_text(entity, "{%s}OrganizationName" % NS['md']) or first_text(
            entity, "{%s}OrganizationDisplayName" % NS['md']
        )
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

        return dict(
            type=contact.get('contactType'),
            first_name=first_name,
            last_name=last_name,
            company=company or org,
            display_name=display_name,
            mail=mail,
        )

    return [_contact_dict(c) for c in entity.iter("{%s}ContactPerson" % NS['md'])]


def entity_nameid_formats(entity):
    return [nif.text for nif in entity.iter("{%s}NameIDFormat" % NS['md'])]


def object_id(e):
    return e.get('entityID')


def entity_simple_info(e, langs=None):
    d = entity_simple_summary(e)
    d['service_name'] = entity_service_name(e, langs)
    d['service_descr'] = entity_service_description(e, langs)
    d['entity_attributes'] = entity_attribute_dict(e)
    keywords = filter_lang(e.iter("{%s}Keywords" % NS['mdui']), langs=langs)
    if keywords is not None:
        lst = [elt.text for elt in keywords]
        if len(lst) > 0:
            d['keywords'] = ",".join(lst)
    return d


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
    d['service_name'] = entity_service_name(e, langs)
    d['service_descr'] = entity_service_description(e, langs)
    d['requested_attributes'] = entity_requested_attributes(e, langs)
    d['entity_attributes'] = entity_attribute_dict(e)
    d['contacts'] = entity_contacts(e)
    d['name_id_formats'] = entity_nameid_formats(e)
    d['is_idp'] = is_idp(e)
    d['is_sp'] = is_sp(e)
    d['is_aa'] = is_aa(e)
    d['xml'] = (
        dumptree(e, xml_declaration=False, pretty_print=True).decode('utf8').replace('<', '&lt;').replace('>', '&gt;')
    )
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
    args = [atom.published("%s" % datetime.now().isoformat()), atom.link(href=subject, rel="saml-metadata-subject")]
    if source is not None:
        args.append(atom.link(href=source, rel="saml-metadata-source"))
    args.extend([atom.title(title), atom.category(term=category), atom.content(message, type="text/plain")])
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
    a = ea.xpath(".//saml:Attribute[@NameFormat='%s' and @Name='%s']" % (nf, attr), namespaces=NS, smart_strings=False)
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
        creation_instant = datetime2iso(utc_now())

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
        ext.remove(ri)

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
            now = utc_now().replace(microsecond=0)
            vu = iso2datetime(valid_until)
            return vu - now
        elif config.respect_cache_duration:
            cache_duration = relt.get('cacheDuration', config.default_cache_duration)
            return duration2timedelta(cache_duration)

    return None


def sort_entities(t, sxp=None):
    """
    Sorts the working entities 't' by the value returned by the xpath 'sxp'
    By default, entities are sorted by 'entityID' when this method is called without 'sxp', and otherwise as
    second criteria.
    Entities where no value exists for the given 'sxp' are sorted last.

    :param t: An element tree containing the entities to sort
    :param sxp: xpath expression selecting the value used for sorting the entities"""

    def get_key(e):
        eid = e.attrib.get('entityID')
        sv = None
        try:
            sxp_values = e.xpath(sxp, namespaces=NS, smart_strings=False)
            try:
                sv = sxp_values[0]
                try:
                    sv = sv.text
                except AttributeError:
                    pass
            except IndexError:
                log.warning("Sort pipe: unable to sort entity by '%s'. " "Entity '%s' has no such value" % (sxp, eid))
        except TypeError:
            pass

        log.debug("Generated sort key for entityID='%s' and %s='%s'" % (eid, sxp, sv))
        return sv is None, sv, eid

    container = root(t)
    container[:] = sorted(container, key=lambda e: get_key(e))


def set_nodecountry(e, country_code):
    """Set eidas:NodeCountry on an EntityDescriptor

    :param e: The EntityDescriptor element
    :param country_code: An ISO country code
    :raise: MetadataException unless e is an EntityDescriptor element
    """
    if e.tag != "{%s}EntityDescriptor" % NS['md']:
        raise MetadataException("I can only add NodeCountry to EntityDescriptor elements")

    def _set_nodecountry_in_ext(ext_elt, iso_cc):
        nc_elt = ext_elt.find("./{%s}NodeCountry" % NS['eidas'])
        if ext_elt is not None and nc_elt is None:
            velt = etree.Element("{%s}NodeCountry" % NS['eidas'])
            velt.text = iso_cc
            ext_elt.append(velt)

    ext = None
    idp = e.find("./{%s}IDPSSODescriptor" % NS['md'])
    if idp is not None and len(idp) > 0:
        ext = entity_extensions(idp)
        _set_nodecountry_in_ext(ext, country_code)

    sp = e.find("./{%s}SPSSODescriptor" % NS['md'])
    if sp is not None and len(sp) > 0:
        ext = entity_extensions(sp)
        _set_nodecountry_in_ext(ext, country_code)


def diff(t1, t2):
    s1 = set([e.get('entityID') for e in iter_entities(root(t1))])
    s2 = set([e.get('entityID') for e in iter_entities(root(t2))])
    return s1.difference(s2)
