import json
from base64 import b64encode
from unittest import TestCase

from pyuppsala import etree

from pyff.constants import NS
from pyff.samlmd import discojson_sp_attr

ENTITY_ID = 'https://sp.example.com/shibboleth'


def _sp(*values):
    """Build an EntityDescriptor with one entity-selection-profile value per argument."""
    e = etree.Element("{{{}}}EntityDescriptor".format(NS['md']), nsmap=NS)
    e.set('entityID', ENTITY_ID)
    ext = etree.SubElement(e, "{{{}}}Extensions".format(NS['md']))
    eas = etree.SubElement(ext, "{{{}}}EntityAttributes".format(NS['mdattr']))
    attr = etree.SubElement(eas, "{{{}}}Attribute".format(NS['saml']))
    attr.set('Name', 'https://refeds.org/entity-selection-profile')
    for value in values:
        etree.SubElement(attr, "{{{}}}AttributeValue".format(NS['saml'])).text = value
    return e


def _b64(trustinfo):
    return b64encode(json.dumps(trustinfo).encode('utf8')).decode('ascii')


class TestDiscojsonSpAttr(TestCase):
    def test_no_valid_profile_gives_none(self):
        assert discojson_sp_attr(_sp('invalidValueForAttribute')) is None
        assert discojson_sp_attr(_sp(_b64({'no-profiles': {}}))) is None

    def test_invalid_value_does_not_hide_valid_one(self):
        sp = discojson_sp_attr(_sp('invalidValueForAttribute', _b64({'profiles': {'p1': {'strict': True}}})))
        assert sp == {'entityID': ENTITY_ID, 'profiles': {'p1': {'strict': True}}, 'extra_md': {}}

    def test_duplicates_keep_first_and_warn(self):
        first = {'profiles': {'p1': {'strict': True}}, 'extra_md': {'https://idp.example.com': {'title': 'first'}}}
        second = {'profiles': {'p1': {'strict': False}}, 'extra_md': {'https://idp.example.com': {'title': 'second'}}}
        with self.assertLogs(level='WARNING') as logs:
            sp = discojson_sp_attr(_sp(_b64(first), _b64(second)))
        assert sp['profiles'] == first['profiles']
        assert sp['extra_md'] == first['extra_md']
        assert any('duplicate trust profile p1' in line for line in logs.output)
        assert any('duplicate extra IdP metadata https://idp.example.com' in line for line in logs.output)
