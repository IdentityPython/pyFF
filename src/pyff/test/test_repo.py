from copy import deepcopy
from unittest import TestCase

import os

from pyff.constants import NS
from pyff.store import make_store_instance
from pyff.utils import resource_filename, parse_xml, root, hash_id, MetadataException
from pyff.samlmd import set_entity_attributes, is_idp, is_sp, entity_icon_url, \
    entity_domains, entity_extended_display, entity_display_name, entity_simple_summary, \
    metadata_expiration, annotate_entity, sha1_id
from pyff.repo import MDRepository


class TestRepo(TestCase):
    def setUp(self):
        self.md = MDRepository()
        self.md.store = make_store_instance()
        self.datadir = resource_filename('metadata', 'test/data')
        self.xml_source = os.path.join(self.datadir, 'test01.xml')
        self.swamid_source = os.path.join(self.datadir, 'swamid-2.0-test.xml')
        self.swamid = root(parse_xml(self.swamid_source))
        self.t = parse_xml(self.xml_source)
        self.non_metadata = parse_xml(resource_filename("not-metadata.xml", self.datadir))

    def test_md_exists(self):
        assert (self.md is not None)

    def test_clone(self):
        entity_id = root(self.t).get('entityID')
        self.md.store.update(root(self.t), entity_id)
        nstore = deepcopy(self.md.store)
        assert (nstore.size() == self.md.store.size())
        assert (nstore.lookup(entity_id) is not None)

    def test_sha1_hash(self):
        entity_id = root(self.t).get('entityID')
        self.md.store.update(root(self.t), entity_id)
        e = self.md.lookup(entity_id)
        assert (sha1_id(e[0]) == "{sha1}568515f6fae8c8b4d42d543853c96d08f051ef13")
        assert (hash_id(e[0], 'sha1', prefix=False) == "568515f6fae8c8b4d42d543853c96d08f051ef13")

    def test_entity_attribute(self):
        entity_id = root(self.t).get('entityID')
        set_entity_attributes(root(self.t), {"http://ns.example.org": "foo"})
        self.md.store.update(root(self.t), entity_id)
        e = self.md.lookup("{%s}%s" % ("http://ns.example.org", 'foo'))[0]
        assert (e is not None)
        assert (e.get('entityID') == entity_id)

    def test_utils(self):
        entity_id = root(self.t).get('entityID')
        self.md.store.update(root(self.t), entity_id)
        e = self.md.lookup(entity_id)[0]
        assert (is_idp(e))
        assert (not is_sp(e))
        icon = entity_icon_url(e)
        assert ('url' in icon)
        assert ('https://www.example.com/static/images/umu_logo.jpg' in icon['url'])
        assert ('width' in icon)
        assert ('358' == icon['width'])
        assert ('height' in icon)
        assert ('63' == icon['height'])
        assert ('62' != icon['height'])

        domains = entity_domains(e)
        assert ('example.com' in domains)
        assert ('example.net' in domains)
        assert ('idp.example.com' not in domains)
        assert ('foo.com' not in domains)

        edup = deepcopy(e)
        name, desc = entity_extended_display(e)
        assert(name == 'Example University')
        assert(desc == 'Identity Provider for Example University')

        disp = entity_display_name(e)
        assert (disp == 'Example University')
        for elt in e.findall(".//{%s}DisplayName" % NS['mdui']):
            elt.getparent().remove(elt)

        disp = entity_display_name(e)
        assert (disp == 'The Example University')
        for elt in e.findall(".//{%s}OrganizationDisplayName" % NS['md']):
            elt.getparent().remove(elt)

        disp = entity_display_name(e)
        assert (disp == 'ExampleU')
        for elt in e.findall(".//{%s}OrganizationName" % NS['md']):
            elt.getparent().remove(elt)

        disp = entity_display_name(e)
        assert (disp == entity_id)

        e = edup

        subs = entity_domains(e)
        assert ('example.com' in subs)
        assert ('example.net' in subs)
        assert ('idp.example.com' not in subs)

        summary = entity_simple_summary(e)
        assert (summary['title'] == 'Example University')
        assert (summary['descr'] == 'Identity Provider for Example University')
        assert (summary['entityID'] == entity_id)
        assert ('domains' in summary)
        assert ('id' in summary)

        empty = entity_simple_summary(None)
        assert (not empty)

    def test_display(self):
        swamid = root(self.swamid)
        self.md.store.update(swamid, swamid.get('Name'))
        funet_connect = self.md.lookup('https://connect.funet.fi/shibboleth')[0]
        name, desc = entity_extended_display(funet_connect)
        assert(name == 'FUNET E-Meeting Service')
        dn = entity_extended_display(funet_connect)

    def test_missing(self):
        swamid = root(self.swamid)
        self.md.store.update(swamid, swamid.get('Name'))
        missing = self.md.lookup('https://connect.funet.fi/shibboleth+missing')
        assert (len(missing) == 0)

    def test_non_metadata(self):
        e = root(self.non_metadata)
        assert metadata_expiration(e) is None
        try:
            annotate_entity(e,"kaka","x","y")
            set_entity_attributes(e, dict(a=1))
            assert False
        except MetadataException:
            pass
