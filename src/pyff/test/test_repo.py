from copy import deepcopy
from unittest import TestCase

import os

from pyff.constants import NS
from pyff.mdrepo import MDRepository
from pyff.store import MemoryStore
from pyff.utils import resource_filename, parse_xml, root, hash_id, MetadataException


class TestRepo(TestCase):
    def setUp(self):
        self.md = MDRepository(store=MemoryStore)
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
        nmd = self.md.clone()
        assert (nmd.store.size() == self.md.store.size())
        assert (nmd.lookup(entity_id) is not None)

    def test_sha1_hash(self):
        entity_id = root(self.t).get('entityID')
        self.md.store.update(root(self.t), entity_id)
        e = self.md.lookup(entity_id)
        assert (self.md.sha1_id(e[0]) == "{sha1}568515f6fae8c8b4d42d543853c96d08f051ef13")
        assert (hash_id(e[0], 'sha1', prefix=False) == "568515f6fae8c8b4d42d543853c96d08f051ef13")

    def test_entity_attribute(self):
        entity_id = root(self.t).get('entityID')
        self.md.set_entity_attributes(root(self.t), {"http://ns.example.org": "foo"})
        self.md.store.update(root(self.t), entity_id)
        e = self.md.lookup("{%s}%s" % ("http://ns.example.org", 'foo'))[0]
        assert (e is not None)
        assert (e.get('entityID') == entity_id)

    def test_utils(self):
        entity_id = root(self.t).get('entityID')
        self.md.store.update(root(self.t), entity_id)
        e = self.md.lookup(entity_id)[0]
        assert (self.md.is_idp(e))
        assert (not self.md.is_sp(e))
        icon = self.md.icon(e)
        assert ('url' in icon)
        assert ('https://www.example.com/static/images/umu_logo.jpg' in icon['url'])
        assert ('width' in icon)
        assert ('358' == icon['width'])
        assert ('height' in icon)
        assert ('63' == icon['height'])
        assert ('62' != icon['height'])

        domains = self.md.domains(e)
        assert ('example.com' in domains)
        assert ('example.net' in domains)
        assert ('idp.example.com' not in domains)
        assert ('foo.com' not in domains)

        edup = deepcopy(e)
        name, desc = self.md.ext_display(e)
        assert(name == 'Example University')
        assert(desc == 'Identity Provider for Example University')

        disp = self.md.display(e)
        assert (disp == 'Example University')
        for elt in e.findall(".//{%s}DisplayName" % NS['mdui']):
            elt.getparent().remove(elt)

        disp = self.md.display(e)
        assert (disp == 'The Example University')
        for elt in e.findall(".//{%s}OrganizationDisplayName" % NS['md']):
            elt.getparent().remove(elt)

        disp = self.md.display(e)
        assert (disp == 'ExampleU')
        for elt in e.findall(".//{%s}OrganizationName" % NS['md']):
            elt.getparent().remove(elt)

        disp = self.md.display(e)
        assert (disp == entity_id)

        e = edup

        subs = self.md.sub_domains(e)
        assert ('example.com' in subs)
        assert ('example.net' in subs)
        assert ('idp.example.com' not in subs)

        summary = self.md.simple_summary(e)
        assert (summary['title'] == 'Example University')
        assert (summary['descr'] == 'Identity Provider for Example University')
        assert (summary['entityID'] == entity_id)
        assert ('icon' in summary)
        assert ('icon_url' in summary and summary['icon'] == summary['icon_url'])
        assert ('domains' in summary)
        assert ('id' in summary)

        empty = self.md.simple_summary(None)
        assert (not empty)

    def test_display(self):
        swamid = root(self.swamid)
        self.md.store.update(swamid, swamid.get('Name'))
        funet_connect = self.md.lookup('https://connect.funet.fi/shibboleth')[0]
        name, desc = self.md.ext_display(funet_connect)
        assert(name == 'FUNET E-Meeting Service')
        dn = self.md.display(funet_connect)


    def test_missing(self):
        swamid = root(self.swamid)
        self.md.store.update(swamid, swamid.get('Name'))
        missing = self.md.lookup('https://connect.funet.fi/shibboleth+missing')
        assert (len(missing) == 0)

    def test_non_metadata(self):
        e = root(self.non_metadata)
        assert self.md.expiration(e) is None
        try:
            self.md.annotate(e,"kaka","x","y")
            self.md.set_entity_attributes(e, dict(a=1))
            assert False
        except MetadataException:
            pass
