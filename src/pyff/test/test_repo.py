from unittest import TestCase
from pyff.mdrepo import MDRepository
from pyff.store import MemoryStore
from pyff.utils import resource_filename, parse_xml, root, hash_id
import os


class TestRepo(TestCase):
    def setUp(self):
        self.md = MDRepository(store=MemoryStore)
        self.datadir = resource_filename('metadata', 'test/data')
        self.xml_source = os.path.join(self.datadir, 'test01.xml')
        self.t = parse_xml(self.xml_source)

    def test_md_exists(self):
        assert (self.md is not None)

    def test_clone(self):
        entity_id = root(self.t).get('entityID')
        self.md.import_metadata(root(self.t), entity_id)
        nmd = self.md.clone()
        assert (nmd.store.size() == self.md.store.size())
        assert (nmd.lookup(entity_id) is not None)

    def test_sha1_hash(self):
        entity_id = root(self.t).get('entityID')
        self.md.import_metadata(root(self.t), entity_id)
        e = self.md.lookup(entity_id)
        assert (self.md.sha1_id(e[0]) == "{sha1}568515f6fae8c8b4d42d543853c96d08f051ef13")
        assert (hash_id(e[0], 'sha1', prefix=False) == "568515f6fae8c8b4d42d543853c96d08f051ef13")

    def test_entity_attribute(self):
        entity_id = root(self.t).get('entityID')
        self.md.set_entity_attributes(root(self.t), {"http://ns.example.org": "foo"})
        self.md.import_metadata(root(self.t), entity_id)
        e = self.md.lookup("{%s}%s" % ("http://ns.example.org", 'foo'))[0]
        assert (e is not None)
        assert (e.get('entityID') == entity_id)

    def test_utils(self):
        entity_id = root(self.t).get('entityID')
        self.md.import_metadata(root(self.t), entity_id)
        e = self.md.lookup(entity_id)[0]
        assert (self.md.is_idp(e))
        assert (not self.md.is_sp(e))
        assert (self.md.icon(e) in ['https://www.example.com/static/images/logo.jpg',
                                    'https://www.example.com/static/images/logo_eng.jpg'] )
        domains = self.md.domains(e)
        assert ('example.com' in domains)
        assert ('example.net' in domains)
        assert ('idp.example.com' in domains)
        assert ('foo.com' not in domains)

        name, desc = self.md.ext_display(e)
        assert(name == 'Example University')
        assert(desc == 'Identity Provider for Example University')

        disp = self.md.display(e)
        assert (disp == 'Example University')

        subs = self.md.sub_domains(e)
        assert ('example.com' in subs)
        assert ('example.net' in subs)
        assert ('idp.example.com' not in subs)

        summary = self.md.simple_summary(e)
        assert (summary['title'] == 'Example University')
        assert (summary['descr'] == 'Identity Provider for Example University')
        assert (summary['value'] == entity_id)
        assert ('icon' in summary)
        assert ('icon_url' in summary and summary['icon'] == summary['icon_url'])
        assert ('domains' in summary)
        assert ('id' in summary)

        empty = self.md.simple_summary(None)
        assert (not empty)