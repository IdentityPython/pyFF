from unittest import TestCase
from pyff.constants import ATTRS
from pyff.store import MemoryStore, StoreBase, entity_attribute_dict
from pyff.utils import resource_string, resource_filename, parse_xml, root
import os


class TestMemoryStore(TestCase):

    def setUp(self):
        self.datadir = resource_filename('metadata', 'test/data')
        print self.datadir

    def test_create_store(self):
        store = MemoryStore()
        assert(store is not None)
        assert(store.size() == 0)
        assert(len(store.collections()) == 0)

    def test_memory_import_reset(self):
        xml_source = os.path.join(self.datadir, 'test01.xml')
        assert(xml_source is not None)
        assert(os.path.exists(xml_source))
        t = parse_xml(xml_source)
        assert(t is not None)

        store = MemoryStore()
        store.update(t)
        assert(store.size() > 0)
        store.reset()
        assert(store.size() == 0)

    def test_entity_dict(self):
        xml_source = os.path.join(self.datadir, 'test01.xml')
        assert(xml_source is not None)
        assert(os.path.exists(xml_source))
        t = parse_xml(xml_source)
        assert(t is not None)

        d = entity_attribute_dict(root(t))
        assert('example.com' in d[ATTRS['domain']])
        assert('example.net' in d[ATTRS['domain']])
        assert('foo.com' not in d[ATTRS['domain']])

    def test_store_base(self):
        base = StoreBase()
        try:
            base.lookup("x")
            assert False
        except NotImplementedError:
            pass

        try:
            base.size()
            assert False
        except NotImplementedError:
            pass

        try:
            base.collections()
            assert False
        except NotImplementedError:
            pass

        try:
            base.update(None)
            assert False
        except NotImplementedError:
            pass

        try:
            base.reset()
            assert False
        except NotImplementedError:
            pass

        try:
            base.set('x','y')
            assert False
        except NotImplementedError:
            pass

        try:
            base.get('x')
            assert False
        except NotImplementedError:
            pass

        assert(base.clone() == base)