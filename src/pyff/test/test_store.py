from unittest import TestCase
from pyff.constants import ATTRS
from pyff.store import MemoryStore, StoreBase, entity_attribute_dict
from pyff.utils import resource_string, resource_filename, parse_xml, root
import os


class TestMemoryStore(TestCase):

    def setUp(self):
        self.datadir = resource_filename('metadata', 'test/data')
        self.xml_source = os.path.join(self.datadir, 'test01.xml')
        self.t = parse_xml(self.xml_source)

    def test_create_store(self):
        store = MemoryStore()
        assert(store is not None)
        assert(store.size() == 0)
        assert(len(store.collections()) == 0)
        assert(str(store))
        assert(not store.attributes())

    def test_parse(self):
        assert(self.xml_source is not None)
        assert(os.path.exists(self.xml_source))
        assert(self.t is not None)

    def test_import_reset(self):
        store = MemoryStore()
        store.update(self.t)
        assert(store.size() > 0)
        store.reset()
        assert(store.size() == 0)

    def test_store_attributes(self):
        store = MemoryStore()
        store.update(self.t)
        assert(ATTRS['domain'] in store.attributes())
        assert(ATTRS['role'] in store.attributes())
        assert(ATTRS['collection'] not in store.attributes())
        assert('example.com' in store.attribute(ATTRS['domain']))
        assert('example.net' in store.attribute(ATTRS['domain']))
        assert('foo.com' not in store.attribute(ATTRS['domain']))

    def test_entity_dict(self):
        d = entity_attribute_dict(root(self.t))
        assert('example.com' in d[ATTRS['domain']])
        assert('example.net' in d[ATTRS['domain']])
        assert('foo.com' not in d[ATTRS['domain']])

    def test_lookup(self):
        store = MemoryStore()
        store.update(self.t)
        entity_id = root(self.t).get('entityID')
        e = store.lookup(entity_id)
        assert(len(e) == 1)
        assert(e[0] is not None)
        assert(e[0].get('entityID') is not None)
        assert(e[0].get('entityID') == entity_id)

    def test_lookup_intersect(self):
        store = MemoryStore()
        store.update(self.t)
        entity_id = root(self.t).get('entityID')
        e = store.lookup("%s=%s+%s=%s" % (ATTRS['domain'],'example.com',ATTRS['role'],'idp'))
        print e
        assert(len(e) == 1)
        assert(e[0] is not None)
        assert(e[0].get('entityID') is not None)
        assert(e[0].get('entityID') == entity_id)

    def test_lookup_intersect_empty(self):
        store = MemoryStore()
        store.update(self.t)
        entity_id = root(self.t).get('entityID')
        e = store.lookup("%s=%s+%s=%s" % (ATTRS['domain'],'example.com',ATTRS['role'],'sp'))
        print e
        assert(len(e) == 0)


class TestStoreBase(TestCase):

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