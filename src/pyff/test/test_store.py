from unittest import TestCase

import mockredis
import os

from pyff.constants import ATTRS
from pyff.store import MemoryStore, SAMLStoreBase, entity_attribute_dict, RedisStore, WhooshStore
from pyff.utils import resource_filename, parse_xml, root


class TestRedisStore(TestCase):
    def setUp(self):
        self.datadir = resource_filename('metadata', 'test/data')
        self.test01_source = os.path.join(self.datadir, 'test01.xml')
        self.test01 = parse_xml(self.test01_source)
        self.swamid_source = os.path.join(self.datadir, 'swamid-2.0-test.xml')
        self.swamid = parse_xml(self.swamid_source)

    def _redis_store(self):
        store = RedisStore()
        store.rc = mockredis.mock_redis_client()
        return store

    def test_create_store(self):
        store = self._redis_store()
        assert (store is not None)
        assert (store.size() == 0)
        print(store.collections())
        assert (len(store.collections()) == 0)
        assert (str(store))
        assert (not store.attributes())

    def test_parse_test01(self):
        assert (self.test01_source is not None)
        assert (os.path.exists(self.test01_source))
        assert (self.test01 is not None)

    def test_import_reset_test01(self):
        store = self._redis_store()
        store.update(self.test01)
        assert (store.size() > 0)
        store.reset()
        assert (store.size() == 0)

    def test_store_attributes_test01(self):
        store = self._redis_store()
        store.update(self.test01)
        assert (ATTRS['domain'] in store.attributes())
        assert (ATTRS['role'] in store.attributes())
        assert (ATTRS['collection'] not in store.attributes())
        assert ('example.com' in store.attribute(ATTRS['domain']))
        assert ('example.net' in store.attribute(ATTRS['domain']))
        assert ('foo.com' not in store.attribute(ATTRS['domain']))

    def test_lookup_test01(self):
        store = self._redis_store()
        store.update(self.test01)
        entity_id = root(self.test01).get('entityID')
        assert (entity_id is not None)
        e = store.lookup(entity_id)
        print("%s: %s" % (entity_id, e))
        assert (len(e) == 1)
        assert (e[0] is not None)
        assert (e[0].get('entityID') is not None)
        assert (e[0].get('entityID') == entity_id)

    def test_lookup_intersect_test01(self):
        store = self._redis_store()
        store.update(self.test01)
        entity_id = root(self.test01).get('entityID')
        assert (entity_id is not None)
        e = store.lookup("{%s}%s+{%s}%s" % (ATTRS['domain'], 'example.com', ATTRS['role'], 'idp'))
        assert (len(e) == 1)
        assert (e[0] is not None)
        assert (e[0].get('entityID') is not None)
        assert (e[0].get('entityID') == entity_id)

    def test_lookup_intersect_empty_test01(self):
        store = self._redis_store()
        store.update(self.test01)
        entity_id = root(self.test01).get('entityID')
        assert (entity_id is not None)
        e = store.lookup("{%s}%s+{%s}%s" % (ATTRS['domain'], 'example.com', ATTRS['role'], 'sp'))
        assert (len(e) == 0)

    def test_maintain_test01(self):
        store = self._redis_store()
        store.update(self.test01)
        entity_id = root(self.test01).get('entityID')
        assert (entity_id is not None)
        d = dict()
        store.periodic(d)
        assert('Last Periodic Maintenance' in d)

    def test_load_swamid(self):
        store = self._redis_store()
        store.update(self.swamid)
        assert (store.size() == 990)
        assert (len(store.lookup("{%s}idp" % ATTRS['role'])) == 534)

class TestWhooshStore(TestCase):
    def setUp(self):
        self.datadir = resource_filename('metadata', 'test/data')
        self.test01_source = os.path.join(self.datadir, 'test01.xml')
        self.test01 = parse_xml(self.test01_source)
        self.swamid_source = os.path.join(self.datadir, 'swamid-2.0-test.xml')
        self.swamid = parse_xml(self.swamid_source)

    def test_create_store(self):
        store = WhooshStore()
        assert (store is not None)
        assert (store.size() == 0)
        assert (len(store.collections()) == 0)
        assert (str(store))
        assert (not store.attributes())

    def test_parse_test01(self):
        assert (self.test01_source is not None)
        assert (os.path.exists(self.test01_source))
        assert (self.test01 is not None)

    def test_import_reset_test01(self):
        store = WhooshStore()
        store.update(self.test01)
        assert (store.size() > 0)
        store.reset()
        assert (store.size() == 0)

    def test_store_attributes_test01(self):
        store = WhooshStore()
        store.update(self.test01)
        assert (ATTRS['domain'] in store.attributes())
        assert (ATTRS['role'] in store.attributes())
        assert (ATTRS['collection'] not in store.attributes())
        assert ('example.com' in store.attribute(ATTRS['domain']))
        assert ('example.net' in store.attribute(ATTRS['domain']))
        assert ('foo.com' not in store.attribute(ATTRS['domain']))

    def test_entity_dict_test01(self):
        d = entity_attribute_dict(root(self.test01))
        assert ('example.com' in d[ATTRS['domain']])
        assert ('example.net' in d[ATTRS['domain']])
        assert ('foo.com' not in d[ATTRS['domain']])

    def test_lookup_test01(self):
        store = WhooshStore()
        store.update(self.test01)
        entity_id = root(self.test01).get('entityID')
        e = store.lookup(entity_id)
        assert (len(e) == 1)
        assert (e[0] is not None)
        assert (e[0].get('entityID') is not None)
        assert (e[0].get('entityID') == entity_id)

    def test_lookup_intersect_test01(self):
        store = WhooshStore()
        store.update(self.test01)
        entity_id = root(self.test01).get('entityID')
        e = store.lookup("%s=%s+%s=%s" % (ATTRS['domain'], u'example.com', ATTRS['role'], u'idp'))
        assert (len(e) == 1)
        assert (e[0] is not None)
        assert (e[0].get('entityID') is not None)
        assert (e[0].get('entityID') == entity_id)

    def test_lookup_intersect_empty_test01(self):
        store = WhooshStore()
        store.update(self.test01)
        entity_id = root(self.test01).get('entityID')
        e = store.lookup("%s=%s+%s=%s" % (ATTRS['domain'], 'example.com', ATTRS['role'], 'sp'))
        assert (len(e) == 0)

class TestMemoryStore(TestCase):
    def setUp(self):
        self.datadir = resource_filename('metadata', 'test/data')
        self.test01_source = os.path.join(self.datadir, 'test01.xml')
        self.test01 = parse_xml(self.test01_source)
        self.swamid_source = os.path.join(self.datadir, 'swamid-2.0-test.xml')
        self.swamid = parse_xml(self.swamid_source)

    def test_create_store(self):
        store = MemoryStore()
        assert (store is not None)
        assert (store.size() == 0)
        assert (len(store.collections()) == 0)
        assert (str(store))
        assert (not store.attributes())

    def test_parse_test01(self):
        assert (self.test01_source is not None)
        assert (os.path.exists(self.test01_source))
        assert (self.test01 is not None)

    def test_import_reset_test01(self):
        store = MemoryStore()
        store.update(self.test01)
        assert (store.size() > 0)
        store.reset()
        assert (store.size() == 0)

    def test_store_attributes_test01(self):
        store = MemoryStore()
        store.update(self.test01)
        assert (ATTRS['domain'] in store.attributes())
        assert (ATTRS['role'] in store.attributes())
        assert (ATTRS['collection'] not in store.attributes())
        assert ('example.com' in store.attribute(ATTRS['domain']))
        assert ('example.net' in store.attribute(ATTRS['domain']))
        assert ('foo.com' not in store.attribute(ATTRS['domain']))

    def test_entity_dict_test01(self):
        d = entity_attribute_dict(root(self.test01))
        assert ('example.com' in d[ATTRS['domain']])
        assert ('example.net' in d[ATTRS['domain']])
        assert ('foo.com' not in d[ATTRS['domain']])

    def test_lookup_test01(self):
        store = MemoryStore()
        store.update(self.test01)
        entity_id = root(self.test01).get('entityID')
        e = store.lookup(entity_id)
        assert (len(e) == 1)
        assert (e[0] is not None)
        assert (e[0].get('entityID') is not None)
        assert (e[0].get('entityID') == entity_id)

    def test_lookup_intersect_test01(self):
        store = MemoryStore()
        store.update(self.test01)
        entity_id = root(self.test01).get('entityID')
        e = store.lookup("%s=%s+%s=%s" % (ATTRS['domain'], 'example.com', ATTRS['role'], 'idp'))
        assert (len(e) == 1)
        assert (e[0] is not None)
        assert (e[0].get('entityID') is not None)
        assert (e[0].get('entityID') == entity_id)

    def test_lookup_intersect_empty_test01(self):
        store = MemoryStore()
        store.update(self.test01)
        entity_id = root(self.test01).get('entityID')
        e = store.lookup("%s=%s+%s=%s" % (ATTRS['domain'], 'example.com', ATTRS['role'], 'sp'))
        assert (len(e) == 0)


class TestStoreBase(TestCase):
    def test_store_base(self):
        base = SAMLStoreBase()
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

        assert (base.clone() == base)