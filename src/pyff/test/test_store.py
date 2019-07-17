from unittest import TestCase
import os
import fakeredis
from pyff.constants import ATTRS
from pyff.samlmd import iter_entities
from pyff.store import MemoryStore, SAMLStoreBase, entity_attribute_dict, RedisWhooshStore
from pyff.utils import resource_filename, parse_xml, root
import tempfile
import shutil


class TestRedisWhooshStore(TestCase):

    def setUp(self):
        self.datadir = resource_filename('metadata', 'test/data')
        self.test01_source = os.path.join(self.datadir, 'test01.xml')
        self.test01 = parse_xml(self.test01_source)
        self.swamid_source = os.path.join(self.datadir, 'swamid-2.0-test.xml')
        self.swamid = parse_xml(self.swamid_source)
        self.wayf_source = os.path.join(self.datadir, 'wayf-edugain-metadata.xml')
        self.wayf = parse_xml(self.wayf_source)
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.dir)

    def test_create_store(self):
        store = RedisWhooshStore(directory=self.dir, clear=True, name="test", redis=fakeredis.FakeStrictRedis())
        assert (store is not None)
        assert (store.size() == 0)
        assert (len(store.collections()) == 0)
        assert (str(store))
        assert (not store.attributes())

    def test_parse_test01(self):
        assert (self.test01_source is not None)
        assert (os.path.exists(self.test01_source))
        assert (self.test01 is not None)

    def test_parse_wayf(self):
        assert (self.wayf_source is not None)
        assert (os.path.exists(self.wayf_source))
        assert (self.wayf is not None)

    def test_import_reset_test01(self):
        store = RedisWhooshStore(directory=self.dir, clear=True, name="test", redis=fakeredis.FakeStrictRedis())
        store.update(self.test01, etag="test01")
        assert (store.size() > 0)
        store.reset()
        print(store.size())
        assert (store.size() == 0)

    def test_import_reset_wayf(self):
        store = RedisWhooshStore(directory=self.dir, clear=True, name="test", redis=fakeredis.FakeStrictRedis())
        store.update(self.wayf, tid='https://metadata.wayf.dk/wayf-edugain-metadata.xml')
        assert (store.size() == 77)
        store.reset()
        assert (store.size() == 0)

    def test_store_attributes_test01(self):
        store = RedisWhooshStore(directory=self.dir, clear=True, name="test", redis=fakeredis.FakeStrictRedis())
        store.update(self.test01, etag='test01', lazy=False)
        print(store.attributes())
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
        store = RedisWhooshStore(directory=self.dir, clear=True, name="test", redis=fakeredis.FakeStrictRedis())
        store.update(self.test01, etag='test01', lazy=False)
        entity_id = root(self.test01).get('entityID')
        e = store.lookup(entity_id)
        assert (len(e) == 1)
        assert (e[0] is not None)
        assert (e[0].get('entityID') is not None)
        assert (e[0].get('entityID') == entity_id)

    def test_lookup_intersect_test01(self):
        store = RedisWhooshStore(directory=self.dir, clear=True, name="test", redis=fakeredis.FakeStrictRedis())
        store.update(self.test01, etag='test01', lazy=False)
        entity_id = root(self.test01).get('entityID')
        e = store.lookup("%s=%s+%s=%s" % (ATTRS['domain'], 'example.com', ATTRS['role'], 'idp'))
        assert (len(e) == 1)
        assert (e[0] is not None)
        assert (e[0].get('entityID') is not None)
        assert (e[0].get('entityID') == entity_id)

    def test_lookup_wayf(self):
        store = RedisWhooshStore(directory=self.dir, clear=True, name="test", redis=fakeredis.FakeStrictRedis())
        store.update(self.wayf, tid='https://metadata.wayf.dk/wayf-edugain-metadata.xml')
        assert(store.size() == 77)
        res = store.lookup("entities")
        lst = [e.get('entityID') for e in res]
        assert (len(lst) == 77)
        assert ('https://birk.wayf.dk/birk.php/wayf.supportcenter.dk/its/saml2/idp/metadata.php?unit=its' in lst)

    def test_select_wayf(self):
        store = RedisWhooshStore(directory=self.dir, clear=True, name="test", redis=fakeredis.FakeStrictRedis())
        store.update(self.wayf, tid='https://metadata.wayf.dk/wayf-edugain-metadata.xml')
        assert(store.size() == 77)
        res = store.select('https://metadata.wayf.dk/wayf-edugain-metadata.xml')
        assert(len(res) == 77)
        lst = [e.get('entityID') for e in res]
        assert (len(lst) == 77)
        assert ('https://birk.wayf.dk/birk.php/wayf.supportcenter.dk/its/saml2/idp/metadata.php?unit=its' in lst)

    def test_lookup_intersect_empty_test01(self):
        store = RedisWhooshStore(directory=self.dir, clear=True, name="test", redis=fakeredis.FakeStrictRedis())
        store.update(self.test01, etag='test01', lazy=False)
        entity_id = root(self.test01).get('entityID')
        e = store.lookup("%s=%s+%s=%s" % (ATTRS['domain'], 'example.com', ATTRS['role'], 'sp'))
        assert (len(e) == 0)

    def test_search_test01(self):
        store = RedisWhooshStore(directory=self.dir, clear=True, name="test", redis=fakeredis.FakeStrictRedis())
        store.update(self.test01, etag='test01', lazy=False)
        entity_id = root(self.test01).get('entityID')
        for q in ('example', 'Example', 'university'):
            e = list(store.search(q))
            assert(len(e) == 1)
            assert (e[0] is not None)
            assert (e[0].get('entityID') is not None)
            assert (e[0].get('entityID') == entity_id)

    def test_search_swamid(self):
        store = RedisWhooshStore(directory=self.dir, clear=True, name="test", redis=fakeredis.FakeStrictRedis())
        store.update(self.swamid, etag='test01', lazy=False)
        for q in ('sunet', 'sunet.se', 'nordunet', 'miun'):
            e = list(store.search(q))
            assert (len(e) != 0)
            assert (e[0] is not None)
            assert (e[0].get('entityID') is not None)


class TestMemoryStore(TestCase):
    def setUp(self):
        self.datadir = resource_filename('metadata', 'test/data')
        self.test01_source = os.path.join(self.datadir, 'test01.xml')
        self.test01 = parse_xml(self.test01_source)
        self.swamid_source = os.path.join(self.datadir, 'swamid-2.0-test.xml')
        self.swamid = parse_xml(self.swamid_source)
        self.wayf_source = os.path.join(self.datadir, 'wayf-edugain-metadata.xml')
        self.wayf = parse_xml(self.wayf_source)

    def test_create_store(self):
        store = MemoryStore()
        assert (store is not None)
        assert (store.size() == 0)
        assert (len(store.collections()) == 0)
        assert (str(store))
        assert (not store.attributes())

    def test_parse_wayf(self):
        assert (self.wayf_source is not None)
        assert (os.path.exists(self.wayf_source))
        assert (self.wayf is not None)

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

    def test_import_reset_wayf(self):
        store = MemoryStore()
        store.update(self.wayf, tid='https://metadata.wayf.dk/wayf-edugain-metadata.xml')
        assert (store.size() == 77)
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

    def test_lookup_wayf(self):
        store = MemoryStore()
        store.update(self.wayf, tid='https://metadata.wayf.dk/wayf-edugain-metadata.xml')
        assert(store.size() == 77)
        res = store.lookup("entities")
        lst = [e.get('entityID') for e in res]
        assert (len(lst) == 77)
        assert ('https://birk.wayf.dk/birk.php/wayf.supportcenter.dk/its/saml2/idp/metadata.php?unit=its' in lst)

    def test_select_wayf(self):
        store = MemoryStore()
        store.update(self.wayf, tid='https://metadata.wayf.dk/wayf-edugain-metadata.xml')
        assert(store.size() == 77)
        res = store.select("https://metadata.wayf.dk/wayf-edugain-metadata.xml")
        lst = [e.get('entityID') for e in res]
        assert (len(lst) == 77)
        assert ('https://birk.wayf.dk/birk.php/wayf.supportcenter.dk/its/saml2/idp/metadata.php?unit=its' in lst)

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