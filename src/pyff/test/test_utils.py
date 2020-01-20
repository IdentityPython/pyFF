import copy
import tempfile
from unittest import TestCase

import os
import six
from pyff import utils
from pyff.constants import NS
from pyff.resource import Resource
from pyff.samlmd import find_entity, entities_list
from pyff.utils import resource_filename, parse_xml, root, resource_string, b2u, Lambda, schema, find_matching_files, \
    url_get, img_to_data, is_past_ttl
from ..merge_strategies import replace_existing, remove
from threading import Thread, current_thread


class TestMetadata(TestCase):

    def setUp(self):
        self.datadir = resource_filename('metadata', 'test/data')
        self.xml_source1 = os.path.join(self.datadir, 'test01.xml')
        self.xml_source2 = os.path.join(self.datadir, 'swamid-2.0-test.xml')
        self.t1 = parse_xml(self.xml_source1)
        self.t2 = parse_xml(self.xml_source2)

    def test_merge_replace_bad(self):
        try:
            replace_existing(self.t1, self.t1)
            assert False
        except AttributeError:
            pass

    def test_merge_remove_bad(self):
        try:
            remove(self.t1, self.t1)
            assert False
        except AttributeError:
            pass

    def test_replace_ndn(self):
        idp = find_entity(root(self.t2), 'https://idp.nordu.net/idp/shibboleth')
        assert (idp is not None)
        idp2 = copy.deepcopy(idp)
        assert idp2 is not None
        for o in idp2.findall(".//{%s}OrganizationName" % NS['md']):
            o.text = "FOO"
        idp2.set('ID', 'kaka4711')
        replace_existing(idp, idp2)
        idp3 = find_entity(root(self.t2), 'kaka4711', attr='ID')
        assert (idp3 is not None)
        for o in idp2.findall(".//{%s}OrganizationName" % NS['md']):
            assert (o.text == "FOO")
        remove(idp3, None)
        idp = find_entity(root(self.t2), 'kaka4711', attr='ID')
        assert (idp3 is not None)

    def test_entities_list(self):
        assert len(list(entities_list(root(self.t2)))) == 1032
        assert len(list(entities_list(None))) == 0


class TestResources(TestCase):

    def test_resource_filename(self):
        assert(resource_filename("missing") is None)
        assert(resource_filename("missing", "gone") is None)
        assert(os.path.isdir(resource_filename('test')))
        assert(os.path.isfile(resource_filename('test/data/empty.txt')))
        assert(os.path.isdir(resource_filename('metadata', 'test/data')))
        assert(os.path.isfile(resource_filename('empty.txt', 'test/data')))
        assert(resource_filename('empty.txt', 'test/data') == resource_filename('test/data/empty.txt'))
        tmp = tempfile.NamedTemporaryFile('w').name
        with open(tmp, "w") as fd:
            fd.write("test")

        try:
            assert(resource_filename(tmp) == tmp)
            (d, fn) = os.path.split(tmp)
            assert(resource_filename(fn, d) == tmp)
        except IOError as ex:
            raise ex
        finally:
            try:
                os.unlink(tmp)
            except Exception:
                pass

    def test_resource_string(self):
        assert(resource_string("missing") is None)
        assert(resource_string("missing", "gone") is None)
        assert(resource_string('test/data/empty.txt') == six.b('empty'))
        assert(resource_string('empty.txt', 'test/data') == six.b('empty'))
        tmp = tempfile.NamedTemporaryFile('w').name
        with open(tmp, "w") as fd:
            fd.write("test")

        try:
            print(resource_string(tmp))
            assert(resource_string(tmp) == 'test')
            (d, fn) = os.path.split(tmp)
            assert(resource_string(fn, d) == 'test')
        except IOError as ex:
            raise ex
        finally:
            try:
                os.unlink(tmp)
            except Exception:
                pass


class TestXMLErrors(TestCase):

    def test_strip_warnings(self):
        errors = [':WARNING:', 'other']
        assert(utils.xml_error(errors) == 'other')
        assert(utils.xml_error(errors, m='other') == 'other')
        assert(utils.xml_error(errors, m='kaka') == '')


class TestMisc(TestCase):

    def test_b2u(self):
        assert(int(b2u(b'1')) == 1)
        assert(b2u('kaka') == 'kaka')

    def test_cache_fuzz(self):
        from pyff.constants import config
        import time
        config.randomize_cache_ttl = False
        config.cache_ttl = 0
        now = int(time.time())
        assert(is_past_ttl(now - 1, ttl=config.cache_ttl))
        assert(not is_past_ttl(now, ttl=config.cache_ttl))
        config.cache_ttl = 3
        config.randomize_cache_ttl = True
        assert(is_past_ttl(now - 6, ttl=config.cache_ttl))
        assert(not is_past_ttl(now, ttl=config.cache_ttl))
        assert(is_past_ttl(now - 100, ttl=config.cache_ttl))

    def test_schema(self):
        assert(schema())

    def test_schema_100_times(self):
        for i in range(1, 100):
            assert(schema())

    def test_schema_threads(self):
        exceptions = dict()
        threads = list()

        def _s(e):
            try:
                schema()
            except BaseException as ex:
                e[current_thread()] = ex
        for i in range(1, 100):
            t = Thread(target=_s, args=[exceptions])
            threads.append(t)
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        for e in exceptions:
            print(e)
        assert(len(exceptions) == 0)


class TestLambda(TestCase):

    def test_lambda(self):

        def _cb(*args, **kwargs):
            assert (args[0] == args[1])

        f = Lambda(_cb, "kaka")
        f("kaka")
        try:
            f("foo")
            assert False
        except AssertionError as ex:
            pass


class TestImage(TestCase):

    ext_to_mime = dict(
        jpg='image/jpeg',
        gif='image/gif',
        ico='image/x-icon',
        png='image/png',
        svg='image/svg+xml')

    def setUp(self):
        self.imagedir = resource_filename('images', 'test/data')
        self.files = [fn for fn in find_matching_files(self.imagedir, ['png', 'gif', 'jpeg', 'jpg', 'ico', 'svg'])]

    def test_match(self):
        assert any('sunet256.png' in fn for fn in self.files)

    def test_convert(self):
        for fn in self.files:
            (basename, _, ext) = fn.rpartition('.')
            mime_type = TestImage.ext_to_mime.get(ext, None)
            assert (mime_type is not None)
            url = "file://{}".format(fn)
            assert url
            r = url_get(url)
            assert r
            assert r.content
            img = img_to_data(r.content, mime_type)
            assert img
            print (img)


class TestResource(TestCase):

    def test_cmp(self):
        r1 = Resource("https://mds.edugain.org", via=lambda x: x)
        r2 = Resource("https://mds.edugain.org")

        assert r1 == r2
