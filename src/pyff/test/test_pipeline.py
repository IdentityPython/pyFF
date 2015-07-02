import os
import shutil
import mock
import sys
import tempfile
from mako.lookup import TemplateLookup
from nose.plugins.skip import Skip
import yaml
from pyff.mdrepo import MDRepository
from pyff.pipes import plumbing, Plumbing, PipeException
from pyff.test import ExitException
from StringIO import StringIO
from pyff.utils import hash_id, parse_xml, resource_filename, root
from pyff.test import SignerTestCase
from mock import patch

__author__ = 'leifj'


class PipeLineTest(SignerTestCase):
    def run_pipeline(self, pl_name, ctx=None, md=MDRepository()):
        if ctx is None:
            ctx = dict()

        templates = TemplateLookup(directories=[os.path.join(self.datadir, 'simple-pipeline')])
        pipeline = tempfile.NamedTemporaryFile('w').name
        template = templates.get_template(pl_name)
        with open(pipeline, "w") as fd:
            fd.write(template.render(ctx=ctx))
        res = plumbing(pipeline).process(md, state={'batch': True, 'stats': {}})
        os.unlink(pipeline)
        return res, md, ctx

    def exec_pipeline(self, pstr):
        md = MDRepository()
        p = yaml.load(StringIO(pstr))
        #print p
        res = Plumbing(p, pid="test").process(md, state={'batch': True, 'stats': {}})
        return res, md

    @classmethod
    def setUpClass(cls):
        SignerTestCase.setUpClass()

    def setUp(self):
        SignerTestCase.setUpClass()
        print "setup called for PipeLineTest"
        self.templates = TemplateLookup(directories=[os.path.join(self.datadir, 'simple-pipeline')])


class StreamCapturing(object):
    def __init__(self, stream):
        self.captured = []
        self.stream = stream

    def __getattr__(self, attr):
        return getattr(self.stream, attr)

    def write(self, data):
        self.captured.append(data)
        self.stream.write(data)

class ParseTest(PipeLineTest):
    def parse_test(self):
        self.output = tempfile.NamedTemporaryFile('w').name
        with patch.multiple("sys", exit=self.sys_exit, stdout=StreamCapturing(sys.stdout), stderr=StreamCapturing(sys.stderr)):
            from testfixtures import LogCapture
            with LogCapture() as l:
                res, md = self.exec_pipeline("""
- load:
    - %s/metadata
- select
- stats
""" % self.datadir)
                print sys.stdout.captured
                print sys.stderr.captured
                eIDs = [e.get('entityID') for e in md.store]
                assert('https://idp.example.com/saml2/idp/metadata.php1' not in eIDs)
                assert('https://idp.example.com/saml2/idp/metadata.php' in eIDs)
                assert("removing 'https://idp.example.com/saml2/idp/metadata.php1': schema validation failed" in str(l))


# noinspection PyUnresolvedReferences
class SigningTest(PipeLineTest):
    def test_signing(self):
        self.output = tempfile.NamedTemporaryFile('w').name
        res, md, ctx = self.run_pipeline("signer.fd", self)
        eIDs = [e.get('entityID') for e in md.store]
        assert ('https://idp.aco.net/idp/shibboleth' in eIDs)
        assert ('https://skriptenforum.net/shibboleth' in eIDs)
        os.unlink(self.output)

    def test_signing_and_validation(self):
        self.output = tempfile.NamedTemporaryFile('w').name
        res_s, md_s, ctx_s = self.run_pipeline("signer.fd", self)
        res_v, md_v, ctx_v = self.run_pipeline("validator.fd", self)

        eIDs = [e.get('entityID') for e in md_v.store]
        assert ('https://idp.aco.net/idp/shibboleth' in eIDs)
        assert ('https://skriptenforum.net/shibboleth' in eIDs)
        os.unlink(self.output)

    def test_cert_report(self):
        self.output = tempfile.NamedTemporaryFile('w').name
        res, md, ctx = self.run_pipeline("certreport.fd", self)
        eIDs = [e.get('entityID') for e in md.store]
        assert ('https://idp.aco.net/idp/shibboleth' in eIDs)
        assert ('https://skriptenforum.net/shibboleth' in eIDs)
        with open(self.output, 'r') as fd:
            lines = fd.readline()
            assert (len(lines) > 0)

    def test_cert_report_swamid(self):
        self.output = tempfile.NamedTemporaryFile('w').name
        res, md, ctx = self.run_pipeline("certreport-swamid.fd", self)
        with open(self.output, 'r') as fd:
            print fd.read()

    def test_info_and_dump(self):
        with patch("sys.stdout", StreamCapturing(sys.stdout)) as ctx:
            try:
                self.exec_pipeline("""
- load:
  - http://md.swamid.se/md/swamid-2.0.xml
- select
- dump
- info
""")
                assert ('https://idp.nordu.net/idp/shibboleth' in sys.stdout.captured)
            except IOError:
                raise Skip

    def test_end_exit(self):
        with patch.multiple("sys", exit=self.sys_exit, stdout=StreamCapturing(sys.stdout)):
            try:
                self.exec_pipeline("""
- end:
    code: 22
    message: "slartibartifast"
""")
                assert False
            except IOError:
                raise Skip
            except ExitException, ex:
                assert ex.code == 22
                assert "slartibartifast" in "".join(sys.stdout.captured)

    def test_single_dump(self):
        with patch.multiple("sys", exit=self.sys_exit, stdout=StreamCapturing(sys.stdout)):
            try:
                self.exec_pipeline("""
- dump
""")
                assert '<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"/>' \
                       in "".join(sys.stdout.captured)
            except IOError:
                raise Skip

    def test_missing_select(self):
        for stmt in ('publish', 'signcerts', 'info', 'sign', 'store', 'finalize',
                     'xslt', 'certreport', 'emit', 'finalize', 'first', 'setattr', 'stats'):
            with patch.multiple("sys", exit=self.sys_exit, stdout=StreamCapturing(sys.stdout)):
                try:
                    self.exec_pipeline("""
- %s
""" % stmt)
                    assert False
                except PipeException:
                    pass
                except IOError:
                    raise Skip

    def test_first_select_as(self):
        with patch.multiple("sys", exit=self.sys_exit, stdout=StreamCapturing(sys.stdout)):
            tmpfile = tempfile.NamedTemporaryFile('w').name
            try:
                self.exec_pipeline("""
- load:
   - file://%s/metadata/test01.xml
- select as FOO
- first
- publish: %s
""" % (self.datadir, tmpfile))
                t1 = parse_xml(resource_filename("metadata/test01.xml", self.datadir))
                assert t1 is not None
                entity_id = 'https://idp.example.com/saml2/idp/metadata.php'
                t2 = parse_xml(tmpfile)
                assert t2 is not None
                assert root(t1).get('entityID') == root(t2).get('entityID')
                assert root(t2).get('entityID') == entity_id
            except PipeException:
                pass
            except IOError:
                raise Skip
            finally:
                try:
                    os.unlink(tmpfile)
                except:
                    pass

    def test_empty_store(self):
        with patch.multiple("sys", exit=self.sys_exit, stdout=StreamCapturing(sys.stdout)):
            try:
                self.exec_pipeline("""
- store
""")
                assert False
            except PipeException:
                pass
            except IOError:
                raise Skip

    def test_empty_store(self):
        with patch.multiple("sys", exit=self.sys_exit, stdout=StreamCapturing(sys.stdout)):
            try:
                self.exec_pipeline("""
- store:
   directory: /tmp
""")
                assert False
            except PipeException:
                pass
            except IOError:
                raise Skip

    def test_empty_dir_error(self):
        with patch.multiple("sys", exit=self.sys_exit, stdout=StreamCapturing(sys.stdout)):
            from testfixtures import LogCapture
            with LogCapture() as l:
                try:
                    self.exec_pipeline("""
- load:
   - %s/empty
""" % self.datadir)
                except IOError:
                    raise Skip
                assert "no entities found in" in str(l)

    def test_store_and_retrieve(self):
        with patch.multiple("sys", exit=self.sys_exit, stdout=StreamCapturing(sys.stdout)):
            tmpdir = tempfile.mkdtemp()
            os.rmdir(tmpdir)  # lets make sure 'store' can recreate it
            try:
                self.exec_pipeline("""
- load:
   - file://%s/metadata/test01.xml
- select
- store:
   directory: %s
""" % (self.datadir, tmpdir))
                t1 = parse_xml(resource_filename("metadata/test01.xml", self.datadir))
                assert t1 is not None
                entity_id = 'https://idp.example.com/saml2/idp/metadata.php'
                sha1id = hash_id(entity_id, prefix=False)
                fn = "%s/%s.xml" % (tmpdir, sha1id)
                assert os.path.exists(fn)
                t2 = parse_xml(fn)
                assert t2 is not None
                assert root(t1).get('entityID') == root(t2).get('entityID')
                assert root(t2).get('entityID') == entity_id
            except IOError:
                raise Skip
            finally:
                shutil.rmtree(tmpdir)

    def test_empty_certreport(self):
        with patch.multiple("sys", exit=self.sys_exit, stdout=StreamCapturing(sys.stdout)):
            try:
                self.exec_pipeline("""
- certreport
""")
                assert False
            except PipeException:
                pass
            except IOError:
                raise Skip

    def test_pick_invalid(self):
        with patch.multiple("sys", exit=self.sys_exit, stdout=StreamCapturing(sys.stdout)):
            tmpfile = tempfile.NamedTemporaryFile('w').name
            try:
                self.exec_pipeline("""
- load validate False:
   - %s/metadata
- pick:
   - https://idp.example.com/saml2/idp/metadata.php1
- publish: %s
""" % (self.datadir, tmpfile))
                assert False
            except PipeException, ex:
                print "".join(sys.stdout.captured)
                print str(ex)
                pass
            except IOError:
                raise Skip
            finally:
                try:
                    os.unlink(tmpfile)
                except:
                    pass