import os
import mock
import sys
import tempfile
from mako.lookup import TemplateLookup
from nose.plugins.skip import Skip
import yaml
from pyff.mdrepo import MDRepository
from pyff.pipes import plumbing, Plumbing, PipeException
from pyff.test import SignerTestCase, ExitException
from StringIO import StringIO


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
        print p
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

    def test_empty_select(self):
        with mock.patch("sys.stdout", StreamCapturing(sys.stdout)) as ctx:
            try:
                self.exec_pipeline("""
- load:
  - http://md.swamid.se/md/swamid-2.0.xml
- info
""")
                assert False
            except IOError:
                raise Skip
            except PipeException:
                pass

    def test_info_and_dump(self):
        with mock.patch("sys.stdout", StreamCapturing(sys.stdout)) as ctx:
            try:
                self.exec_pipeline("""
- load:
  - http://md.swamid.se/md/swamid-2.0.xml
- select
- dump
- info
""")
                assert('https://idp.nordu.net/idp/shibboleth' in sys.stdout.captured)
            except IOError:
                raise Skip


    def test_end(self):
        with mock.patch("sys.exit", self.sys_exit):
            with mock.patch("sys.stdout", StreamCapturing(sys.stdout)) as ctx:
                try:
                    self.exec_pipeline("""
- end 1 "slartibartifast"
""")
                    assert False
                except IOError:
                    raise Skip
                except ExitException,ex:
                    assert ex.code == 1
                    assert "slartibartifast" in sys.stdout.captured

    def test_end(self):
        with mock.patch("sys.exit", self.sys_exit):
            with mock.patch("sys.stdout", StreamCapturing(sys.stdout)) as ctx:
                try:
                    self.exec_pipeline("""
- dump
""")
                    assert '<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"/>' \
                           in "".join(sys.stdout.captured)
                except IOError:
                    raise Skip

    def test_empty_dump(self):
        with mock.patch("sys.exit", self.sys_exit):
            with mock.patch("sys.stdout", StreamCapturing(sys.stdout)) as ctx:
                try:
                    self.exec_pipeline("""
- publish
""")
                    assert False
                except PipeException:
                    pass
                except IOError:
                    raise Skip

    def test_empty_dump(self):
        with mock.patch("sys.exit", self.sys_exit):
            with mock.patch("sys.stdout", StreamCapturing(sys.stdout)) as ctx:
                try:
                    self.exec_pipeline("""
- load:
  - file://%s/metadata/test01.xml
- select
- publish
""" % self.datadir)
                    assert False
                except PipeException:
                    pass
                except IOError:
                    raise Skip