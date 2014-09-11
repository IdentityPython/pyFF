import os
import tempfile
from mako.lookup import TemplateLookup
from pyff.mdrepo import MDRepository
from pyff.pipes import plumbing
from pyff.test import SignerTestCase

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

    @classmethod
    def setUpClass(cls):
        SignerTestCase.setUpClass()

    def setUp(self):
        SignerTestCase.setUpClass()
        print "setup called for PipeLineTest"
        self.templates = TemplateLookup(directories=[os.path.join(self.datadir, 'simple-pipeline')])


class SigningTest(PipeLineTest):

    def test_signing(self):
        self.output = tempfile.NamedTemporaryFile('w').name
        res, md, ctx = self.run_pipeline("signer.fd", self)
        eIDs = [e.get('entityID') for e in md.store]
        assert('https://idp.aco.net/idp/shibboleth' in eIDs)
        assert('https://skriptenforum.net/shibboleth' in eIDs)
        os.unlink(self.output)

    def test_signing_and_validation(self):
        self.output = tempfile.NamedTemporaryFile('w').name
        res_s, md_s, ctx_s = self.run_pipeline("signer.fd", self)
        res_v, md_v, ctx_v = self.run_pipeline("validator.fd", self)

        eIDs = [e.get('entityID') for e in md_v.store]
        assert('https://idp.aco.net/idp/shibboleth' in eIDs)
        assert('https://skriptenforum.net/shibboleth' in eIDs)
        os.unlink(self.output)

    def test_cert_report(self):
        self.output = tempfile.NamedTemporaryFile('w').name
        res, md, ctx = self.run_pipeline("certreport.fd", self)
        eIDs = [e.get('entityID') for e in md.store]
        assert('https://idp.aco.net/idp/shibboleth' in eIDs)
        assert('https://skriptenforum.net/shibboleth' in eIDs)
        with open(self.output, 'r') as fd:
            print fd.read()

    def test_cert_report_swamid(self):
        self.output = tempfile.NamedTemporaryFile('w').name
        res, md, ctx = self.run_pipeline("certreport-swamid.fd", self)
        with open(self.output, 'r') as fd:
            print fd.read()