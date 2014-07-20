import os
import tempfile
from mako.lookup import TemplateLookup
from pyff import MDRepository, plumbing
from pyff.store import MemoryStore
from pyff.test import SignerTestCase

__author__ = 'leifj'


class PipeLineTest(SignerTestCase):

    def run_pipeline(self, pl_name, ctx=dict(), md=MDRepository(store=MemoryStore())):
        pipeline = tempfile.NamedTemporaryFile('w').name
        template = self.templates.get_template(pl_name)
        with open(pipeline, "w") as fd:
            fd.write(template.render(ctx=ctx))
        res = plumbing(pipeline).process(md, state={'batch': True, 'stats': {}})
        os.unlink(pipeline)
        return res, md, ctx

    def setUp(self):
        super(PipeLineTest, self).setUp()
        self.templates = TemplateLookup(directories=[os.path.join(self.datadir, 'simple-pipeline')])


class SigningTest(PipeLineTest):

    def testSigning(self):
        self.output = tempfile.NamedTemporaryFile('w').name
        res, md, ctx = self.run_pipeline("signer.fd", self)
        eIDs = [e.get('entityID') for e in md.store]
        assert('https://idp.aco.net/idp/shibboleth' in eIDs)
        assert('https://skriptenforum.net/shibboleth' in eIDs)
        os.unlink(self.output)

    def testSigningAndValidation(self):
        self.output = tempfile.NamedTemporaryFile('w').name
        res_s, md_s, ctx_s = self.run_pipeline("signer.fd", self)
        res_v, md_v, ctx_v = self.run_pipeline("validator.fd", self)

        eIDs = [e.get('entityID') for e in md_v.store]
        assert('https://idp.aco.net/idp/shibboleth' in eIDs)
        assert('https://skriptenforum.net/shibboleth' in eIDs)
        os.unlink(self.output)

    def testCertReport(self):
        self.output = tempfile.NamedTemporaryFile('w').name
        res, md, ctx = self.run_pipeline("certreport.fd", self)
        eIDs = [e.get('entityID') for e in md.store]
        assert('https://idp.aco.net/idp/shibboleth' in eIDs)
        assert('https://skriptenforum.net/shibboleth' in eIDs)
        with open(self.output, 'r') as fd:
            print fd.read()

    def testCertReportSWAMID(self):
        self.output = tempfile.NamedTemporaryFile('w').name
        res, md, ctx = self.run_pipeline("certreport-swamid.fd", self)
        with open(self.output, 'r') as fd:
            print fd.read()