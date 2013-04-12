import os
import tempfile
from mako.lookup import TemplateLookup
import pkg_resources
from pyff import MDRepository, plumbing
from pyff.test import SignerTestCase, _p

__author__ = 'leifj'


class SimplePipeLineTest(SignerTestCase):

    def setUp(self):
        super(SimplePipeLineTest, self).setUp()
        self.templates = TemplateLookup(directories=[os.path.join(self.datadir, 'simple-pipeline')])
        self.output = tempfile.NamedTemporaryFile('w').name
        self.signer = tempfile.NamedTemporaryFile('w').name
        self.signer_template = self.templates.get_template('signer.fd')
        self.validator = tempfile.NamedTemporaryFile('w').name
        self.validator_template = self.templates.get_template('validator.fd')
        self.md_signer = MDRepository()
        self.md_validator = MDRepository()
        with open(self.signer, "w") as fd:
            fd.write(self.signer_template.render(ctx=self))
        with open(self.validator, "w") as fd:
            fd.write(self.validator_template.render(ctx=self))
        self.signer_result = plumbing(self.signer).process(self.md_signer, state={'batch': True, 'stats': {}})
        self.validator_result = plumbing(self.validator).process(self.md_validator, state={'batch': True, 'stats': {}})

    def testEntityIDPresent(self):
        eIDs = [e.get('entityID') for e in self.md_signer]
        assert('https://idp.aco.net/idp/shibboleth' in eIDs)
        assert('https://skriptenforum.net/shibboleth' in eIDs)

        eIDs = [e.get('entityID') for e in self.md_validator]
        assert('https://idp.aco.net/idp/shibboleth' in eIDs)
        assert('https://skriptenforum.net/shibboleth' in eIDs)

    def testNonZeroOutput(self):
        assert(self.md_signer is not None)
        assert(len(self.md_signer) == 2)
        assert(self.md_validator is not None)
        assert(len(self.md_validator) == 1)
        assert(os.path.getsize(self.output) > 0)

    def testSelectSingle(self):
        assert(self.validator_result is not None)

    def tearDown(self):
        super(SimplePipeLineTest,self).tearDown()
        os.unlink(self.signer)
        os.unlink(self.validator)
        os.unlink(self.output)


