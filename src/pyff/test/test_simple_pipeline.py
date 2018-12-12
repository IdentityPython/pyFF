import tempfile

import os
from mako.lookup import TemplateLookup

from pyff.constants import NS
from pyff.samlmd import MDRepository
from pyff.pipes import plumbing
from pyff.test import SignerTestCase


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

    def test_entityid_present(self):
        eids = [e.get('entityID') for e in self.md_signer.store]
        print(eids)
        assert('https://idp.aco.net/idp/shibboleth' in eids)
        assert('https://skriptenforum.net/shibboleth' in eids)

        eids = [e.get('entityID') for e in self.md_validator.store]
        print(eids)
        assert('https://idp.aco.net/idp/shibboleth' in eids)
        assert('https://skriptenforum.net/shibboleth' in eids)

    def test_non_zero_output(self):
        assert(self.md_signer is not None)
        assert(self.md_signer.store.size() == 2)
        assert(self.md_validator is not None)
        assert(self.md_validator.store.size() == 2)
        assert(os.path.getsize(self.output) > 0)

    def test_select_single(self):
        assert(self.validator_result is not None)
        entities = self.validator_result.findall('{%s}EntityDescriptor' % NS['md'])
        assert(len(entities) == 1)
        assert(entities[0].get('entityID') == 'https://idp.aco.net/idp/shibboleth')

    def tear_down(self):
        super(SimplePipeLineTest, self).tearDown()
        #os.unlink(self.signer)
        #os.unlink(self.validator)
        #os.unlink(self.output)
