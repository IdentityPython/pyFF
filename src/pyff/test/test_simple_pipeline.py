import os
import tempfile

from mako.lookup import TemplateLookup

from pyff.constants import NS
from pyff.mdrepo import MDRepository
from pyff.pipes import plumbing
from pyff.store import MemoryStore
from pyff.test import SignerTestCase
from pyff.test.test_pipeline import PipeLineTest
from pyff.md import __doc__ as pyffdoc
from pyff import __version__ as pyffversion


class PyFFTest(PipeLineTest):
    def setUp(self):
        super(PyFFTest, self).setUp()
        self.templates = TemplateLookup(directories=[os.path.join(self.datadir, 'simple-pipeline')])
        self.output = tempfile.NamedTemporaryFile('w').name
        self.signer = tempfile.NamedTemporaryFile('w').name
        self.signer_template = self.templates.get_template('signer.fd')
        with open(self.signer, "w") as fd:
            fd.write(self.signer_template.render(ctx=self))

    def test_run_signer(self):
        out = self.run_pyff("--log-level=DEBUG", self.signer)
        assert (out is not None)

    def test_help(self):
        out, exit_code = self.run_pyff("--help")
        assert (pyffdoc in out)
        assert (exit_code == 0)

    def test_version(self):
        out, exit_code = self.run_pyff("--version")
        assert (pyffversion in out)
        assert (exit_code == 0)

    def test_bad_arg(self):
        out, exit_code = self.run_pyff("--snartibartfast")
        assert (exit_code == 2)
        assert ('snartibartfast' in out)


    def tear_down(self):
        super(SimplePipeLineTest, self).tearDown()
        os.unlink(self.signer)
        os.unlink(self.output)

class SimplePipeLineTest(SignerTestCase):

    def setUp(self):
        super(SimplePipeLineTest, self).setUp()
        self.templates = TemplateLookup(directories=[os.path.join(self.datadir, 'simple-pipeline')])
        self.output = tempfile.NamedTemporaryFile('w').name
        self.signer = tempfile.NamedTemporaryFile('w').name
        self.signer_template = self.templates.get_template('signer.fd')
        self.validator = tempfile.NamedTemporaryFile('w').name
        self.validator_template = self.templates.get_template('validator.fd')
        self.md_signer = MDRepository(store=MemoryStore())
        self.md_validator = MDRepository(store=MemoryStore())
        with open(self.signer, "w") as fd:
            fd.write(self.signer_template.render(ctx=self))
        with open(self.validator, "w") as fd:
            fd.write(self.validator_template.render(ctx=self))
        self.signer_result = plumbing(self.signer).process(self.md_signer, state={'batch': True, 'stats': {}})
        self.validator_result = plumbing(self.validator).process(self.md_validator, state={'batch': True, 'stats': {}})

    def test_entityid_present(self):
        eids = [e.get('entityID') for e in self.md_signer.store]
        assert('https://idp.aco.net/idp/shibboleth' in eids)
        assert('https://skriptenforum.net/shibboleth' in eids)

        eids = [e.get('entityID') for e in self.md_validator.store]
        assert('https://idp.aco.net/idp/shibboleth' in eids)
        assert('https://skriptenforum.net/shibboleth' in eids)

    def test_non_zero_output(self):
        assert(self.md_signer is not None)
        assert(self.md_signer.store.size() == 3)
        assert(self.md_validator is not None)
        assert(self.md_validator.store.size() == 3)
        assert(os.path.getsize(self.output) > 0)

    def test_select_single(self):
        assert(self.validator_result is not None)
        entities = self.validator_result.findall('{%s}EntityDescriptor' % NS['md'])
        assert(len(entities) == 1)
        assert(entities[0].get('entityID') == 'https://idp.aco.net/idp/shibboleth')

    def tear_down(self):
        super(SimplePipeLineTest, self).tearDown()
        os.unlink(self.signer)
        os.unlink(self.validator)
        os.unlink(self.output)
