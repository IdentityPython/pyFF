import os
import tempfile
import sys
import imp
from mako.lookup import TemplateLookup
from mock import patch
import pkg_resources
from pyff import md
from pyff.mdrepo import MDRepository
from pyff.pipes import plumbing
from StringIO import StringIO
from pyff.test import SignerTestCase

__author__ = 'leifj'

class ExitException(Exception):
    def __init__(self, code):
        self.code = code

    def __str__(self):
        return "would have exited with %d" % self.code

class PipeLineTest(SignerTestCase):

    def run_pipeline(self, pl_name, ctx=dict(), md=MDRepository()):
        pipeline = tempfile.NamedTemporaryFile('w').name
        template = self.templates.get_template(pl_name)
        with open(pipeline, "w") as fd:
            fd.write(template.render(ctx=ctx))
        res = plumbing(pipeline).process(md, state={'batch': True, 'stats': {}})
        os.unlink(pipeline)
        return res, md, ctx

    def run_pyff(self, *args):
        def _mock_exit(n):
            if n != 0:
                raise ExitException(n)

        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                filename = pkg_resources.resource_filename(__name__, '../md.py')
                opts = list(args)
                opts.insert(0, filename)
                sys.argv = opts
                orig_exit = sys.exit
                sys.exit = _mock_exit
                try:
                    exit_code = 0
                    md.main()
                except ExitException, ex:
                    exit_code = ex.code
                finally:
                    sys.exit = orig_exit
                return mock_stdout.getvalue(), mock_stderr.getvalue(), exit_code

    def setUp(self):
        super(PipeLineTest, self).setUp()
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

    def test_cert_report_SWAMID(self):
        self.output = tempfile.NamedTemporaryFile('w').name
        res, md, ctx = self.run_pipeline("certreport-swamid.fd", self)
        with open(self.output, 'r') as fd:
            print fd.read()