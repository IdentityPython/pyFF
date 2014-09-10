import tempfile
from threading import Thread
from time import sleep
from mako.lookup import TemplateLookup
import requests
from pyff.test.test_pipeline import PipeLineTest
import os
from pyff.md import __doc__ as pyffdoc
from pyff import __version__ as pyffversion


class PyFFDTest(PipeLineTest):
    """
    Runs twill tests using the pyffd cmdline - only mocks exit
    """
    def setUp(self):
        super(PyFFDTest, self).setUp()
        self.templates = TemplateLookup(directories=[os.path.join(self.datadir, 'mdx')])
        self.mdx = tempfile.NamedTemporaryFile('w').name
        self.mdx_template = self.templates.get_template('mdx.fd')
        self.pidfile = tempfile.NamedTemporaryFile('w').name
        with open(self.mdx, "w") as fd:
            fd.write(self.mdx_template.render(ctx=self))
        self.pyffd = Thread(target=self.run_pyffd,
                            name="pyffd-test",
                            args=["--loglevel=INFO", '-f', '-C', '-p', self.pidfile, "--terminator", self.mdx])
        self.pyffd.start()
        sleep(10)

    def test_is_running(self):
        assert (os.path.exists(self.pidfile))
        with open(self.pidfile) as pidf:
            pid = int(pidf.read().strip())
            assert pid
        assert (self.pyffd.isAlive())

    def tearDown(self):
        super(PyFFDTest, self).tearDown()
        requests.get("http://127.0.0.1:8080/shutdown")
        if os.path.exists(self.mdx):
            os.unlink(self.mdx)
        if os.path.exists(self.pidfile):
            os.unlink(self.pidfile)
        self.pyffd.join()



class PyFFTest(PipeLineTest):
    """
    Runs tests through the pyff cmdline - only mocks exit
    """
    def setUp(self):
        super(PyFFTest, self).setUp()
        self.templates = TemplateLookup(directories=[os.path.join(self.datadir, 'simple-pipeline')])
        self.output = tempfile.NamedTemporaryFile('w').name
        self.logfile = tempfile.NamedTemporaryFile('w').name
        self.signer = tempfile.NamedTemporaryFile('w').name
        self.signer_template = self.templates.get_template('signer.fd')
        with open(self.signer, "w") as fd:
            fd.write(self.signer_template.render(ctx=self))
        self.bad = tempfile.NamedTemporaryFile('w').name
        self.bad_template = self.templates.get_template('bad.fd')
        with open(self.bad, "w") as fd:
            fd.write(self.bad_template.render(ctx=self))

    def test_run_signer(self):
        out, err, exit_code = self.run_pyff("--loglevel=DEBUG", self.signer)
        assert (not out)
        assert (not err)
        assert (exit_code == 0)

    def test_run_bad(self):
        out, err, exit_code = self.run_pyff("--loglevel=DEBUG", self.bad)
        assert (not out)
        assert 'Traceback' in err
        assert 'No pipe named snartibartifast is installed' in err
        assert (exit_code == -1)

    def test_run_signer_logfile(self):
        out, err, exit_code = self.run_pyff("--loglevel=DEBUG", "--logfile=%s" % self.logfile, self.signer)
        assert (not out)
        assert (not err)
        assert (exit_code == 0)

    def test_help(self):
        out, err, exit_code = self.run_pyff("--help")
        assert (pyffdoc in out)
        assert (exit_code == 0)

    def test_version(self):
        out, err, exit_code = self.run_pyff("--version")
        assert (pyffversion in out)
        assert (exit_code == 0)

    def test_bad_arg(self):
        out, err, exit_code = self.run_pyff("--snartibartfast")
        assert (exit_code == 2)
        assert ('snartibartfast' in out)

    def test_bad_loglevel(self):
        try:
            out, err, exit_code = self.run_pyff("--loglevel=TRACE")
        except ValueError, ex:
            assert ('TRACE' in str(ex))

    def tear_down(self):
        super(PyFFTest, self).tearDown()
        os.unlink(self.signer)
        os.unlink(self.output)
        os.unlink(self.logfile)