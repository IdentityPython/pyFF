
import unittest
from six.moves.urllib_parse import quote_plus
import tempfile
from threading import Thread
from time import sleep
from mako.lookup import TemplateLookup
import requests
from pyff.test import SignerTestCase, run_pyffd, run_pyff, find_unbound_port
from pyff.test.test_pipeline import PipeLineTest
import os
from pyff.md import __doc__ as pyffdoc
from pyff import __version__ as pyffversion
from pyff.utils import parse_xml, root, validate_document
import six

# range of ports where available ports can be found
PORT_RANGE = [33000, 60000]
MAX_PORT_TRIES = 100


class PyFFDTest(PipeLineTest):
    """
    Runs twill tests using the pyffd cmdline - only mocks exit
    """

    pyffd_thread = None
    mdx = None
    mdx_template = None
    pidfile = None
    tmpdir = None
    curdir = None
    port = None
    logfile = None

    @classmethod
    def setUpClass(cls):
        SignerTestCase.setUpClass()
        cls.templates = TemplateLookup(directories=[os.path.join(cls.datadir, 'mdx')])
        cls.mdx = tempfile.NamedTemporaryFile('w').name
        cls.mdx_template = cls.templates.get_template('mdx.fd')
        cls.pidfile = tempfile.NamedTemporaryFile('w').name
        cls.logfile = tempfile.NamedTemporaryFile('w').name
        with open(cls.mdx, "w") as fd:
            fd.write(cls.mdx_template.render(ctx=cls))
        with open(cls.mdx, 'r') as r:
            print("".join(r.readlines()))
        cls.curdir = os.getcwd()
        cls.port = find_unbound_port()
        print("Using port {:d}, logging to {}".format(cls.port, cls.logfile))
        cls.pyffd_thread = Thread(target=run_pyffd,
                                  name="pyffd-test",
                                  args=["--loglevel=DEBUG",
                                        "--log=%s" % cls.logfile,
                                        "--dir=%s" % cls.curdir,
                                        '-f',
                                        '-a',
                                        '-P', "%s" % cls.port,
                                        '-C',
                                        '-p', cls.pidfile,
                                        "--allow_shutdown",
                                        cls.mdx])
        cls.pyffd_thread.start()
        sleep(1)
        for i in range(0, 60):
            try:
                r = requests.get("http://127.0.0.1:%s/status" % cls.port)
                if r.json() and 'running' in r.json()['status']:
                    return

                print(r.json())
                sleep(1)
            except Exception as ex:
                print(ex)
                pass
            sleep(1)
        raise ValueError("unable to start test pyffd server on port %d" % cls.port)

    def test_is_running(self):
        assert (os.path.exists(self.pidfile))
        with open(PyFFDTest.pidfile) as pidf:
            pid = int(pidf.read().strip())
            assert pid
        assert (PyFFDTest.pyffd_thread.isAlive())

    def test_frontpage(self):
        r = requests.get("http://127.0.0.1:%s/" % self.port)
        assert ("text/html" in r.headers['content-type'])
        assert ("Metadata By Attributes" in r.text)
        assert (r.status_code == 200)

    def test_alias_ndn(self):
        r = requests.get("http://127.0.0.1:%s/ndn.xml" % self.port)
        assert (r.status_code == 200)
        # assert (r.encoding == 'utf8')
        t = parse_xml(six.BytesIO(r.content))
        assert (t is not None)
        assert (root(t).get('entityID') == 'https://idp.nordu.net/idp/shibboleth')
        validate_document(t)

    def test_metadata_html(self):
        r = requests.get(
            "http://127.0.0.1:%s/metadata/%%7Bsha1%%7Dc50752ce1d12c2b37da13a1a396b8e3895d35dd9.html" % self.port)
        assert (r.status_code == 200)
        assert ('text/html' in r.headers['Content-Type'])

    def test_metadata_xml(self):
        r = requests.get(
            "http://127.0.0.1:%s/metadata/%%7Bsha1%%7Dc50752ce1d12c2b37da13a1a396b8e3895d35dd9.xml" % self.port)
        assert (r.status_code == 200)
        assert ('application/xml' in r.headers['Content-Type'])

    def test_metadata_json(self):
        r = requests.get(
            "http://127.0.0.1:%s/metadata/%%7Bsha1%%7Dc50752ce1d12c2b37da13a1a396b8e3895d35dd9.json" % self.port)
        assert (r.status_code == 200)
        info = r.json()[0]
        assert (type(info) == dict)
        assert (info['title'] == 'NORDUnet')
        assert ('nordu.net' in info['scope'])

    def test_md_query_single(self):
        q = quote_plus('https://idp.nordu.net/idp/shibboleth')
        r = requests.get("http://127.0.0.1:%s/entities/%s" % (self.port, q))
        assert (r.status_code == 200)
        assert ('application/xml' in r.headers['Content-Type'])
        t = parse_xml(six.BytesIO(r.content))
        assert (t is not None)
        e = root(t)
        assert (e.get('entityID') == 'https://idp.nordu.net/idp/shibboleth')

    def test_all_entities_parses(self):
        r = requests.get("http://127.0.0.1:%s/entities" % self.port)
        assert (r.status_code == 200)
        # assert (r.encoding == 'utf8')
        t = parse_xml(six.BytesIO(r.content))
        assert (t is not None)
        validate_document(t)

    def test_webfinger(self):
        r = requests.get(
            "http://127.0.0.1:%s/.well-known/webfinger?resource=http://127.0.0.1:%s" % (self.port, self.port))
        assert (r.status_code == 200)
        assert r.json()

    def test_some_pages(self):
        for p in ('robots.txt', 'settings', 'about', 'reset'):
            r = requests.get("http://127.0.0.1:%s/%s" % (self.port, p))
            assert (r.status_code == 200)

    def test_parse_robots(self):
        try:
            import six.moves.urllib_robotparser as robotparser
        except ImportError as ex:
            raise unittest.SkipTest()

        rp = robotparser.RobotFileParser()
        rp.set_url("http://127.0.0.1:%s/robots.txt" % self.port)
        rp.read()
        assert not rp.can_fetch("*", "http://127.0.0.1:%s/" % self.port)

    def test_favicon(self):
        r = requests.get("http://127.0.0.1:%s/favicon.ico" % self.port)
        assert (r.status_code == 200)
        assert ('image/x-icon' in r.headers['Content-Type'])

    def test_ds_bad_request(self):
        r = requests.get("http://127.0.0.1:%s/role/idp.ds" % self.port)
        assert (r.status_code == 400)

    def test_ds_request(self):
        r = requests.get(
            "http://127.0.0.1:%s/role/idp.ds?entityID=https://idp.nordu.net/idp/shibboleth&return=#" % self.port)
        assert (r.status_code == 200)

    def test_ds_search(self):
        r = requests.get("http://127.0.0.1:%s/role/idp.s" % self.port)
        assert (r.status_code == 200)
        assert len(r.json()) == 0

    @classmethod
    def tearDownClass(cls):
        SignerTestCase.tearDownClass()
        try:
            requests.get("http://127.0.0.1:%s/shutdown" % cls.port)
            with open(cls.logfile) as fd:
                print ("+++ DEBUG log +++")
                print("\n".join(fd.readlines()))
        except Exception as ex:
            from traceback import print_exc
            print_exc(ex)
        finally:
            if os.path.exists(cls.mdx):
                os.unlink(cls.mdx)
            if os.path.exists(cls.pidfile):
                os.unlink(cls.pidfile)
            if os.path.exists(cls.logfile):
                os.unlink(cls.logfile)
        cls.pyffd_thread.join()


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
        out, err, exit_code = run_pyff("--loglevel=DEBUG", self.signer)
        assert err
        assert (exit_code == 0)

    def test_run_bad(self):
        out, err, exit_code = run_pyff("--loglevel=DEBUG", self.bad)
        assert 'Traceback' in err
        assert 'No pipe named snartibartifast is installed' in err
        print(exit_code)
        assert (exit_code == 1)

    def test_run_signer_logfile(self):
        out, err, exit_code = run_pyff("--loglevel=DEBUG", "--logfile=%s" % self.logfile, self.signer)
        assert (exit_code == 0)

    def test_help(self):
        out, err, exit_code = run_pyff("--help")
        assert (pyffdoc in out)
        assert (exit_code == 0)

    def test_version(self):
        out, err, exit_code = run_pyff("--version")
        assert (pyffversion in out)
        assert (exit_code == 0)

    def test_bad_arg(self):
        out, err, exit_code = run_pyff("--snartibartfast")
        assert (exit_code == 2)
        assert ('snartibartfast' in out)

    def test_bad_loglevel(self):
        try:
            out, err, exit_code = run_pyff("--loglevel=TRACE")
        except ValueError as ex:
            assert ('TRACE' in str(ex))

    def tear_down(self):
        super(PyFFTest, self).tearDown()
        os.unlink(self.signer)
        os.unlink(self.output)
        os.unlink(self.logfile)
