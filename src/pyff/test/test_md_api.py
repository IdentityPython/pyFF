
import requests
from pyff.test.test_pipeline import PipeLineTest
from wsgi_intercept.interceptor import RequestsInterceptor
from pyff.api import mkapp
from pyff.test import SignerTestCase
from mako.lookup import TemplateLookup
import tempfile
import os


class PyFFAPITest(PipeLineTest):
    """
    Runs twill tests using the wsgi-intercept
    """

    mdx = None
    mdx_template = None
    app = None

    @classmethod
    def setUpClass(cls):
        SignerTestCase.setUpClass()
        cls.templates = TemplateLookup(directories=[os.path.join(cls.datadir, 'mdx')])
        cls.mdx = tempfile.NamedTemporaryFile('w').name
        cls.mdx_template = cls.templates.get_template('mdx.fd')
        with open(cls.mdx, "w") as fd:
            fd.write(cls.mdx_template.render(ctx=cls))
        with open(cls.mdx, 'r') as r:
            print("".join(r.readlines()))
        cls.app = lambda *args, **kwargs: mkapp(cls.mdx)

    @classmethod
    def tearDownClass(cls):
        SignerTestCase.tearDownClass()
        if os.path.exists(cls.mdx):
            os.unlink(cls.mdx)

    def test_status(self):
        with RequestsInterceptor(self.app, host='127.0.0.1', port=80) as url:
            r = requests.get("{}/api/status".format(url))
            assert ("application/json" in r.headers['content-type'])
            assert ("version" in r.text)
            assert (r.status_code == 200)
            data = r.json()
            assert('version' in data)
            assert('store' in data)
            assert('size' in data['store'])
            assert(int(data['store']['size']) == 0)