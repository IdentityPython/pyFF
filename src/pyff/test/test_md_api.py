
import requests
from pyff.test.test_pipeline import PipeLineTest
from wsgi_intercept.interceptor import RequestsInterceptor, UrllibInterceptor
from pyff.api import mkapp
from pyff.test import SignerTestCase
from mako.lookup import TemplateLookup
import tempfile
import os
import unittest


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
        cls._app = mkapp(cls.mdx)
        cls.app = lambda *args, **kwargs: cls._app

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
            assert(int(data['store']['size']) >= 0)

    def test_parse_robots(self):
        try:
            import six.moves.urllib_robotparser as robotparser
        except ImportError as ex:
            raise unittest.SkipTest()

        rp = robotparser.RobotFileParser()
        with UrllibInterceptor(self.app, host='127.0.0.1', port=80) as url:
            rp.set_url("{}/robots.txt".format(url))
            rp.read()
            assert not rp.can_fetch("*", url)

    def test_webfinger(self):
        with RequestsInterceptor(self.app, host='127.0.0.1', port=80) as url:
            r = requests.get("{}/.well-known/webfinger?resource={}".format(url, url))
            assert (r.status_code == 200)
            assert ("application/json" in r.headers['content-type'])
            data = r.json()
            assert(data is not None)
            assert('expires' in data)
            assert('links' in data)
            assert('subject' in data)
            assert(data['subject'] == url)
            for link in data['links']:
                assert('rel' in link)
                assert('href' in link)

    def test_webfinger_rel_dj(self):
        with RequestsInterceptor(self.app, host='127.0.0.1', port=80) as url:
            r = requests.get("{}/.well-known/webfinger?resource={}&rel=disco-json".format(url, url))
            assert (r.status_code == 200)
            assert ("application/json" in r.headers['content-type'])
            data = r.json()
            assert(data is not None)
            assert('expires' in data)
            assert('links' in data)
            assert('subject' in data)
            assert(data['subject'] == url)
            for link in data['links']:
                assert('rel' in link)
                assert(link['rel'] in 'disco-json')
                assert(link['rel'] not in 'urn:oasis:names:tc:SAML:2.0:metadata')
                assert('href' in link)

    def test_load_and_query(self):
        with RequestsInterceptor(self.app, host='127.0.0.1', port=80) as url:
            r = requests.post("{}/api/call/update".format(url))
            assert ("application/xml" in r.headers['content-type'])

            # verify we managed to load something into the DB
            r = requests.get("{}/api/status".format(url))
            assert ("application/json" in r.headers['content-type'])
            assert ("version" in r.text)
            assert (r.status_code == 200)
            data = r.json()
            assert ('version' in data)
            assert ('store' in data)
            assert ('size' in data['store'])
            assert (int(data['store']['size']) > 0)

            # load the NORDUnet IdP as xml
            r = requests.get("{}/entities/%7Bsha1%7Dc50752ce1d12c2b37da13a1a396b8e3895d35dd9.xml".format(url))
            assert (r.status_code == 200)
            assert ('application/xml' in r.headers['Content-Type'])

            # load the NORDUnet IdP as json
            r = requests.get("{}/entities/%7Bsha1%7Dc50752ce1d12c2b37da13a1a396b8e3895d35dd9.json".format(url))
            assert (r.status_code == 200)
            data = r.json()
            assert(data is not None and len(data) == 1)
            info = data[0]
            assert (type(info) == dict)
            assert (info['title'] == 'NORDUnet')
            assert ('nordu.net' in info['scope'])