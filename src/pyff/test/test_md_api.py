import os
import shutil
import tempfile
import unittest
from datetime import datetime, timezone
from urllib.parse import quote as urlescape
from xml.etree import ElementTree as ET

import pytest
import requests
from lxml import etree
from mako.lookup import TemplateLookup
from wsgi_intercept.interceptor import RequestsInterceptor, UrllibInterceptor

from pyff.api import mkapp
from pyff.constants import config
from pyff.samlmd import iter_entities
from pyff.test import SignerTestCase
from pyff.test.test_pipeline import PipeLineTest


class PyFFAPITest(PipeLineTest):
    """
    Runs twill tests using the wsgi-intercept
    """

    mdx = None
    mdx_template = None
    app = None
    tmp = None

    @classmethod
    def setUpClass(cls):
        SignerTestCase.setUpClass()
        cls.templates = TemplateLookup(directories=[os.path.join(cls.datadir, 'mdx')])
        with tempfile.TemporaryDirectory() as td:
            cls.tmp = td
            cls.mdx = os.path.join(td, 'mdx.fd')
            cls.mdx_template = cls.templates.get_template('mdx.fd')
            with open(cls.mdx, "w+") as fd:
                fd.write(cls.mdx_template.render(ctx=cls))
            with open(cls.mdx) as r:
                print("".join(r.readlines()))
            config.local_copy_dir = td
            cls._app = mkapp(cls.mdx)
            cls.app = lambda *args, **kwargs: cls._app

    @classmethod
    def tearDownClass(cls):
        SignerTestCase.tearDownClass()
        if os.path.exists(cls.tmp):
            shutil.rmtree(cls.tmp)

    def test_status(self):
        with RequestsInterceptor(self.app, host='127.0.0.1', port=80) as url:
            r = requests.get(f"{url}/api/status")
            assert "application/json" in r.headers['content-type']
            assert "version" in r.text
            assert r.status_code == 200
            data = r.json()
            assert 'version' in data
            assert 'store' in data
            assert 'size' in data['store']
            assert int(data['store']['size']) >= 0

    def test_parse_robots(self):
        try:
            from urllib import robotparser
        except ImportError:
            raise unittest.SkipTest()

        rp = robotparser.RobotFileParser()
        with UrllibInterceptor(self.app, host='127.0.0.1', port=80) as url:
            rp.set_url(f"{url}/robots.txt")
            rp.read()
            assert not rp.can_fetch("*", url)

    def test_webfinger(self):
        with RequestsInterceptor(self.app, host='127.0.0.1', port=80) as url:
            r = requests.get(f"{url}/.well-known/webfinger?resource={url}")
            assert r.status_code == 200
            assert "application/json" in r.headers['content-type']
            data = r.json()
            assert data is not None
            assert 'expires' in data
            assert 'links' in data
            assert 'subject' in data
            assert data['subject'] == url
            for link in data['links']:
                assert 'rel' in link
                assert 'href' in link

    def test_webfinger_rel_dj(self):
        with RequestsInterceptor(self.app, host='127.0.0.1', port=80) as url:
            r = requests.get(f"{url}/.well-known/webfinger?resource={url}&rel=disco-json")
            assert r.status_code == 200
            assert "application/json" in r.headers['content-type']
            data = r.json()
            assert data is not None
            assert 'expires' in data
            assert 'links' in data
            assert 'subject' in data
            assert data['subject'] == url
            for link in data['links']:
                assert 'rel' in link
                assert link['rel'] in 'disco-json'
                assert link['rel'] not in 'urn:oasis:names:tc:SAML:2.0:metadata'
                assert 'href' in link

    @pytest.mark.skipif(os.environ.get('PYFF_SKIP_SLOW_TESTS') is not None, reason='Slow tests skipped')
    def test_load_and_query(self):
        with RequestsInterceptor(self.app, host='127.0.0.1', port=80) as url:
            r = requests.post(f"{url}/api/call/update")
            assert "application/samlmetadata+xml" in r.headers['Content-Type']

            # verify we managed to load something into the DB
            r = requests.get(f"{url}/api/status")
            assert "application/json" in r.headers['content-type']
            assert "version" in r.text
            assert r.status_code == 200
            data = r.json()
            assert 'version' in data
            assert 'store' in data
            assert 'size' in data['store']
            assert int(data['store']['size']) > 0

            # load the NORDUnet IdP as xml
            r = requests.get(f"{url}/entities/%7Bsha1%7Dc50752ce1d12c2b37da13a1a396b8e3895d35dd9.xml")
            assert r.status_code == 200
            assert 'application/samlmetadata+xml' in r.headers['Content-Type']

            # load the NORDUnet IdP as json
            r = requests.get(f"{url}/entities/%7Bsha1%7Dc50752ce1d12c2b37da13a1a396b8e3895d35dd9.json")
            assert "application/json" in r.headers['Content-Type']
            assert r.status_code == 200
            data = r.json()
            assert data is not None and len(data) == 1
            info = data[0]
            assert isinstance(info, dict)
            assert info['title'] == 'NORDUnet'
            assert 'nordu.net' in info['scope']

            # check that we get a discovery_responses where we expect one
            r = requests.get(f"{url}/entities/%7Bsha1%7Dc3ba81cede254454b64ee9743df19201fe34adc9.json")
            assert r.status_code == 200
            data = r.json()
            info = data[0]
            assert (
                'https://box-idp.nordu.net/simplesaml/module.php/saml/sp/discoResponse' in info['discovery_responses']
            )

            r = requests.get(f"{url}/entities/https%3A%2F%2Fclarino.uib.no%2F", headers={'Accept':'application/json'})
            assert r.status_code == 200
            data = r.json()
            info = data[0]
            assert (
                'https://clarino.uib.no/feide/single-login' in info['discovery_responses']
            )

            r = requests.get(f"{url}/entities/https%3A%2F%2Fshibboleth.mzk.cz%2Fsimplesaml%2Fmetadata.xml", headers={'Accept':'application/xml'})
            assert r.status_code == 200

            root = ET.fromstring(r.content)
            assert root.tag.endswith('EntityDescriptor')


class PyFFAPITestResources(PipeLineTest):
    """
    Runs twill tests using the wsgi-intercept
    """

    mdx = None
    mdx_template = None
    app = None

    @classmethod
    def setUpClass(cls):
        SignerTestCase.setUpClass()
        config.local_copy_dir = tempfile.mkdtemp()
        cls.templates = TemplateLookup(directories=[os.path.join(cls.datadir, 'mdx')])
        cls.mdx = tempfile.NamedTemporaryFile('w').name
        # cls.mdx_template = cls.templates.get_template('mdx.fd')
        cls.test01 = os.path.join(cls.datadir, 'metadata', 'test01.xml')
        with open(cls.mdx, "w") as fd:
            fd.write(
                f"""
- when update:
    - load:
        - {cls.test01}
"""
            )
        with open(cls.mdx) as r:
            print("".join(r.readlines()))
        cls._app = mkapp(cls.mdx)
        cls.app = lambda *args, **kwargs: cls._app

    @classmethod
    def tearDownClass(cls):
        SignerTestCase.tearDownClass()
        if os.path.exists(cls.mdx):
            os.unlink(cls.mdx)
        if os.path.exists(config.local_copy_dir):
            shutil.rmtree(config.local_copy_dir)

    def test_api_resources(self):
        """"""
        with RequestsInterceptor(self.app, host='127.0.0.1', port=80) as url:
            r1 = requests.post(f'{url}/api/call/update')
            assert r1.status_code == 200

            r2 = requests.get(f'{url}/api/resources')
            assert 'application/json' in r2.headers['content-type']
            # assert "version" in r.text
            assert r2.status_code == 200
            data = r2.json()

            expected = [
                {
                    'Resource': f'file://{self.test01}',
                    'HTTP Response Headers': {'Content-Length': 3633},
                    'Status Code': '200',
                    'Reason': None,
                    'State': 'Ready',
                    'Entities': ['https://idp.example.com/saml2/idp/metadata.php'],
                    'Validation Errors': {},
                    'Expiration Time': data[0]['Expiration Time'],  # '2021-04-14 15:21:33.150742',
                    'Expired': False,
                    'Valid': True,
                    'Parser': 'SAML',
                    'Last Seen': data[0]['Last Seen'],  # '2021-04-14 14:21:33.150781',
                }
            ]
            assert data == expected

            # Now check the timestamps
            now = datetime.now(tz=timezone.utc)

            exp = datetime.fromisoformat(data[0]['Expiration Time'])
            assert (exp - now).total_seconds() > 3590
            assert (exp - now).total_seconds() < 3610

            last_seen = datetime.fromisoformat(data[0]['Last Seen'])
            assert (last_seen - now).total_seconds() < 60

            assert os.path.exists(os.path.join(config.local_copy_dir, urlescape(f'file://{self.test01}')))


class PyFFAPITestTrailingSlash(PipeLineTest):
    """
    A trailing slash is part of an entityID, except when there is no entityID at all -
    a bare /entities/ selects everything, just like /entities does.
    """

    mdx = None
    app = None
    idp = 'https://idp.example.com/saml2/idp/metadata.php'
    sp = 'https://sp.example.com/saml2/metadata/'

    @classmethod
    def setUpClass(cls):
        SignerTestCase.setUpClass()
        config.local_copy_dir = tempfile.mkdtemp()
        cls.test01 = os.path.join(cls.datadir, 'metadata', 'test01.xml')
        cls.test04 = os.path.join(cls.datadir, 'metadata', 'test04-trailing-slash-sp.xml')
        cls.mdx = tempfile.NamedTemporaryFile('w').name
        with open(cls.mdx, "w") as fd:
            fd.write(
                f"""
- when update:
    - load:
        - {cls.test01}
        - {cls.test04}
- when request:
    - select
    - pipe:
        - when accept application/xml:
            - finalize:
                cacheDuration: PT5H
                validUntil: P10D
            - emit application/xml
            - break
"""
            )
        cls._app = mkapp(cls.mdx)
        cls.app = lambda *args, **kwargs: cls._app

    @classmethod
    def tearDownClass(cls):
        SignerTestCase.tearDownClass()
        if os.path.exists(cls.mdx):
            os.unlink(cls.mdx)
        if os.path.exists(config.local_copy_dir):
            shutil.rmtree(config.local_copy_dir)

    def _entity_ids(self, url, path):
        """Return the set of entityIDs the API serves for path"""
        r = requests.get(f'{url}{path}', headers={'Accept': 'application/xml'})
        assert r.status_code == 200, f'{path} -> {r.status_code}'
        t = etree.fromstring(r.content)
        return {e.get('entityID') for e in iter_entities(t)}

    def test_entities_without_trailing_slash(self):
        with RequestsInterceptor(self.app, host='127.0.0.1', port=80) as url:
            assert requests.post(f'{url}/api/call/update').status_code == 200
            assert self._entity_ids(url, '/entities') == {self.idp, self.sp}

    def test_entities_with_trailing_slash(self):
        with RequestsInterceptor(self.app, host='127.0.0.1', port=80) as url:
            assert requests.post(f'{url}/api/call/update').status_code == 200
            assert self._entity_ids(url, '/entities/') == {self.idp, self.sp}

    def test_entity_id_keeps_its_trailing_slash(self):
        """An entityID ending in a slash must not be truncated - cf. issue #298"""
        with RequestsInterceptor(self.app, host='127.0.0.1', port=80) as url:
            assert requests.post(f'{url}/api/call/update').status_code == 200
            # the unescaped form - WSGI hands us a single slash after the scheme
            assert self._entity_ids(url, '/entities/https:/sp.example.com/saml2/metadata/') == {self.sp}
            # ... and the escaped form
            assert self._entity_ids(url, f'/entities/{urlescape(self.sp, safe="")}') == {self.sp}

    def test_entity_id_without_trailing_slash_is_not_found(self):
        """Dropping the slash from an entityID that has one must not match it"""
        with RequestsInterceptor(self.app, host='127.0.0.1', port=80) as url:
            assert requests.post(f'{url}/api/call/update').status_code == 200
            assert self._entity_ids(url, '/entities/https:/sp.example.com/saml2/metadata') == set()
