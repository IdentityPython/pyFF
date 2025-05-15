import os
import tempfile
from io import StringIO

import pytest
import yaml
from mako.lookup import TemplateLookup

from pyff import builtins
from pyff.constants import NS
from pyff.pipes import Plumbing, plumbing
from pyff.repo import MDRepository
from pyff.test import SignerTestCase
from pyff.utils import parse_xml

__author__ = 'leifj'

# The 'builtins' import appears unused to static analysers, ensure it isn't removed
assert builtins is not None


class PipeLineTest(SignerTestCase):
    @pytest.fixture(autouse=True)
    def _capsys(self, capsys):
        self._capsys = capsys

    @property
    def captured_stdout(self) -> str:
        """ Return anything written to STDOUT during this test """
        out, _err = self._capsys.readouterr()  # type: ignore
        return out

    @property
    def captured_stderr(self) -> str:
        """ Return anything written to STDERR during this test """
        _out, err = self._capsys.readouterr()  # type: ignore
        return err

    @pytest.fixture(autouse=True)
    def _caplog(self, caplog):
        """ Return anything written to the logging system during this test """
        self._caplog = caplog

    @property
    def captured_log_text(self) -> str:
        return self._caplog.text  # type: ignore

    def run_pipeline(self, pl_name, ctx=None, md=None):
        if ctx is None:
            ctx = dict()

        if md is None:
            md = MDRepository()

        templates = TemplateLookup(directories=[os.path.join(self.datadir, 'simple-pipeline')])
        pipeline = tempfile.NamedTemporaryFile('w').name
        template = templates.get_template(pl_name)
        with open(pipeline, "w") as fd:
            fd.write(template.render(ctx=ctx))
        res = plumbing(pipeline).process(md, state={'batch': True, 'stats': {}})
        os.unlink(pipeline)
        return res, md, ctx

    def exec_pipeline(self, pstr):
        md = MDRepository()
        p = yaml.safe_load(StringIO(pstr))
        print(f"\n{yaml.dump(p)}")
        pl = Plumbing(p, pid="test")
        res = pl.process(md, state={'batch': True, 'stats': {}})
        return res, md

    @classmethod
    def setUpClass(cls):
        SignerTestCase.setUpClass()

    def setUp(self):
        SignerTestCase.setUpClass()
        self.templates = TemplateLookup(directories=[os.path.join(self.datadir, 'simple-pipeline')])


class ParseTest(PipeLineTest):
    def test_eidas_country(self):
            tmpfile = tempfile.NamedTemporaryFile('w').name
            try:
                self.exec_pipeline(f"""
- when eidas:
    - xslt:
       stylesheet: eidas-cleanup.xsl
    - break

- load:
   - file://{self.datadir}/eidas/eidas.xml cleanup eidas
- select
- publish: {tmpfile}
"""
                )
                xml = parse_xml(tmpfile)
                assert xml is not None
                entityID = "https://pre.eidas.gov.gr/EidasNode/ServiceMetadata"
                with_hide_from_discovery = xml.find("{{{}}}EntityDescriptor[@entityID='{}']".format(NS['md'], entityID))
                assert with_hide_from_discovery is not None
                search = "{{{}}}Extensions/{{{}}}EntityAttributes/{{{}}}Attribute[@Name='{}']".format(NS['md'], NS['mdattr'], NS['saml'],'http://macedir.org/entity-category')
                ecs = with_hide_from_discovery.find(search)
                assert ecs is not None
                entityID2 = "https://eidas.pp.dev-franceconnect.fr/EidasNode/ServiceMetadata"
                without_hide_from_discovery = xml.find("{{{}}}EntityDescriptor[@entityID='{}']".format(NS['md'], entityID2))
                ecs2 = without_hide_from_discovery.find(search)
                assert ecs2 is None
            except OSError:
                pass
            finally:
                try:
                #os.unlink(tmpfile)
                    pass
                except OSError:
                    pass
