import json
import os
import shutil
import sys
import tempfile

import pytest
import six
import yaml
from mako.lookup import TemplateLookup
from mock import patch

from pyff import builtins
from pyff.exceptions import MetadataException
from pyff.parse import ParserException
from pyff.pipes import PipeException, Plumbing, plumbing
from pyff.repo import MDRepository
from pyff.resource import ResourceException
from pyff.test import ExitException, SignerTestCase
from pyff.utils import hash_id, parse_xml, resource_filename, root

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
        p = yaml.safe_load(six.StringIO(pstr))
        print("\n{}".format(yaml.dump(p)))
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
    def test_parse(self):
        res, md = self.exec_pipeline(
            f"""
- load:
    - {self.datadir}/metadata
- select
- stats
"""
        )
        eIDs = [e.get('entityID') for e in md.store]
        assert 'https://idp.example.com/saml2/idp/metadata.php1' not in eIDs
        assert 'https://idp.example.com/saml2/idp/metadata.php' in eIDs
        assert (
            "removing 'https://idp.example.com/saml2/idp/metadata.php1': schema validation failed"
            in self.captured_log_text
        )


# To run all LoadErrorTests: ./setup.py test -s pyff.test.test_pipeline.LoadErrorTest
# To run individual test: ./setup.py test -s pyff.test.test_pipeline.LoadErrorTest.test_fail_on_error_no_file
class LoadErrorTest(PipeLineTest):
    # A File that does not exist must throw an error with fail_on_error=True
    def test_fail_on_error_no_file(self):
        try:
            res, md = self.exec_pipeline(
                f"""
    - load fail_on_error True:
        - {self.datadir}/file_that_does_not_exist.xml
    - select
    - stats
    """
            )
        except ResourceException as ex:
            print("----\n", ex, "\n++++")
            assert "file_that_does_not_exist.xml" in str(ex)
            return True

        assert "Expected PipeException or ResourceException" == False

    # A File that does not exist must throw an error with fail_on_error=True
    def test_fail_on_error_no_file_url(self):
        try:
            res, md = self.exec_pipeline(
                f"""
    - load fail_on_error True:
        - file://{self.datadir}/file_that_does_not_exist.xml
    - select
    - stats
    """
            )
        except ResourceException as ex:
            print(str(ex))
            assert "file_that_does_not_exist.xml" in str(ex)
            return True

        assert "Expected ResourceException" == False

    # An URL that cannot be downloaded must throw an error with fail_on_error=True
    # Note: Due to load_url retries it takes 20s to complete this test
    def test_fail_on_error_no_url(self):
        try:
            res, md = self.exec_pipeline(
                """
    - load fail_on_error True:
        - http://127.0.0.1/does_not_exist.xml
    - select
    - stats
    """
            )
        except BaseException as ex:
            print(ex)
            assert "does_not_exist.xml" in str(ex)
            return True

        assert "Expected Exception" == False

    # A file with invalid XML must throw an exception with fail_on_error True:
    def test_fail_on_error_invalid_file(self):
        try:
            res, md = self.exec_pipeline(
                f"""
    - load fail_on_error True:
        - {self.datadir}/metadata/test01.xml
        - {self.datadir}/metadata/test02-invalid.xml
    - select
    - stats
"""
            )
        except (MetadataException, ParserException, ResourceException) as ex:
            print(ex)
            return True

        assert "Expected MetadataException or ParserException" == False

    # A directory with a file with invalid metadata must throw an exception with fail_on_error True and filter_invalid False:
    def test_fail_on_error_invalid_dir(self):
        try:
            res, md = self.exec_pipeline(
                f"""
    - load fail_on_error True filter_invalid False:
        - {self.datadir}/metadata/
    - select
    - stats
    """
            )
        except (MetadataException, ParserException, ResourceException) as ex:
            print(ex)
            return True

        assert "Expected MetadataException or ParserException" == False

    # A file with invalid XML must not throw an exception by default (fail_on_error False):
    def test_no_fail_on_error_invalid_file(self):
        res, md = self.exec_pipeline(
            f"""
    - load:
        - {self.datadir}/metadata/test01.xml
        - {self.datadir}/metadata/test02-invalid.xml
    - select
    - stats
    """
        )
        # Test that the test01.xml was loaded
        assert md.lookup('https://idp.example.com/saml2/idp/metadata.php')

    # Loading an xml file with an invalid entity must throw when filter_invalid False and fail_on_error True
    def test_fail_on_error_invalid_entity(self):
        try:
            res, md = self.exec_pipeline(
                f"""
    - load fail_on_error True filter_invalid False:
        - {self.datadir}/metadata/test01.xml
        - {self.datadir}/metadata/test03-invalid.xml
    - select
    - stats
    """
            )
        except (MetadataException, ParserException) as ex:
            print(ex)
            assert ":SCHEMASV:" in str(ex)
            assert "/metadata/test03-invalid.xml" in str(ex)
            return True

        assert "Expected MetadataException or ParserException" == False

    # Test default behaviour. Loading a file with an invalid entity must not raise an exception
    def test_no_fail_on_error_invalid_entity(self):
        res, md = self.exec_pipeline(
            f"""
    - load:
        - {self.datadir}/metadata/test01.xml
        - {self.datadir}/metadata/test03-invalid.xml
    - select
    - stats
    """
        )
        # Test that the test01.xml was loaded
        assert md.lookup('https://idp.example.com/saml2/idp/metadata.php')

    # A directory with a file with invalid metadata must not throw by default:
    def test_no_fail_on_error_invalid_dir(self):
        res, md = self.exec_pipeline(
            f"""
    - load:
        - {self.datadir}/metadata/
    - select
    - stats
    """
        )
        # Test that the test01.xml was loaded
        assert md.lookup('https://idp.example.com/saml2/idp/metadata.php')


class SortTest(PipeLineTest):
    EID1 = "https://idp.aco.net/idp/shibboleth"
    EID2 = "https://idp.example.com/saml2/idp/metadata.php"
    EID3 = "https://sharav.abes.fr/idp/shibboleth"

    @staticmethod
    def _run_sort_test(expected_order, sxp, res, l):
        if sxp is not None:
            # Verify expected warnings for missing sort values
            for e in expected_order:
                try:
                    if not isinstance(e[1], bool):
                        raise TypeError
                    if not e[1]:
                        keygen_fail_str = (
                            f"Sort pipe: unable to sort entity by '{sxp}'. Entity '{e[0]}' has no such value"
                        )
                        try:
                            assert keygen_fail_str in str(l)
                        except AssertionError:
                            print(
                                f"Test failed on expecting missing sort value from: '{e[0]}'.\n"
                                f"Could not find string on the output: '{keygen_fail_str}'.\nOutput was:\n {six.u(l)}"
                            )
                            raise
                except (IndexError, TypeError):
                    print(
                        f"Test failed for: '{''.join(str(e))}' due to 'order_by' xpath "
                        "supplied without proper expectation tuple."
                    )
                    raise

        # Verify order
        from pyff.samlmd import iter_entities

        elts = list(iter_entities(res))
        print("elts: {}".format(elts))
        for i, me in enumerate(expected_order):
            print("{}: {}".format(i, me))
            try:
                assert elts[i].attrib.get("entityID") == me[0]
            except AssertionError:
                print(
                    (
                        f"Test failed on verifying sort position {i:d}.\nExpected: {me[0]}; "
                        f"Found: {elts[i].attrib.get('entityID')} "
                    )
                )
                raise

    # Test sort by entityID only
    def test_sort(self):
        sxp = None
        res, md = self.exec_pipeline(
            f"""
    - load:
        - {self.datadir}/metadata/test01.xml
        - {self.datadir}/metadata/sharav.abes.fr.xml
        - {self.datadir}/simple-pipeline/idp.aco.net.xml
    - select:
        - "!//md:EntityDescriptor[md:IDPSSODescriptor]"
    - sort
    - dump
    - stats
    """
        )

        # tuple format (entityID, has value for 'order_by' xpath)
        expected_order = [(self.EID1,), (self.EID2,), (self.EID3,)]
        self._run_sort_test(expected_order, sxp, res, self.captured_log_text)

    # Test sort entries first by registrationAuthority
    def test_sort_by_ra(self):
        sxp = ".//md:Extensions/mdrpi:RegistrationInfo/@registrationAuthority"
        res, md = self.exec_pipeline(
            f"""
    - load:
        - {self.datadir}/metadata/test01.xml
        - {self.datadir}/metadata/sharav.abes.fr.xml
        - {self.datadir}/simple-pipeline/idp.aco.net.xml
    - select:
        - "!//md:EntityDescriptor[md:IDPSSODescriptor]"
    - sort order_by {sxp}
    - stats
    """
        )

        # tuple format (entityID, has value for 'order_by' xpath)
        expected_order = [(self.EID3, True), (self.EID1, False), (self.EID2, False)]
        self._run_sort_test(expected_order, sxp, res, self.captured_log_text)

    # Test group entries by specific NameIDFormat support
    def test_sort_group(self):
        sxp = ".//md:IDPSSODescriptor/md:NameIDFormat[./text()='urn:mace:shibboleth:1.0:nameIdentifier']"
        res, md = self.exec_pipeline(
            f"""
    - load:
        - {self.datadir}/metadata/test01.xml
        - {self.datadir}/metadata/sharav.abes.fr.xml
        - {self.datadir}/simple-pipeline/idp.aco.net.xml
    - select:
        - "!//md:EntityDescriptor[md:IDPSSODescriptor]"
    - sort order_by {sxp}
    - stats
    """
        )
        # tuple format (entityID, has value for 'order_by' xpath)
        expected_order = [(self.EID1, True), (self.EID3, True), (self.EID2, False)]
        self._run_sort_test(expected_order, sxp, res, self.captured_log_text)


# noinspection PyUnresolvedReferences
class SigningTest(PipeLineTest):
    def test_signing(self):
        self.output = tempfile.NamedTemporaryFile('w').name
        res, md, ctx = self.run_pipeline("signer.fd", self)
        eIDs = [e.get('entityID') for e in md.store]
        assert 'https://idp.aco.net/idp/shibboleth' in eIDs
        assert 'https://skriptenforum.net/shibboleth' in eIDs
        os.unlink(self.output)

    def test_signing_and_validation(self):
        self.output = tempfile.NamedTemporaryFile('w').name
        res_s, md_s, ctx_s = self.run_pipeline("signer.fd", self)
        res_v, md_v, ctx_v = self.run_pipeline("validator.fd", self)

        eIDs = [e.get('entityID') for e in md_v.store]
        assert 'https://idp.aco.net/idp/shibboleth' in eIDs
        assert 'https://skriptenforum.net/shibboleth' in eIDs
        os.unlink(self.output)

    def test_cert_report(self):
        self.output = tempfile.NamedTemporaryFile('w').name
        res, md, ctx = self.run_pipeline("certreport.fd", self)
        eIDs = [e.get('entityID') for e in md.store]
        assert 'https://idp.aco.net/idp/shibboleth' in eIDs
        assert 'https://skriptenforum.net/shibboleth' in eIDs
        with open(self.output, 'r') as fd:
            lines = fd.readline()
            assert len(lines) > 0

    def test_cert_report_swamid(self):
        self.output = tempfile.NamedTemporaryFile('w').name
        res, md, ctx = self.run_pipeline("certreport-swamid.fd", self)
        with open(self.output, 'r') as fd:
            print(fd.read())

    def test_info_and_dump(self):
        try:
            self.exec_pipeline(
                """
- load:
  - http://mds.swamid.se/md/swamid-2.0.xml
- select
- dump
- info
"""
            )
            assert 'https://idp.nordu.net/idp/shibboleth' in self.captured_stdout
        except IOError:
            pass

    def test_end_exit(self):
        with patch.multiple("sys", exit=self.sys_exit):
            try:
                self.exec_pipeline(
                    """
- end:
    code: 22
    message: "slartibartifast"
"""
                )
                assert False
            except IOError:
                pass
            except ExitException as ex:
                assert ex.code == 22
                assert "slartibartifast" in self.captured_stdout

    def test_single_dump(self):
        try:
            self.exec_pipeline(
                """
- dump
"""
            )
            assert '<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"/>' in self.captured_stdout
        except IOError:
            pass

    def test_missing_select(self):
        for stmt in (
            'publish',
            'signcerts',
            'info',
            'sign',
            'store',
            'finalize',
            'xslt',
            'certreport',
            'emit',
            'finalize',
            'first',
            'setattr',
            'stats',
        ):
            try:
                self.exec_pipeline(
                    f"""
- {stmt}
"""
                )
                assert False
            except PipeException:
                pass
            except IOError:
                pass

    def test_first_select_as(self):
        tmpfile = tempfile.NamedTemporaryFile('w').name
        try:
            self.exec_pipeline(
                f"""
- load:
   - file://{self.datadir}/metadata/test01.xml
- select as FOO:
- first
- publish: {tmpfile}
"""
            )
            t1 = parse_xml(resource_filename("metadata/test01.xml", self.datadir))
            assert t1 is not None
            entity_id = 'https://idp.example.com/saml2/idp/metadata.php'
            t2 = parse_xml(tmpfile)
            assert t2 is not None
            assert root(t1).get('entityID') == root(t2).get('entityID')
            assert root(t2).get('entityID') == entity_id
        except PipeException:
            pass
        except IOError:
            pass
        finally:
            try:
                os.unlink(tmpfile)
            except (IOError, OSError):
                pass

    def test_prune(self):
        tmpfile = tempfile.NamedTemporaryFile('w').name
        try:
            self.exec_pipeline(
                f"""
- load:
   - file://{self.datadir}/metadata/test01.xml
- select
- prune:
    - .//{{urn:oasis:names:tc:SAML:metadata:ui}}UIInfo
- publish: {tmpfile}
"""
            )
            t1 = parse_xml(resource_filename("metadata/test01.xml", self.datadir))
            uiinfo = t1.find(".//{urn:oasis:names:tc:SAML:metadata:ui}UIInfo")
            assert uiinfo is not None
            t2 = parse_xml(tmpfile)
            assert t2 is not None
            gone = t2.find(".//{urn:oasis:names:tc:SAML:metadata:ui}UIInfo")
            assert gone is None
        except PipeException:
            pass
        except IOError:
            pass
        finally:
            try:
                os.unlink(tmpfile)
            except:
                pass

    def test_empty_store(self):
        try:
            self.exec_pipeline(
                """
- store
"""
            )
            assert False
        except PipeException:
            pass
        except IOError:
            pass

    def test_empty_store2(self):
        try:
            self.exec_pipeline(
                """
- store:
   directory: /tmp
"""
            )
            assert False
        except PipeException:
            pass
        except IOError:
            pass

    def test_empty_dir_error(self):
        try:
            self.exec_pipeline(
                f"""
- load fail_on_error True:
   - {self.datadir}/empty
"""
            )
        except IOError:
            pass
        assert "no entities found in" in str(self.captured_log_text)

    def test_store_and_retrieve(self):
        tmpdir = tempfile.mkdtemp()
        os.rmdir(tmpdir)  # lets make sure 'store' can recreate it
        try:
            self.exec_pipeline(
                f"""
- load:
   - file://{self.datadir}/metadata/test01.xml
- select
- store:
   directory: {tmpdir}
"""
            )
            t1 = parse_xml(resource_filename("metadata/test01.xml", self.datadir))
            assert t1 is not None
            entity_id = 'https://idp.example.com/saml2/idp/metadata.php'
            sha1id = hash_id(entity_id, prefix=False)
            fn = f"{tmpdir}/{sha1id}.xml"
            assert os.path.exists(fn)
            t2 = parse_xml(fn)
            assert t2 is not None
            assert root(t1).get('entityID') == root(t2).get('entityID')
            assert root(t2).get('entityID') == entity_id
        except IOError:
            pass
        finally:
            shutil.rmtree(tmpdir)

    def test_empty_certreport(self):
        try:
            self.exec_pipeline(
                """
- certreport
"""
            )
            assert False
        except PipeException:
            pass
        except IOError:
            pass

    def test_pick_invalid(self):
        tmpfile = tempfile.NamedTemporaryFile('w').name
        try:
            self.exec_pipeline(
                f"""
- load validate False:
   - {self.datadir}/metadata
- pick:
   - https://idp.example.com/saml2/idp/metadata.php1
- publish: {tmpfile}
"""
            )
            assert False
        except PipeException:
            pass
        except IOError:
            pass
        finally:
            try:
                os.unlink(tmpfile)
            except:
                pass

    def test_blacklist_single_file(self):
        entity = 'https://idp.example.com/saml2/idp/metadata.php'

        # First, load without a filter to ensure the entity is there
        res, md = self.exec_pipeline(
            f"""
- when batch:
    - load:
        - {self.datadir}/metadata/test01.xml
        """
        )
        assert md.lookup(entity)

        # Then, load with a filter and ensure the entity isn't there anymore
        res, md = self.exec_pipeline(
            f"""
- when batch:
    - load:
        - {self.datadir}/metadata/ via blacklist_example
- when blacklist_example:
    - fork merge remove:
        - filter:
            - {entity}
"""
        )
        assert not md.lookup(entity)

    def test_blacklist_directory(self):
        """ Test filter action when loading all metadata in a directory.

        This test has the side effect of testing some resource option inheritance mechanisms.
        """
        entity = 'https://idp.example.com/saml2/idp/metadata.php'

        # First, load without a filter to ensure the entity is there
        res, md = self.exec_pipeline(
            f"""
- when batch:
    - load:
        - {self.datadir}/metadata/test01.xml
        """
        )
        assert md.lookup(entity)

        # Then, load with a filter and ensure the entity isn't there anymore
        res, md = self.exec_pipeline(
            f"""
- when batch:
    - load:
        - {self.datadir}/metadata/ via blacklist_example
- when blacklist_example:
    - fork merge remove:
        - filter:
            - {entity}
"""
        )
        assert not md.lookup(entity)

    def test_bad_namespace(self):
        try:
            res, md = self.exec_pipeline(
                f"""
- when batch:
    - load:
        - {self.datadir}/bad_metadata cleanup bad
- when bad:
    - check_xml_namespaces
"""
            )
        except ValueError:
            pass
        assert "Expected exception from bad namespace in"

    def test_parsecopy_(self):
        entity = 'https://idp.example.com/saml2/idp/metadata.php'
        res, md = self.exec_pipeline(
            f"""
- when batch:
    - load:
        - {self.datadir}/metadata/test01.xml
- map:
     - fork:
       - publish:
"""
        )
        assert "Expected exception from bad namespace in"
        assert md.lookup(entity)

    def test_discojson_sp(self):
        with patch.multiple("sys", exit=self.sys_exit):
            tmpdir = tempfile.mkdtemp()
            os.rmdir(tmpdir)  # lets make sure 'store' can recreate it
            try:
                self.exec_pipeline("""
- load:
   - file://%s/metadata/test02-sp.xml
- select
- discojson_sp
- publish:
    output: %s/disco_sp.json
    raw: true
    update_store: false
""" % (self.datadir, tmpdir))
                fn = "%s/disco_sp.json" % tmpdir
                assert os.path.exists(fn)
                with open(fn, 'r') as f:
                    sp_json = json.load(f)

                assert 'https://example.com.com/shibboleth' in str(sp_json)
                assert len(sp_json) == 2
                example_sp_json = sp_json[0]
                assert 'customer' in example_sp_json['profiles']
                customer_tinfo = example_sp_json['profiles']['customer']
                assert customer_tinfo['entity'][0] == {'entity_id': 'https://example.org/idp.xml', 'include': True}
                assert customer_tinfo['entities'][0] == {'select': 'http://www.swamid.se/', 'match': 'registrationAuthority', 'include': True}
                assert customer_tinfo['fallback_handler'] == {'profile': 'href', 'handler': 'https://www.example.org/about'}

                example_sp_json_2 = sp_json[1]
                assert 'incommon-wayfinder' in example_sp_json_2['profiles']
                tinfo = example_sp_json_2['profiles']['incommon-wayfinder']
                assert tinfo['entities'][0] == {'select': 'https://mdq.incommon.org/entities', 'match': 'md_source', 'include': True}
                assert tinfo['strict']
            except IOError:
                pass
            finally:
                shutil.rmtree(tmpdir)

    def test_discojson_sp_trustinfo_in_attr(self):
        with patch.multiple("sys", exit=self.sys_exit):
            tmpdir = tempfile.mkdtemp()
            os.rmdir(tmpdir)  # lets make sure 'store' can recreate it
            try:
                self.exec_pipeline("""
- load:
   - file://%s/metadata/test-sp-trustinfo-in-attr.xml
- select
- discojson_sp_attr
- publish:
    output: %s/disco_sp_attr.json
    raw: true
    update_store: false
""" % (self.datadir, tmpdir))
                fn = "%s/disco_sp_attr.json" % tmpdir
                assert os.path.exists(fn)
                with open(fn, 'r') as f:
                    sp_json = json.load(f)

                assert 'https://example.com/shibboleth' in str(sp_json)
                example_sp_json = sp_json[0]
                assert 'incommon-wayfinder' in example_sp_json['profiles']
                tinfo = example_sp_json['profiles']['incommon-wayfinder']
                assert tinfo['entities'][0] == {'select': 'https://mdq.incommon.org/entities', 'match': 'md_source', 'include': True}
                assert tinfo['strict']
            except IOError:
                pass
            finally:
                shutil.rmtree(tmpdir)
