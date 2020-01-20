import shutil
import sys
import tempfile
import os
import yaml
from mako.lookup import TemplateLookup
from mock import patch
from pyff.repo import MDRepository
from pyff.exceptions import MetadataException
from pyff.pipes import plumbing, Plumbing, PipeException
from pyff.test import ExitException
from pyff.test import SignerTestCase
from pyff.utils import hash_id, parse_xml, resource_filename, root
from pyff.parse import ParserException
from pyff.resource import ResourceException
import six
from pyff.store import make_store_instance

# don't remove this - it only appears unused to static analysis
from pyff import builtins

__author__ = 'leifj'


class PipeLineTest(SignerTestCase):
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
        res = Plumbing(p, pid="test").process(md, state={'batch': True, 'stats': {}})
        return res, md

    @classmethod
    def setUpClass(cls):
        SignerTestCase.setUpClass()

    def setUp(self):
        SignerTestCase.setUpClass()
        self.templates = TemplateLookup(directories=[os.path.join(self.datadir, 'simple-pipeline')])


class StreamCapturing(object):
    def __init__(self, stream):
        self.captured = []
        self.stream = stream

    def __getattr__(self, attr):
        return getattr(self.stream, attr)

    def write(self, data):
        self.captured.append(data)
        self.stream.write(data)


class ParseTest(PipeLineTest):
    def parse_test(self):
        self.output = tempfile.NamedTemporaryFile('w').name
        with patch.multiple("sys", exit=self.sys_exit, stdout=StreamCapturing(sys.stdout),
                            stderr=StreamCapturing(sys.stderr)):
            from testfixtures import LogCapture
            with LogCapture() as l:
                res, md = self.exec_pipeline("""
- load:
    - %s/metadata
- select
- stats
""" % self.datadir)
                print(sys.stdout.captured)
                print(sys.stderr.captured)
                eIDs = [e.get('entityID') for e in md.store]
                assert ('https://idp.example.com/saml2/idp/metadata.php1' not in eIDs)
                assert ('https://idp.example.com/saml2/idp/metadata.php' in eIDs)
                assert ("removing 'https://idp.example.com/saml2/idp/metadata.php1': schema validation failed" in str(l))


# To run all LoadErrorTests: ./setup.py test -s pyff.test.test_pipeline.LoadErrorTest
# To run individual test: ./setup.py test -s pyff.test.test_pipeline.LoadErrorTest.test_fail_on_error_no_file
class LoadErrorTest(PipeLineTest):
    # A File that does not exist must throw an error with fail_on_error=True
    def test_fail_on_error_no_file(self):
        self.output = tempfile.NamedTemporaryFile('w').name
        with patch.multiple("sys", exit=self.sys_exit, stdout=StreamCapturing(sys.stdout),
                            stderr=StreamCapturing(sys.stderr)):
            from testfixtures import LogCapture
            with LogCapture() as l:
                try:
                    res, md = self.exec_pipeline("""
    - load fail_on_error True:
        - %s/file_that_does_not_exist.xml
    - select
    - stats
    """ % (self.datadir))
                except ResourceException as ex:
                    print("----\n",ex,"\n++++")
                    assert ("file_that_does_not_exist.xml" in str(ex))
                    return True
                finally:
                    if os.path.isfile(self.output):
                        os.unlink(self.output)
                    print(sys.stdout.captured)
                    print(sys.stderr.captured)

        assert "Expected PipeException or ResourceException" == False

    # A File that does not exist must throw an error with fail_on_error=True
    def test_fail_on_error_no_file_url(self):
        self.output = tempfile.NamedTemporaryFile('w').name
        with patch.multiple("sys", exit=self.sys_exit, stdout=StreamCapturing(sys.stdout),
                            stderr=StreamCapturing(sys.stderr)):
            from testfixtures import LogCapture
            with LogCapture() as l:
                try:
                    res, md = self.exec_pipeline("""
    - load fail_on_error True:
        - file://%s/file_that_does_not_exist.xml
    - select
    - stats
    """ % (self.datadir))
                except ResourceException as ex:
                    print(str(ex))
                    assert ("file_that_does_not_exist.xml" in str(ex))
                    return True
                finally:
                    if os.path.isfile(self.output):
                        os.unlink(self.output)
                    print(sys.stdout.captured)
                    print(sys.stderr.captured)

        assert "Expected ResourceException" == False

    # An URL that cannot be downloaded must throw an error with fail_on_error=True
    # Note: Due to load_url retries it takes 20s to complete this test
    def test_fail_on_error_no_url(self):
        self.output = tempfile.NamedTemporaryFile('w').name
        with patch.multiple("sys", exit=self.sys_exit, stdout=StreamCapturing(sys.stdout),
                            stderr=StreamCapturing(sys.stderr)):
            from testfixtures import LogCapture
            with LogCapture() as l:
                try:
                    res, md = self.exec_pipeline("""
    - load fail_on_error True:
        - http://127.0.0.1/does_not_exist.xml
    - select
    - stats
    """)
                except BaseException as ex:
                    print(ex)
                    assert ("does_not_exist.xml" in str(ex))
                    return True
                finally:
                    if os.path.isfile(self.output):
                        os.unlink(self.output)
                    print(sys.stdout.captured)
                    print(sys.stderr.captured)

        assert "Expected Exception" == False

    # A file with invalid XML must throw an exception with fail_on_error True:
    def test_fail_on_error_invalid_file(self):
        self.output = tempfile.NamedTemporaryFile('w').name
        with patch.multiple("sys", exit=self.sys_exit, stdout=StreamCapturing(sys.stdout),
                            stderr=StreamCapturing(sys.stderr)):
            from testfixtures import LogCapture
            with LogCapture() as l:
                try:
                    res, md = self.exec_pipeline("""
    - load fail_on_error True:
        - %s/metadata/test01.xml
        - %s/metadata/test02-invalid.xml
    - select
    - stats
    """ % (self.datadir, self.datadir))
                except (MetadataException, ParserException, ResourceException) as ex:
                    print(ex)
                    return True
                finally:
                    if os.path.isfile(self.output):
                        os.unlink(self.output)
                    print(sys.stdout.captured)
                    print(sys.stderr.captured)

        assert "Expected MetadataException or ParserException" == False

    # A directory with a file with invalid metadata must throw an exception with fail_on_error True and filter_invalid False:
    def test_fail_on_error_invalid_dir(self):
        self.output = tempfile.NamedTemporaryFile('w').name
        with patch.multiple("sys", exit=self.sys_exit, stdout=StreamCapturing(sys.stdout),
                            stderr=StreamCapturing(sys.stderr)):
            from testfixtures import LogCapture
            with LogCapture() as l:
                try:
                    res, md = self.exec_pipeline("""
    - load fail_on_error True filter_invalid False:
        - %s/metadata/
    - select
    - stats
    """ % (self.datadir))
                except (MetadataException, ParserException, ResourceException) as ex:
                    print(ex)
                    return True
                finally:
                    if os.path.isfile(self.output):
                        os.unlink(self.output)
                    print(sys.stdout.captured)
                    print(sys.stderr.captured)

        assert "Expected MetadataException or ParserException" == False

    # A file with invalid XML must not throw an exception by default (fail_on_error False):
    def test_no_fail_on_error_invalid_file(self):
        self.output = tempfile.NamedTemporaryFile('w').name
        with patch.multiple("sys", exit=self.sys_exit, stdout=StreamCapturing(sys.stdout),
                            stderr=StreamCapturing(sys.stderr)):
            from testfixtures import LogCapture
            with LogCapture() as l:
                res, md = self.exec_pipeline("""
    - load:
        - %s/metadata/test01.xml
        - %s/metadata/test02-invalid.xml
    - select
    - stats
    """ % (self.datadir, self.datadir))
                print(sys.stdout.captured)
                print(sys.stderr.captured)
                if os.path.isfile(self.output):
                    os.unlink(self.output)

    # Loading an xml file with an invalid entity must throw when filter_invalid False and fail_on_error True
    def test_fail_on_error_invalid_entity(self):
        self.output = tempfile.NamedTemporaryFile('w').name
        with patch.multiple("sys", exit=self.sys_exit, stdout=StreamCapturing(sys.stdout),
                            stderr=StreamCapturing(sys.stderr)):
            from testfixtures import LogCapture
            with LogCapture() as l:
                try:
                    res, md = self.exec_pipeline("""
    - load fail_on_error True filter_invalid False:
        - %s/metadata/test01.xml
        - %s/metadata/test03-invalid.xml
    - select
    - stats
    """ % (self.datadir, self.datadir))
                except (MetadataException, ParserException) as ex:
                    print(ex)
                    assert (":SCHEMASV:" in str(ex))
                    assert ("/metadata/test03-invalid.xml" in str(ex))
                    return True
                finally:
                    if os.path.isfile(self.output):
                        os.unlink(self.output)
                    print(sys.stdout.captured)
                    print(sys.stderr.captured)

    # Test default behaviour. Loading a file with an invalid entity must not raise an exception
    def test_no_fail_on_error_invalid_entity(self):
        self.output = tempfile.NamedTemporaryFile('w').name
        with patch.multiple("sys", exit=self.sys_exit, stdout=StreamCapturing(sys.stdout),
                            stderr=StreamCapturing(sys.stderr)):
            from testfixtures import LogCapture
            with LogCapture() as l:
                res, md = self.exec_pipeline("""
    - load:
        - %s/metadata/test01.xml
        - %s/metadata/test03-invalid.xml
    - select
    - stats
    """ % (self.datadir, self.datadir))
                print(sys.stdout.captured)
                print(sys.stderr.captured)
                if os.path.isfile(self.output):
                    os.unlink(self.output)

    # A directory with a file with invalid metadata must not throw by default:
    def test_no_fail_on_error_invalid_dir(self):
        self.output = tempfile.NamedTemporaryFile('w').name
        with patch.multiple("sys", exit=self.sys_exit, stdout=StreamCapturing(sys.stdout),
                            stderr=StreamCapturing(sys.stderr)):
            from testfixtures import LogCapture
            with LogCapture() as l:
                res, md = self.exec_pipeline("""
    - load:
        - %s/metadata/
    - select
    - stats
    """ % (self.datadir))
                if os.path.isfile(self.output):
                    os.unlink(self.output)
                print(sys.stdout.captured)
                print(sys.stderr.captured)


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
                        keygen_fail_str = ("Sort pipe: unable to sort entity by '%s'. "
                                           "Entity '%s' has no such value" % (sxp, e[0]))
                        try:
                            assert (keygen_fail_str in str(l))
                        except AssertionError:
                            print("Test failed on expecting missing sort value from: '%s'.\nCould not find string "
                                  "on the output: '%s'.\nOutput was:\n %s" % (e[0], keygen_fail_str,six.u(l)))
                            raise
                except (IndexError, TypeError):
                    print("Test failed  for: '%s' due to 'order_by' xpath supplied without proper expectation tuple." %
                          "".join(str(e)))
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
                print(("Test failed on verifying sort position %i.\nExpected: %s; Found: %s " %
                       (i, me[0], elts[i].attrib.get("entityID"))))
                raise

    # Test sort by entityID only
    def test_sort(self):
        sxp = None
        self.output = tempfile.NamedTemporaryFile('w').name
        with patch.multiple("sys", exit=self.sys_exit, stdout=StreamCapturing(sys.stdout),
                            stderr=StreamCapturing(sys.stderr)):
            from testfixtures import LogCapture
            with LogCapture() as l:
                res, md = self.exec_pipeline("""
    - load:
        - %s/metadata/test01.xml
        - %s/metadata/sharav.abes.fr.xml
        - %s/simple-pipeline/idp.aco.net.xml
    - select:
        - "!//md:EntityDescriptor[md:IDPSSODescriptor]"
    - sort
    - dump
    - stats
    """ % (self.datadir, self.datadir, self.datadir))
            print(sys.stdout.captured)
            print(sys.stderr.captured)

            # tuple format (entityID, has value for 'order_by' xpath)
            expected_order = [(self.EID1, ), (self.EID2, ), (self.EID3, )]
            self._run_sort_test(expected_order, sxp, res, l)

    # Test sort entries first by registrationAuthority
    def test_sort_by_ra(self):
        sxp = ".//md:Extensions/mdrpi:RegistrationInfo/@registrationAuthority"
        self.output = tempfile.NamedTemporaryFile('w').name
        with patch.multiple("sys", exit=self.sys_exit, stdout=StreamCapturing(sys.stdout),
                            stderr=StreamCapturing(sys.stderr)):
            from testfixtures import LogCapture
            with LogCapture() as l:
                res, md = self.exec_pipeline("""
    - load:
        - %s/metadata/test01.xml
        - %s/metadata/sharav.abes.fr.xml
        - %s/simple-pipeline/idp.aco.net.xml
    - select:
        - "!//md:EntityDescriptor[md:IDPSSODescriptor]"
    - sort order_by %s
    - stats
    """ % (self.datadir, self.datadir, self.datadir, sxp))
            #print(l)

            # tuple format (entityID, has value for 'order_by' xpath)
            expected_order = [(self.EID3, True), (self.EID1, False), (self.EID2, False)]
            self._run_sort_test(expected_order, sxp, res, l)

    # Test group entries by specific NameIDFormat support
    def test_sort_group(self):
        sxp = ".//md:IDPSSODescriptor/md:NameIDFormat[./text()='urn:mace:shibboleth:1.0:nameIdentifier']"
        self.output = tempfile.NamedTemporaryFile('w').name
        with patch.multiple("sys", exit=self.sys_exit, stdout=StreamCapturing(sys.stdout),
                            stderr=StreamCapturing(sys.stderr)):
            from testfixtures import LogCapture
            with LogCapture() as l:
                res, md = self.exec_pipeline("""
    - load:
        - %s/metadata/test01.xml
        - %s/metadata/sharav.abes.fr.xml
        - %s/simple-pipeline/idp.aco.net.xml
    - select:
        - "!//md:EntityDescriptor[md:IDPSSODescriptor]"
    - sort order_by %s
    - stats
    """ % (self.datadir, self.datadir, self.datadir, sxp))
            print(sys.stdout.captured)
            print(sys.stderr.captured)

            # tuple format (entityID, has value for 'order_by' xpath)
            expected_order = [(self.EID1, True), (self.EID3, True), (self.EID2, False)]
            self._run_sort_test(expected_order, sxp, res, l)


# noinspection PyUnresolvedReferences
class SigningTest(PipeLineTest):

    def test_signing(self):
        self.output = tempfile.NamedTemporaryFile('w').name
        res, md, ctx = self.run_pipeline("signer.fd", self)
        eIDs = [e.get('entityID') for e in md.store]
        assert ('https://idp.aco.net/idp/shibboleth' in eIDs)
        assert ('https://skriptenforum.net/shibboleth' in eIDs)
        os.unlink(self.output)

    def test_signing_and_validation(self):
        self.output = tempfile.NamedTemporaryFile('w').name
        res_s, md_s, ctx_s = self.run_pipeline("signer.fd", self)
        res_v, md_v, ctx_v = self.run_pipeline("validator.fd", self)

        eIDs = [e.get('entityID') for e in md_v.store]
        assert ('https://idp.aco.net/idp/shibboleth' in eIDs)
        assert ('https://skriptenforum.net/shibboleth' in eIDs)
        os.unlink(self.output)

    def test_cert_report(self):
        self.output = tempfile.NamedTemporaryFile('w').name
        res, md, ctx = self.run_pipeline("certreport.fd", self)
        eIDs = [e.get('entityID') for e in md.store]
        assert ('https://idp.aco.net/idp/shibboleth' in eIDs)
        assert ('https://skriptenforum.net/shibboleth' in eIDs)
        with open(self.output, 'r') as fd:
            lines = fd.readline()
            assert (len(lines) > 0)

    def test_cert_report_swamid(self):
        self.output = tempfile.NamedTemporaryFile('w').name
        res, md, ctx = self.run_pipeline("certreport-swamid.fd", self)
        with open(self.output, 'r') as fd:
            print(fd.read())

    def test_info_and_dump(self):
        with patch("sys.stdout", StreamCapturing(sys.stdout)) as ctx:
            try:
                self.exec_pipeline("""
- load:
  - http://mds.swamid.se/md/swamid-2.0.xml
- select
- dump
- info
""")
                assert ('https://idp.nordu.net/idp/shibboleth' in sys.stdout.captured)
            except IOError:
                pass

    def test_end_exit(self):
        with patch.multiple("sys", exit=self.sys_exit, stdout=StreamCapturing(sys.stdout)):
            try:
                self.exec_pipeline("""
- end:
    code: 22
    message: "slartibartifast"
""")
                assert False
            except IOError:
                pass
            except ExitException as ex:
                assert ex.code == 22
                assert "slartibartifast" in "".join(sys.stdout.captured)

    def test_single_dump(self):
        with patch.multiple("sys", exit=self.sys_exit, stdout=StreamCapturing(sys.stdout)):
            try:
                self.exec_pipeline("""
- dump
""")
                assert '<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"/>' \
                       in "".join(sys.stdout.captured)
            except IOError:
                pass

    def test_missing_select(self):
        for stmt in ('publish', 'signcerts', 'info', 'sign', 'store', 'finalize',
                     'xslt', 'certreport', 'emit', 'finalize', 'first', 'setattr', 'stats'):
            with patch.multiple("sys", exit=self.sys_exit, stdout=StreamCapturing(sys.stdout)):
                try:
                    self.exec_pipeline("""
- %s
""" % stmt)
                    assert False
                except PipeException:
                    pass
                except IOError:
                    pass

    def test_first_select_as(self):
        with patch.multiple("sys", exit=self.sys_exit, stdout=StreamCapturing(sys.stdout)):
            tmpfile = tempfile.NamedTemporaryFile('w').name
            try:
                self.exec_pipeline("""
- load:
   - file://%s/metadata/test01.xml
- select as FOO:
- first
- publish: %s
""" % (self.datadir, tmpfile))
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
        with patch.multiple("sys", exit=self.sys_exit, stdout=StreamCapturing(sys.stdout)):
            tmpfile = tempfile.NamedTemporaryFile('w').name
            try:
                self.exec_pipeline("""
- load:
   - file://%s/metadata/test01.xml
- select
- prune:
    - .//{urn:oasis:names:tc:SAML:metadata:ui}UIInfo
- publish: %s
""" % (self.datadir, tmpfile))
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
        with patch.multiple("sys", exit=self.sys_exit, stdout=StreamCapturing(sys.stdout)):
            try:
                self.exec_pipeline("""
- store
""")
                assert False
            except PipeException:
                pass
            except IOError:
                pass

    def test_empty_store2(self):
        with patch.multiple("sys", exit=self.sys_exit, stdout=StreamCapturing(sys.stdout)):
            try:
                self.exec_pipeline("""
- store:
   directory: /tmp
""")
                assert False
            except PipeException:
                pass
            except IOError:
                pass

    def test_empty_dir_error(self):
        with patch.multiple("sys", exit=self.sys_exit, stdout=StreamCapturing(sys.stdout)):
            from testfixtures import LogCapture
            with LogCapture() as l:
                try:
                    self.exec_pipeline("""
- load fail_on_error True:
   - %s/empty
""" % self.datadir)
                except IOError:
                    pass
                assert "no entities found in" in str(l)

    def test_store_and_retrieve(self):
        with patch.multiple("sys", exit=self.sys_exit, stdout=StreamCapturing(sys.stdout)):
            tmpdir = tempfile.mkdtemp()
            os.rmdir(tmpdir)  # lets make sure 'store' can recreate it
            try:
                self.exec_pipeline("""
- load:
   - file://%s/metadata/test01.xml
- select
- store:
   directory: %s
""" % (self.datadir, tmpdir))
                t1 = parse_xml(resource_filename("metadata/test01.xml", self.datadir))
                assert t1 is not None
                entity_id = 'https://idp.example.com/saml2/idp/metadata.php'
                sha1id = hash_id(entity_id, prefix=False)
                fn = "%s/%s.xml" % (tmpdir, sha1id)
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
        with patch.multiple("sys", exit=self.sys_exit, stdout=StreamCapturing(sys.stdout)):
            try:
                self.exec_pipeline("""
- certreport
""")
                assert False
            except PipeException:
                pass
            except IOError:
                pass

    def test_pick_invalid(self):
        with patch.multiple("sys", exit=self.sys_exit, stdout=StreamCapturing(sys.stdout)):
            tmpfile = tempfile.NamedTemporaryFile('w').name
            try:
                self.exec_pipeline("""
- load validate False:
   - %s/metadata
- pick:
   - https://idp.example.com/saml2/idp/metadata.php1
- publish: %s
""" % (self.datadir, tmpfile))
                assert False
            except PipeException as ex:
                print("".join(sys.stdout.captured))
                print(str(ex))
                pass
            except IOError:
                pass
            finally:
                try:
                    os.unlink(tmpfile)
                except:
                    pass

    def test_blacklist(self):
        with patch.multiple("sys", exit=self.sys_exit, stdout=StreamCapturing(sys.stdout)):
            tmpfile = tempfile.NamedTemporaryFile('w').name
            try:
                res, md = self.exec_pipeline("""
- when batch:
    - load:
        - %s/metadata via blacklist_example
- when blacklist_example:
    - fork merge remove:
        - filter:
            - https://idp.example.com/saml2/idp/metadata.php
""" % self.datadir)
            except IOError:
                pass
            print(md.lookup('https://idp.example.com/saml2/idp/metadata.php'))
            assert (not md.lookup('https://idp.example.com/saml2/idp/metadata.php'))

    def test_bad_namespace(self):
        with patch.multiple("sys", exit=self.sys_exit, stdout=StreamCapturing(sys.stdout)):
            tmpfile = tempfile.NamedTemporaryFile('w').name
            try:
                res, md = self.exec_pipeline("""
- when batch:
    - load:
        - %s/bad_metadata cleanup bad
- when bad:
    - check_xml_namespaces
""" % self.datadir)
            except ValueError:
                pass
            assert("Expected exception from bad namespace in")
