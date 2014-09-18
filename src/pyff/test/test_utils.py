from unittest import TestCase
from pyff.constants import NS
from pyff.utils import resource_filename, parse_xml, find_entity, root
import os
import copy

from ..merge_strategies import replace_existing, remove


class TestMetadata(TestCase):

    def setUp(self):
        self.datadir = resource_filename('metadata', 'test/data')
        self.xml_source1 = os.path.join(self.datadir, 'test01.xml')
        self.xml_source2 = os.path.join(self.datadir, 'swamid-2.0-test.xml')
        self.t1 = parse_xml(self.xml_source1)
        self.t2 = parse_xml(self.xml_source2)

    def test_merge_replace_bad(self):
        try:
            replace_existing(self.t1, self.t1)
            assert False
        except AttributeError:
            pass

    def test_merge_remove_bad(self):
        try:
            remove(self.t1, self.t1)
            assert False
        except AttributeError:
            pass

    def test_replace_ndn(self):
        idp = find_entity(root(self.t2), 'https://idp.nordu.net/idp/shibboleth')
        assert (idp is not None)
        idp2 = copy.deepcopy(idp)
        assert idp2 is not None
        for o in idp2.findall(".//{%s}OrganizationName" % NS['md']):
            o.text = "FOO"
        idp2.set('ID', 'kaka4711')
        replace_existing(idp, idp2)
        idp3 = find_entity(root(self.t2), 'kaka4711', attr='ID')
        assert (idp3 is not None)
        for o in idp2.findall(".//{%s}OrganizationName" % NS['md']):
            assert (o.text == "FOO")
        remove(idp3, None)
        idp = find_entity(root(self.t2), 'kaka4711', attr='ID')
        assert (idp3 is not None)