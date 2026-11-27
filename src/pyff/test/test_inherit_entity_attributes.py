"""
The ``inherit_entity_attributes`` source option (#285).

Entity attributes in md:EntitiesDescriptor/md:Extensions are bound to every md:EntityDescriptor in
that group. With the option on, they are merged into each entity as the source is parsed.
"""

import logging
import os
import shutil
import tempfile
from io import BytesIO
from unittest import TestCase

from pyff.constants import NS
from pyff.samlmd import inherit_entity_attributes, iter_entities
from pyff.test.test_pipeline import PipeLineTest
from pyff.utils import dumptree, parse_xml, root

CATEGORY = "http://macedir.org/entity-category-support"
RS = "http://refeds.org/category/research-and-scholarship"
OWN = "http://own.example.org/category"
NF_URI = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
NF_BASIC = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"

HEAD = (
    '<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" '
    'xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute" '
    'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="{name}">'
)


def _attribute(name, *values, nf=NF_URI):
    vals = "".join(f"<saml:AttributeValue>{v}</saml:AttributeValue>" for v in values)
    return f'<saml:Attribute Name="{name}" NameFormat="{nf}">{vals}</saml:Attribute>'


def _extensions(*attributes):
    return f"<md:Extensions><mdattr:EntityAttributes>{''.join(attributes)}</mdattr:EntityAttributes></md:Extensions>"


def _idp(entity_id, *attributes):
    ext = _extensions(*attributes) if attributes else ""
    return (
        f'<md:EntityDescriptor entityID="{entity_id}">{ext}'
        '<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
        '<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" '
        f'Location="{entity_id}/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>'
    )


def _sp(entity_id, *attributes):
    ext = _extensions(*attributes) if attributes else ""
    return (
        f'<md:EntityDescriptor entityID="{entity_id}">{ext}'
        '<md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
        '<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
        f'Location="{entity_id}/acs" index="1"/></md:SPSSODescriptor></md:EntityDescriptor>'
    )


def _group(name, group_attributes, *members):
    ext = _extensions(*group_attributes) if group_attributes else ""
    return f"{HEAD.format(name=name)}{ext}{''.join(members)}</md:EntitiesDescriptor>"


def _tree(xml):
    return root(parse_xml(BytesIO(xml.encode("utf-8"))))


def _attributes(entity):
    """{(Name, NameFormat): [[values of the first such attribute element], [values of the second], ...]}"""
    found = {}
    for a in entity.iter(f"{{{NS['saml']}}}Attribute"):
        values = [v.text for v in a.findall(f"{{{NS['saml']}}}AttributeValue")]
        found.setdefault((a.get("Name"), a.get("NameFormat")), []).append(values)
    return found


def _by_id(t):
    return {e.get("entityID"): e for e in iter_entities(t)}


class InheritFixtures:
    def setUp(self):
        super().setUp()
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)

    def write(self, name, xml):
        path = os.path.join(self.dir, name)
        with open(path, "w") as fh:
            fh.write(xml)
        return path


class TestInheritFunction(TestCase):
    def test_entity_without_attributes_gets_the_groups(self):
        t = _tree(_group("g", [_attribute(CATEGORY, RS)], _sp("https://sp")))
        inherit_entity_attributes(t)
        assert _attributes(_by_id(t)["https://sp"]) == {(CATEGORY, NF_URI): [[RS]]}

    def test_values_are_merged_into_one_attribute_own_values_first(self):
        t = _tree(_group("g", [_attribute(CATEGORY, RS)], _idp("https://idp", _attribute(CATEGORY, OWN))))
        inherit_entity_attributes(t)
        assert _attributes(_by_id(t)["https://idp"]) == {(CATEGORY, NF_URI): [[OWN, RS]]}

    def test_value_already_present_is_not_duplicated(self):
        t = _tree(_group("g", [_attribute(CATEGORY, RS)], _idp("https://idp", _attribute(CATEGORY, RS, OWN))))
        inherit_entity_attributes(t)
        assert _attributes(_by_id(t)["https://idp"]) == {(CATEGORY, NF_URI): [[RS, OWN]]}

    def test_running_twice_changes_nothing(self):
        t = _tree(_group("g", [_attribute(CATEGORY, RS)], _idp("https://idp", _attribute(CATEGORY, OWN))))
        inherit_entity_attributes(t)
        inherit_entity_attributes(t)
        assert _attributes(_by_id(t)["https://idp"]) == {(CATEGORY, NF_URI): [[OWN, RS]]}

    def test_other_name_format_is_a_different_attribute(self):
        t = _tree(_group("g", [_attribute(CATEGORY, RS)], _idp("https://idp", _attribute(CATEGORY, OWN, nf=NF_BASIC))))
        inherit_entity_attributes(t)
        assert _attributes(_by_id(t)["https://idp"]) == {(CATEGORY, NF_BASIC): [[OWN]], (CATEGORY, NF_URI): [[RS]]}

    def test_every_enclosing_group_applies(self):
        inner = _group("inner", [_attribute("urn:y", "Y")], _idp("https://b"))
        outer = _group("outer", [_attribute("urn:x", "X")], _idp("https://a"), inner)
        t = _tree(outer)
        inherit_entity_attributes(t)
        got = {k: _attributes(v) for k, v in _by_id(t).items()}
        assert got["https://a"] == {("urn:x", NF_URI): [["X"]]}
        assert got["https://b"] == {("urn:x", NF_URI): [["X"]], ("urn:y", NF_URI): [["Y"]]}

    def test_typed_value_keeps_the_namespaces_its_type_needs(self):
        typed = (
            '<saml:Attribute Name="urn:t" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">'
            '<saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" '
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">v</saml:AttributeValue>'
            "</saml:Attribute>"
        )
        t = _tree(_group("g", [typed], _sp("https://sp")))
        inherit_entity_attributes(t)
        out = dumptree(_by_id(t)["https://sp"], xml_declaration=False).decode()
        assert 'xsi:type="xs:string"' in out
        assert 'xmlns:xs="http://www.w3.org/2001/XMLSchema"' in out  # or the type would not resolve

    def test_plain_value_adds_no_namespace_declarations(self):
        t = _tree(_group("g", [_attribute(CATEGORY, RS)], _sp("https://sp")))
        inherit_entity_attributes(t)
        out = dumptree(_by_id(t)["https://sp"], xml_declaration=False).decode()
        assert "ns0:" not in out
        assert f"<saml:AttributeValue>{RS}</saml:AttributeValue>" in out

    def test_group_without_attributes_changes_nothing(self):
        t = _tree(_group("g", [], _sp("https://sp")))
        assert inherit_entity_attributes(t) == 0
        assert _attributes(_by_id(t)["https://sp"]) == {}

    def test_assertions_in_a_group_are_ignored(self):
        assertion = '<saml:Assertion Version="2.0" ID="x" IssueInstant="2020-01-01T00:00:00Z"/>'
        t = _tree(_group("g", [assertion, _attribute(CATEGORY, RS)], _sp("https://sp")))
        inherit_entity_attributes(t)
        sp = _by_id(t)["https://sp"]
        assert _attributes(sp) == {(CATEGORY, NF_URI): [[RS]]}
        assert sp.find(f".//{{{NS['saml']}}}Assertion") is None

    def test_extensions_go_after_an_enveloped_signature(self):
        sig = '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/>'
        sp = _sp("https://sp").replace('entityID="https://sp">', f'entityID="https://sp">{sig}', 1)
        t = _tree(_group("g", [_attribute(CATEGORY, RS)], sp))
        inherit_entity_attributes(t)
        tags = [c.tag for c in _by_id(t)["https://sp"]]
        assert tags[0] == "{http://www.w3.org/2000/09/xmldsig#}Signature"
        assert tags[1] == f"{{{NS['md']}}}Extensions"

    def test_the_groups_own_attributes_are_not_modified(self):
        t = _tree(_group("g", [_attribute(CATEGORY, RS)], _idp("https://idp", _attribute(CATEGORY, OWN))))
        inherit_entity_attributes(t)
        group_ext = t.find(f"{{{NS['md']}}}Extensions")
        values = [v.text for v in group_ext.iter(f"{{{NS['saml']}}}AttributeValue")]
        assert values == [RS]

    def test_returns_number_of_values_added(self):
        t = _tree(
            _group("g", [_attribute(CATEGORY, RS)], _sp("https://a"), _idp("https://b", _attribute(CATEGORY, RS)))
        )
        assert inherit_entity_attributes(t) == 1  # b already has it


class TestInheritInPipeline(InheritFixtures, PipeLineTest):
    def _entities(self, res):
        return {k: _attributes(v) for k, v in _by_id(res).items()}

    def test_off_by_default(self):
        """The reporter's case: nothing is inherited unless the source asks for it."""
        path = self.write(
            "a.xml",
            _group("a", [_attribute(CATEGORY, RS)], _sp("https://sp"), _idp("https://idp", _attribute(CATEGORY, OWN))),
        )
        res, _md = self.exec_pipeline(f"- load:\n    - {path}\n- select\n")
        got = self._entities(res)
        assert got["https://sp"] == {}
        assert got["https://idp"] == {(CATEGORY, NF_URI): [[OWN]]}

    def test_on_for_the_source(self):
        path = self.write(
            "a.xml",
            _group("a", [_attribute(CATEGORY, RS)], _sp("https://sp"), _idp("https://idp", _attribute(CATEGORY, OWN))),
        )
        res, _md = self.exec_pipeline(f"- load:\n    - {path} inherit_entity_attributes\n- select\n")
        got = self._entities(res)
        assert got["https://sp"] == {(CATEGORY, NF_URI): [[RS]]}
        assert got["https://idp"] == {(CATEGORY, NF_URI): [[OWN, RS]]}

    def test_only_the_flagged_source(self):
        a = self.write("a.xml", _group("a", [_attribute("urn:a", "A")], _sp("https://a-sp")))
        b = self.write("b.xml", _group("b", [_attribute("urn:b", "B")], _sp("https://b-sp")))
        res, _md = self.exec_pipeline(f"- load:\n    - {a} inherit_entity_attributes\n    - {b}\n- select\n")
        got = self._entities(res)
        assert got["https://a-sp"] == {("urn:a", NF_URI): [["A"]]}
        assert got["https://b-sp"] == {}

    def test_attributes_do_not_cross_between_flagged_sources(self):
        a = self.write("a.xml", _group("a", [_attribute("urn:a", "A")], _sp("https://a-sp")))
        b = self.write("b.xml", _group("b", [_attribute("urn:b", "B")], _sp("https://b-sp")))
        res, _md = self.exec_pipeline(
            f"- load:\n    - {a} inherit_entity_attributes\n    - {b} inherit_entity_attributes\n- select\n"
        )
        got = self._entities(res)
        assert got["https://a-sp"] == {("urn:a", NF_URI): [["A"]]}
        assert got["https://b-sp"] == {("urn:b", NF_URI): [["B"]]}

    def test_flag_works_with_other_keywords(self):
        a = self.write("a.xml", _group("a", [_attribute("urn:a", "A")], _sp("https://a-sp")))
        res, _md = self.exec_pipeline(f"- load:\n    - {a} as AAA inherit_entity_attributes\n- select: AAA\n")
        assert self._entities(res)["https://a-sp"] == {("urn:a", NF_URI): [["A"]]}

    def test_directory_source(self):
        self.write("one.xml", _group("one", [_attribute("urn:one", "1")], _sp("https://one")))
        self.write("two.xml", _group("two", [_attribute("urn:two", "2")], _sp("https://two")))
        res, _md = self.exec_pipeline(f"- load:\n    - {self.dir} inherit_entity_attributes\n- select\n")
        got = self._entities(res)
        assert got["https://one"] == {("urn:one", NF_URI): [["1"]]}
        assert got["https://two"] == {("urn:two", NF_URI): [["2"]]}

    def test_nested_groups(self):
        inner = _group("inner", [_attribute("urn:y", "Y")], _idp("https://b"))
        path = self.write("n.xml", _group("outer", [_attribute("urn:x", "X")], _idp("https://a"), inner))
        res, _md = self.exec_pipeline(f"- load:\n    - {path} inherit_entity_attributes\n- select\n")
        got = self._entities(res)
        assert got["https://a"] == {("urn:x", NF_URI): [["X"]]}
        assert got["https://b"] == {("urn:x", NF_URI): [["X"]], ("urn:y", NF_URI): [["Y"]]}

    def test_result_is_still_schema_valid_and_signable_input(self):
        path = self.write("a.xml", _group("a", [_attribute(CATEGORY, RS)], _sp("https://sp")))
        res, _md = self.exec_pipeline(
            f"- load fail_on_error True:\n    - {path} inherit_entity_attributes\n- select\n- validate\n"
        )
        assert len(list(iter_entities(res))) == 1

    def test_logs_how_much_was_added(self):
        path = self.write("a.xml", _group("a", [_attribute(CATEGORY, RS)], _sp("https://x"), _sp("https://y")))
        with self._caplog.at_level(logging.INFO):
            self.exec_pipeline(f"- load:\n    - {path} inherit_entity_attributes\n- select\n")
        assert "inherit_entity_attributes" in self.captured_log_text
        assert "2 entities" in self.captured_log_text
