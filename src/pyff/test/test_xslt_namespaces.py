from unittest import TestCase

from pyuppsala import etree

XSI = "http://www.w3.org/2001/XMLSchema-instance"
XSL_HEAD = b'<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">'


def _transform(stylesheet: bytes, source: bytes):
    result = etree.XSLT(etree.fromstring(stylesheet))(etree.fromstring(source))
    # getroot() reparses the serialized output, so an undeclared prefix raises here
    return result.getroot()


class TestXSLTNamespaceDeclarations(TestCase):
    """Created attributes must carry the namespace declaration they need (XSLT 1.0 7.1.3).

    Regression tests for https://github.com/kushaldas/pyuppsala/issues/36.
    """

    def test_attribute_copied_into_literal_result_element(self):
        xsl = (
            XSL_HEAD
            + b"""
<xsl:template match="/root"><out><xsl:apply-templates select="node()|@*"/></out></xsl:template>
<xsl:template match="*"><xsl:copy><xsl:apply-templates select="node()|@*"/></xsl:copy></xsl:template>
<xsl:template match="text()|@*"><xsl:copy/></xsl:template>
</xsl:stylesheet>"""
        )
        src = b'<root xmlns:xsi="%s" xsi:type="xsd:string"><a xsi:type="x"/></root>' % XSI.encode()
        out = _transform(xsl, src)
        assert out.get('{%s}type' % XSI) == 'xsd:string'
        assert out[0].get('{%s}type' % XSI) == 'x'

    def test_prefix_declared_only_on_dropped_element(self):
        xsl = (
            XSL_HEAD
            + b"""
<xsl:template match="/"><out><xsl:copy-of select="//a/@*"/><b><xsl:copy-of select="//a/@*"/></b></out></xsl:template>
</xsl:stylesheet>"""
        )
        src = b'<root><a xmlns:xsi="%s" xsi:type="t"/></root>' % XSI.encode()
        out = _transform(xsl, src)
        assert out.get('{%s}type' % XSI) == 't'
        assert out[0].get('{%s}type' % XSI) == 't'
