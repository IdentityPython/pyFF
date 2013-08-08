<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdrpi="urn:oasis:names:tc:SAML:metadata:rpi"
  xmlns:date="http://exslt.org/dates-and-times" extension-element-prefixes="date">

  <xsl:param name="publisher"/>
  <xsl:variable name="datetime">
    <xsl:value-of select="date:date-time()"/>
  </xsl:variable>

  <xsl:template match="node()|@*" name="identity">
    <xsl:copy>
      <xsl:apply-templates select="node()|@*"/>
    </xsl:copy>
  </xsl:template>

  <xsl:template match="md:EntitiesDescriptor/md:Extensions">
    <xsl:copy>
      <xsl:apply-templates select="node()"/>
      <xsl:element name="mdrpi:PublicationInfo">
        <xsl:attribute name="publisher"><xsl:value-of select="$publisher"/></xsl:attribute>
        <xsl:attribute name="creationInstant"><xsl:value-of select="$datetime"/></xsl:attribute>
      </xsl:element>
    </xsl:copy>
    <xsl:apply-templates select="md:EntityDescriptor"/>
  </xsl:template>

  <xsl:template match="md:EntitiesDescriptor[not(md:Extensions)]">
    <xsl:copy>
      <xsl:apply-templates select="@*"/>
        <xsl:element name="md:Extensions">
          <xsl:element name="mdrpi:PublicationInfo">
            <xsl:attribute name="publisher"><xsl:value-of select="$publisher"/></xsl:attribute>
            <xsl:attribute name="creationInstant"><xsl:value-of select="$datetime"/></xsl:attribute>
          </xsl:element>
        </xsl:element>
      <xsl:apply-templates select="md:EntityDescriptor"/>
    </xsl:copy>
  </xsl:template>

</xsl:stylesheet>
