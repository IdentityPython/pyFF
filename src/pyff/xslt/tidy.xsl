<?xml version="1.0"?>
<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:shibmeta="urn:mace:shibboleth:metadata:1.0"
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
		xmlns:xi="http://www.w3.org/2001/XInclude"
                xmlns:shibmd="urn:mace:shibboleth:metadata:1.0">

  <xsl:template match="@ID"/>
  <xsl:template match="@validUntil"/>
  <xsl:template match="@cacheDuration"/>

  <xsl:template match="text()|comment()|@*">
    <xsl:copy/>
  </xsl:template>
  
  <xsl:template match="*">
    <xsl:copy>
      <xsl:apply-templates select="node()|@*"/>
    </xsl:copy>
  </xsl:template>

</xsl:stylesheet>
