<?xml version="1.0"?>
<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:shibmeta="urn:mace:shibboleth:metadata:1.0"
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                xmlns:xi="http://www.w3.org/2001/XInclude"
                xmlns:idpdisco="urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol"
                xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute"
                xmlns:shibmd="urn:mace:shibboleth:metadata:1.0">
 
  <xsl:output method="xml" indent="yes" encoding="UTF-8"/>
  <xsl:param name="indent-increment" select="'  '"/>
  <xsl:strip-space elements="*" />

  <xsl:template match="md:Extensions">
      <md:Extensions>
        <xsl:apply-templates select="shibmeta:Scope"/>
        <xsl:apply-templates select="idpdisco:DiscoveryResponse"/>
      </md:Extensions>
  </xsl:template>

  <xsl:template match="text()|comment()|@*">
    <xsl:copy/>
  </xsl:template>
  
  <xsl:template match="*">
    <xsl:copy>
      <xsl:apply-templates select="node()|@*"/>
    </xsl:copy>
  </xsl:template>

</xsl:stylesheet>
