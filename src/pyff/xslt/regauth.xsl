<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdrpi="urn:oasis:names:tc:SAML:metadata:rpi"
  xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">

  <xsl:param name="entityAttribute" select="'http://aai.dfn.de/edugain/registrationAuthority'"/>

  <xsl:template match="node()|@*" name="identity">
    <xsl:copy>
      <xsl:apply-templates select="node()|@*"/>
    </xsl:copy>
  </xsl:template>
  
  <xsl:template match="md:EntityDescriptor/md:Extensions/mdattr:EntityAttributes">
    <xsl:copy>
      <xsl:apply-templates select="node()"/>
        <saml:Attribute Name="{$entityAttribute}" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
          <saml:AttributeValue><xsl:value-of select="../mdrpi:RegistrationInfo/@registrationAuthority"/></saml:AttributeValue>
        </saml:Attribute>
    </xsl:copy>
    <xsl:apply-templates select="md:EntityDescriptor"/>
  </xsl:template>

  <xsl:template match="md:EntityDescriptor/md:Extensions[not(mdattr:EntityAttributes)]">
    <xsl:copy>
      <xsl:apply-templates select="node()"/>
      <mdattr:EntityAttributes>
        <saml:Attribute Name="{$entityAttribute}" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
          <saml:AttributeValue><xsl:value-of select="mdrpi:RegistrationInfo/@registrationAuthority"/></saml:AttributeValue>
        </saml:Attribute>
      </mdattr:EntityAttributes>
    </xsl:copy>
    <xsl:apply-templates select="md:EntityDescriptor"/>
  </xsl:template>

</xsl:stylesheet>
