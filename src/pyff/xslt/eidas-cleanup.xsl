<?xml version="1.0"?>
<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                xmlns:samla="urn:oasis:names:tc:SAML:2.0:assertion"
                xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:protocol">

    <!-- remove ID, validUntil, cacheDuration and xml:base -->
    <xsl:template match="@ID"/>
    <xsl:template match="@Id"/>
    <xsl:template match="@xml:id"/>
    <xsl:template match="@validUntil"/>
    <xsl:template match="@cacheDuration"/>
    <xsl:template match="@xml:base"/>

    <!-- drop any remaining XML Signature objects -->
    <xsl:template match="ds:Signature"/>

    <!-- output organization elements in correct order and provide fallback for missing elements -->
    <xsl:template match="md:Organization">
        <xsl:copy>
            <xsl:choose>
                <xsl:when test="not(md:OrganizationName/text()) or not(md:OrganizationName)">
                    <xsl:choose>
                        <xsl:when test="md:OrganizationDisplayName/text()">
                            <md:OrganizationName xml:lang="en"><xsl:value-of select="md:OrganizationDisplayName"/></md:OrganizationName>
                        </xsl:when>
                        <xsl:otherwise>
                            <md:OrganizationName xml:lang="en"><xsl:text>Undefined</xsl:text></md:OrganizationName>
                        </xsl:otherwise>
                    </xsl:choose>
                </xsl:when>
                <xsl:otherwise>
                    <xsl:apply-templates select="md:OrganizationName"/>
                </xsl:otherwise>
            </xsl:choose>
            <xsl:choose>
                <xsl:when test="not(md:OrganizationDisplayName/text()) or not(md:OrganizationDisplayName)">
                    <xsl:choose>
                        <xsl:when test="md:OrganizationName/text()">
                            <md:OrganizationDisplayName xml:lang="en"><xsl:value-of select="md:OrganizationName"/></md:OrganizationDisplayName>
                        </xsl:when>
                        <xsl:otherwise>
                            <md:OrganizationDisplayName xml:lang="en"><xsl:text>Undefined</xsl:text></md:OrganizationDisplayName>
                        </xsl:otherwise>
                    </xsl:choose>
                </xsl:when>
                <xsl:otherwise>
                    <xsl:apply-templates select="md:OrganizationDisplayName"/>
                </xsl:otherwise>
            </xsl:choose>
            <xsl:choose>
                <xsl:when test="not(md:OrganizationURL/text()) or not(md:OrganizationURL)">
                    <md:OrganizationURL xml:lang="en"><xsl:value-of select="../@entityID"/></md:OrganizationURL>
                </xsl:when>
                <xsl:otherwise>
                    <xsl:apply-templates select="md:OrganizationURL"/>
                </xsl:otherwise>
            </xsl:choose>
        </xsl:copy>
    </xsl:template>

    <!-- correct namespace for Extension element in some versions of EU-provided EIDAS software -->
    <xsl:template match="saml:Extensions">
        <xsl:element name="md:Extensions">
            <xsl:apply-templates select="text()|comment()|@*|node()"/>
        </xsl:element>
    </xsl:template>

    <xsl:template name="attributes">
        <samla:Attribute Name="https://pyff.io/eidas/endpoint_type">
            <samla:AttributeValue><xsl:value-of select="$eidas_endpoint_type"/></samla:AttributeValue>
        </samla:Attribute>
        <samla:Attribute Name="https://pyff.io/eidas/territory">
            <samla:AttributeValue><xsl:value-of select="$eidas_territory"/></samla:AttributeValue>
        </samla:Attribute>
    </xsl:template>

    <xsl:template match="md:EntityDescriptor">
        <xsl:choose>
            <xsl:when test="md:Extensions">
                <xsl:copy>
                    <xsl:apply-templates select="node()|@*"/>
                </xsl:copy>
            </xsl:when>
            <xsl:otherwise>
                <mdattr:EntityAttributes>
                    <xsl:call-template name="attributes"/>
                </mdattr:EntityAttributes>
            </xsl:otherwise>
        </xsl:choose>
    </xsl:template>

    <xsl:template match="mdattr:EntityAttributes">
        <xsl:call-template name="attributes"/>
    </xsl:template>

    <!-- just copy everything else -->
    <xsl:template match="text()|comment()|@*">
        <xsl:copy/>
    </xsl:template>

    <xsl:template match="*">
        <xsl:copy>
          <xsl:apply-templates select="node()|@*"/>
        </xsl:copy>
    </xsl:template>

</xsl:stylesheet>
