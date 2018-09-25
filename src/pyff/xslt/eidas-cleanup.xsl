<?xml version="1.0"?>
<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:xs="http://www.w3.org/2001/XMLSchema"
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-Instance"
                xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                xmlns:samla="urn:oasis:names:tc:SAML:2.0:assertion"
                xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:protocol">

    <xsl:variable name="eidas_territory"/>
    <xsl:variable name="eidas_endpoint_type"/>

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

    <xsl:template match="md:Extensions[not(mdattr:EntityAttributes)]">
        <md:Extensions>
            <xsl:call-template name="eidas-attributes-wrapper"/>
            <xsl:apply-templates/>
        </md:Extensions>
    </xsl:template>

    <xsl:template match="saml:Extensions[not(mdattr:EntityAttributes)]">
        <md:Extensions>
            <xsl:call-template name="eidas-attributes-wrapper"/>
            <xsl:apply-templates/>
        </md:Extensions>
    </xsl:template>

    <!-- correct namespace for Extension element in some versions of EU-provided EIDAS software -->
    <xsl:template match="saml:Extensions">
        <xsl:element name="md:Extensions">
            <xsl:apply-templates/>
        </xsl:element>
    </xsl:template>

    <xsl:template name="eidas-attributes-wrapper">
        <xsl:if test="$eidas_endpoint_type and $eidas_territory">
            <mdattr:EntityAttributes>
                <xsl:call-template name="eidas-attributes"/>
            </mdattr:EntityAttributes>
        </xsl:if>
    </xsl:template>

    <xsl:template name="eidas-attributes">
        <xsl:if test="$eidas_endpoint_type and $eidas_territory">
            <samla:Attribute Name="https://pyff.io/eidas/endpoint_type">
                <samla:AttributeValue><xsl:value-of select="$eidas_endpoint_type"/></samla:AttributeValue>
            </samla:Attribute>
            <samla:Attribute Name="https://pyff.io/eidas/territory">
                <samla:AttributeValue><xsl:value-of select="$eidas_territory"/></samla:AttributeValue>
            </samla:Attribute>
        </xsl:if>
    </xsl:template>

    <xsl:template match="md:EntityDescriptor[not(md:Extensions) and not(saml:Extensions)]">
        <md:EntityDescriptor>
            <xsl:attribute name="entityID"><xsl:value-of select="@entityID"></xsl:value-of></xsl:attribute>
            <xsl:apply-templates/>
        </md:EntityDescriptor>
    </xsl:template>

    <xsl:template match="mdattr:EntityAttributes">
        <xsl:call-template name="eidas-attributes"/>
        <xsl:copy>
          <xsl:apply-templates select="node()|@*"/>
        </xsl:copy>
    </xsl:template>

    <!-- just copy everything else -->
    <xsl:template match="text()|comment()|@*">
        <xsl:copy/>
    </xsl:template>

    <xsl:template match="@type"/>

    <xsl:template match="*">
        <xsl:copy>
          <xsl:apply-templates select="node()|@*"/>
        </xsl:copy>
    </xsl:template>

</xsl:stylesheet>
