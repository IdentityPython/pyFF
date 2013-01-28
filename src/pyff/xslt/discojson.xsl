<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                xmlns:atom="http://www.w3.org/2005/Atom"
                xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui"
                xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                xmlns:shibmd="urn:mace:shibboleth:metadata:1.0"
                xmlns:html="http://www.w3.org/1999/xhtml">

    <xsl:output method="text" encoding="UTF-8"/>
    <xsl:template match="md:EntitiesDescriptor">
        <xsl:text>[</xsl:text>
        <xsl:apply-templates/>
        <xsl:text>]</xsl:text>
    </xsl:template>

    <xsl:template match="md:EntityDescriptor">
        <xsl:text>{</xsl:text>

        <xsl:text>"entityID": "</xsl:text>
        <xsl:value-of select="@entityID"/>
        <xsl:text>"</xsl:text>

        <xsl:text>,"type": "</xsl:text>
        <xsl:apply-templates select=".//md:IDPSSODescriptor[1]"/>
        <xsl:apply-templates select=".//md:SPSSODescriptor[1]"/>
        <xsl:text>"</xsl:text>

        <xsl:text>,"icon": "</xsl:text>
        <xsl:apply-templates select=".//mdui:Logo[1]/text()"/>
        <xsl:text>"</xsl:text>

        <xsl:text>,"title": "</xsl:text>
        <xsl:choose>
            <xsl:when test=".//mdui:DisplayName">
                <xsl:call-template name="getString">
                    <xsl:with-param name="preflang">en</xsl:with-param>
                    <xsl:with-param name="path" select=".//mdui:DisplayName"/>
                </xsl:call-template>
            </xsl:when>
            <xsl:when test=".//md:OrganizationDisplayName">
                <xsl:call-template name="getString">
                    <xsl:with-param name="preflang">en</xsl:with-param>
                    <xsl:with-param name="path" select=".//md:OrganizationDisplayName"/>
                </xsl:call-template>
            </xsl:when>
            <xsl:when test=".//md:ServiceName">
                <xsl:call-template name="getString">
                    <xsl:with-param name="preflang">en</xsl:with-param>
                    <xsl:with-param name="path" select=".//md:ServiceName"/>
                </xsl:call-template>
            </xsl:when>
            <xsl:when test=".//mdui:DomainHint">
                <xsl:value-of select=".//mdui:DomainHint[1]/text()"/>
            </xsl:when>
            <xsl:otherwise>
                <xsl:value-of select="@entityID"/>
            </xsl:otherwise>
        </xsl:choose>
        <xsl:text>"</xsl:text>
        <xsl:choose>
            <xsl:when test=".//mdui:Description">
                <xsl:text>,"descr": "</xsl:text>
                <xsl:call-template name="getString">
                    <xsl:with-param name="preflang">en</xsl:with-param>
                    <xsl:with-param name="path" select=".//mdui:Description"/>
                </xsl:call-template>
                <xsl:text>"</xsl:text>
            </xsl:when>
        </xsl:choose>
        <xsl:if test=".//mdui:GeolocationHint">
            <xsl:text>,"geo":</xsl:text>
            <xsl:apply-templates select=".//mdui:GeolocationHint[1]"></xsl:apply-templates>
        </xsl:if>
        <xsl:text>,"auth": "saml"</xsl:text>
        <xsl:text>}</xsl:text>
        <xsl:if test="./following-sibling::*">
            <xsl:text>,</xsl:text>
        </xsl:if>
    </xsl:template>

    <xsl:template match="md:SPSSODescriptor">
        <xsl:if test="not(md:IDPSSODescriptor)">
            <xsl:text>sp</xsl:text>
        </xsl:if>
    </xsl:template>

    <xsl:template match="md:IDPSSODescriptor">
        <xsl:text>idp</xsl:text>
    </xsl:template>

    <xsl:template match="mdui:GeolocationHint">
        <xsl:variable name="pos" select="substring(text(),5)"/>
        <xsl:text>{"lat":</xsl:text>
        <xsl:value-of select="substring-before($pos,',')"/>
        <xsl:text>,"long":</xsl:text>
        <xsl:value-of select="substring-after($pos,',')"/>
        <xsl:text>}</xsl:text>
    </xsl:template>

    <xsl:template match="*"/>

    <!-- utilities -->

    <xsl:template name="getString">
        <xsl:param name="path"/>
        <xsl:param name="preflang"/>
        <xsl:variable name="str" select="$path"/>
        <xsl:choose>
            <xsl:when test="$str[lang($preflang)]">
                <xsl:value-of select="$str[lang($preflang)]"/>
            </xsl:when>
            <xsl:when test="$str">
                <xsl:value-of select="$str[1]"/>
            </xsl:when>
            <xsl:otherwise>
                <xsl:message terminate="no">
                    <xsl:text>Warning: path not found: '</xsl:text>
                    <xsl:value-of select="$path"/>
                </xsl:message>
            </xsl:otherwise>
        </xsl:choose>
    </xsl:template>

</xsl:stylesheet>