<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui"
                xmlns:shibmd="urn:mace:shibboleth:metadata:1.0"
                extension-element-prefixes="str"
>

    <xsl:output method="text" encoding="UTF-8"/>
    <xsl:template match="md:EntitiesDescriptor">
        <xsl:text>[</xsl:text>
        <xsl:apply-templates select="md:EntityDescriptor"/>
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

        <xsl:text>,"title": "</xsl:text>
        <xsl:choose>
            <xsl:when test=".//mdui:DisplayName">
                <xsl:call-template name="getString">
                    <xsl:with-param name="preflang">en</xsl:with-param>
                    <xsl:with-param name="path" select=".//mdui:DisplayName"/>
                </xsl:call-template>
            </xsl:when>
            <xsl:when test=".//md:ServiceName">
                <xsl:call-template name="getString">
                    <xsl:with-param name="preflang">en</xsl:with-param>
                    <xsl:with-param name="path" select=".//md:ServiceName"/>
                </xsl:call-template>
            </xsl:when>
            <xsl:when test=".//md:OrganizationDisplayName">
                <xsl:call-template name="getString">
                    <xsl:with-param name="preflang">en</xsl:with-param>
                    <xsl:with-param name="path" select=".//md:OrganizationDisplayName"/>
                </xsl:call-template>
            </xsl:when>
            <xsl:when test=".//mdui:DomainHint">
                <xsl:value-of select=".//mdui:DomainHint[1]/text()"/>
            </xsl:when>
            <xsl:otherwise>
                <xsl:call-template name="getURIHostName">
                    <xsl:with-param name="uri"><xsl:value-of select="@entityID"></xsl:value-of></xsl:with-param>
                </xsl:call-template>
            </xsl:otherwise>
        </xsl:choose>
        <xsl:text>"</xsl:text>
        <xsl:if test="./md:IDPSSODescriptor/md:Extensions/shibmd:Scope">
            <xsl:text>, "scope": [</xsl:text>
            <xsl:apply-templates select="./md:IDPSSODescriptor/md:Extensions/shibmd:Scope"></xsl:apply-templates>
            <xsl:text>]</xsl:text>
        </xsl:if>
        <xsl:if test=".//mdui:Keywords">
                <xsl:text>,"keywords": "</xsl:text>
                <xsl:call-template name="getString">
                    <xsl:with-param name="preflang">en</xsl:with-param>
                    <xsl:with-param name="path" select=".//mdui:Keywords/text()"/>
                </xsl:call-template>
                <xsl:text>"</xsl:text>
        </xsl:if>
        <xsl:if test=".//mdui:Logo">
                <xsl:text>,"icon": "</xsl:text>
                <xsl:call-template name="getString">
                    <xsl:with-param name="preflang">en</xsl:with-param>
                    <xsl:with-param name="path" select=".//mdui:Logo/text()"/>
                </xsl:call-template>
                <xsl:text>"</xsl:text>
        </xsl:if>
        <xsl:if test=".//mdui:Description">
                <xsl:text>,"descr": "</xsl:text>
                <xsl:call-template name="getString">
                    <xsl:with-param name="preflang">en</xsl:with-param>
                    <xsl:with-param name="path" select=".//mdui:Description"/>
                </xsl:call-template>
                <xsl:text>"</xsl:text>
        </xsl:if>
        <xsl:if test=".//mdui:PrivacyStatementURL">
                <xsl:text>,"psu": "</xsl:text>
                <xsl:call-template name="getString">
                    <xsl:with-param name="preflang">en</xsl:with-param>
                    <xsl:with-param name="path" select=".//mdui:PrivacyStatementURL"/>
                </xsl:call-template>
                <xsl:text>"</xsl:text>
        </xsl:if>
        <xsl:if test=".//mdui:GeolocationHint">
            <xsl:apply-templates select=".//mdui:GeolocationHint[1]"></xsl:apply-templates>
        </xsl:if>
        <xsl:text>,"auth": "saml"</xsl:text>
        <xsl:text>}</xsl:text>
        <xsl:if test="position() != last()">
            <xsl:text>,
</xsl:text>
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

    <xsl:template match="shibmd:Scope">
        <xsl:text>"</xsl:text>
        <xsl:call-template name="safeString">
            <xsl:with-param name="qstr"><xsl:value-of select="text()"/></xsl:with-param>
        </xsl:call-template>
        <xsl:text>"</xsl:text>
        <xsl:if test="position() != last()"><xsl:text>,</xsl:text></xsl:if>
    </xsl:template>
    
    <xsl:template match="mdui:GeolocationHint">
        <xsl:variable name="pos" select="substring(text(),5)"/>
        <xsl:variable name="lat" select="substring-before($pos,',')"/>
        <xsl:variable name="long" select="substring-after($pos,',')"/>
        <xsl:if test="number($lat) = $lat and number($long) = $long">
           <xsl:text>,"geo":</xsl:text>
           <xsl:text>{"lat":</xsl:text>
           <xsl:value-of select="$lat"/>
           <xsl:text>,"long":</xsl:text>
           <xsl:value-of select="$long"/>
           <xsl:text>}</xsl:text>
        </xsl:if>
    </xsl:template>

    <xsl:template match="node()">
        <xsl:copy>
            <xsl:apply-templates select="@* | node()"/>
        </xsl:copy>
    </xsl:template>

    <xsl:template match="@*">
        <xsl:attribute name="{name()}">
            <xsl:value-of select="normalize-space()"/>
        </xsl:attribute>
    </xsl:template>

    <xsl:template match="*"/>

    <!-- utilities -->

    <xsl:template name="getURIHostName">
        <xsl:param name="uri"></xsl:param>
        <xsl:variable name="h"><xsl:value-of select="substring-after($uri,'://')"/></xsl:variable>
        <xsl:if test="contains($h,'/')">
          <xsl:value-of select="substring-before($h,'/')"/>
        </xsl:if>
        <xsl:if test="not(contains($h,'/'))">
          <xsl:value-of select="$h"/>
        </xsl:if>
    </xsl:template>

    <xsl:template name="safeString">
        <xsl:param name="qstr"/>
        <xsl:variable name="remove">'"\</xsl:variable>
        <xsl:value-of select="translate($qstr,$remove,'')"/>
<!-- 
        <xsl:variable name="apos">'</xsl:variable><xsl:variable name="e_apos">\\'</xsl:variable>
        <xsl:variable name="quot">"</xsl:variable><xsl:variable name="e_quot">\"</xsl:variable>
        <xsl:variable name="bs">\</xsl:variable><xsl:variable name="e_bs">\\</xsl:variable>
        <xsl:value-of select="str:replace(str:replace(str:replace(str:replace(str:replace($qstr,$e_quot,$quot),$e_apos,$apos),$bs,$e_bs),$quot,$e_quot),$apos,$e_apos)"/>
-->
    </xsl:template>

    <xsl:template name="getString">
        <xsl:param name="path"/>
        <xsl:param name="preflang"/>
        <xsl:variable name="str" select="$path"/>
        <xsl:choose>
            <xsl:when test="$str[lang($preflang)]">
                <xsl:call-template name="safeString">
                    <xsl:with-param name="qstr" select="normalize-space($str[lang($preflang)])"/>
                </xsl:call-template>
            </xsl:when>
            <xsl:when test="$str">
                <xsl:call-template name="safeString">
                    <xsl:with-param name="qstr" select="normalize-space($str[1])"/>
                </xsl:call-template>
            </xsl:when>
            <xsl:otherwise>
                <xsl:message terminate="no">
                    <xsl:text>Warning: path not found: '</xsl:text>
                    <xsl:value-of select="$path"/>
                    <xsl:text>'</xsl:text>
                </xsl:message>
            </xsl:otherwise>
        </xsl:choose>
    </xsl:template>

</xsl:stylesheet>
