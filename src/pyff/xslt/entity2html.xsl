<?xml version="1.0"?>
<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                xmlns:atom="http://www.w3.org/2005/Atom"
                xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui"
                xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                xmlns:shibmd="urn:mace:shibboleth:metadata:1.0"
                xmlns:html="http://www.w3.org/1999/xhtml">

    <xsl:output method="html" omit-xml-declaration="yes" encoding="UTF-8"/>
    <xsl:template match="md:EntityDescriptor">
      <div>
            <h1>
                <xsl:call-template name="truncate">
                    <xsl:with-param name="maxlen">40</xsl:with-param>
                    <xsl:with-param name="str">
                    <xsl:choose>
                        <xsl:when test="//mdui:DisplayName">
                            <xsl:call-template name="getString">
                                <xsl:with-param name="path" select="//mdui:DisplayName"/>
                            </xsl:call-template>
                        </xsl:when>
                        <xsl:when test="//md:OrganizationDisplayName">
                            <xsl:call-template name="getString">
                                <xsl:with-param name="path" select="//md:OrganizationDisplayName"/>
                            </xsl:call-template>
                        </xsl:when>
                        <xsl:when test="//md:ServiceName">
                            <xsl:call-template name="getString">
                                <xsl:with-param name="path" select="//md:ServiceName"/>
                            </xsl:call-template>
                        </xsl:when>
                        <xsl:otherwise>
                            <xsl:value-of select="@entityID"/>
                        </xsl:otherwise>
                    </xsl:choose>

                    <xsl:if test="//mdui:Logo">
                        <html:div class="pull-right"><html:img>
                            <xsl:attribute name="style">vertical-align: bottom; margin-right: 5px;</xsl:attribute>
                            <xsl:attribute name="class">img-polaroid</xsl:attribute>
                            <xsl:attribute name="src">
                                <xsl:call-template name="getString">
                                    <xsl:with-param name="path" select="//mdui:Logo"/>
                                </xsl:call-template>
                            </xsl:attribute>
                        </html:img></html:div>
                    </xsl:if></xsl:with-param>
                </xsl:call-template>
            </h1>
        <div>
            <ul id="menu" class="nav nav-tabs">
                <li class="active"><a href="#summary" >Summary</a></li>
                <xsl:if test="md:IDPSSODescriptor">
                   <li><a href="#idp">Identity Provider</a></li>
                </xsl:if>
                <xsl:if test="md:SPSSODescriptor">
                    <li><a href="#sp">Service Provider</a></li>
                </xsl:if>
                <xsl:if test="//md:ContactPerson">
                    <li><a href="#contacts">Contacts</a></li>
                </xsl:if>
                <xsl:if test="//mdui:GeolocationHint">
                    <li><a id="locationtab" href="#location">Location</a></li>
                </xsl:if>
                <li><a href="#fullxml">XML</a></li>
            </ul>
            <div class="tab-content">
                <div class="tab-pane active" id="summary">
                    <div class="well">
                        <xsl:choose>
                            <xsl:when test="//mdui:Description">
                                <xsl:call-template name="getString">
                                    <xsl:with-param name="path" select="//mdui:Description"/>
                                </xsl:call-template>
                            </xsl:when>
                            <xsl:when test="//md:OrganizationDisplayName">
                                <xsl:call-template name="getString">
                                    <xsl:with-param name="path" select="//md:OrganizationDisplayName"/>
                                </xsl:call-template>
                            </xsl:when>
                            <xsl:otherwise>
                                <xsl:text>No information provided</xsl:text>
                            </xsl:otherwise>
                        </xsl:choose>
                        <xsl:if test="//md:OrganizationURL">
                            <div><a>
                                <xsl:attribute name="href">
                                    <xsl:call-template name="getString">
                                        <xsl:with-param name="path" select="//md:OrganizationURL"/>
                                    </xsl:call-template>
                                </xsl:attribute>
                                <xsl:call-template name="getString">
                                    <xsl:with-param name="path" select="//md:OrganizationURL"/>
                                </xsl:call-template>
                            </a></div>
                        </xsl:if>
                    </div>
                </div>
                <xsl:if test="md:IDPSSODescriptor">
                    <xsl:apply-templates select=".//md:IDPSSODescriptor"/>
                </xsl:if>
                <xsl:if test="md:SPSSODescriptor">
                    <xsl:apply-templates select=".//md:SPSSODescriptor"/>
                </xsl:if>
                <xsl:if test="md:ContactPerson">
                    <div class="tab-pane" id="contacts">
                        <xsl:apply-templates select=".//md:ContactPerson"/>
                    </div>
                </xsl:if>
                <xsl:if test="//mdui:GeolocationHint">
                    <div class="tab-pane" id="location">
                        <div class="well">
                            <div id="map_canvas" style="width:100%;height:350px; overflow:hidden">Unable to display map</div>
                        </div>
                        <script type="text/javascript">
                            <xsl:text>
$(function() { $("#map_canvas").gmap({'zoom': 16,
                                      'center':'</xsl:text>
                            <xsl:call-template name="getPos">
                                <xsl:with-param name="path" select="//mdui:GeolocationHint[1]"/>
                            </xsl:call-template>
                            <xsl:text>',
                                      'zoomControl': true,
                                      'zoomControlOptions': {'style': google.maps.ZoomControlStyle.LARGE},
                                      'callback': function() {
   var self = this;
   $('#locationtab').on('shown',function(ev) {
      self.refresh();
   });
</xsl:text>
                            <xsl:apply-templates select="//mdui:GeolocationHint"/>
                            <xsl:text>}})});</xsl:text>
                        </script>
                    </div>
                </xsl:if>
                <div class="tab-pane" id="fullxml">
                    <pre class="pre-scrollable prettyprint linenums language-xml">
                        <code role="entity"></code>
                    </pre>
                </div>
            </div>
        </div>
        <script type="text/javascript">
            $(function() {
                $('#menu a').click(function (e) {
                      e.preventDefault();
                      $(this).tab('show');
                })
            });
        </script>
      </div>
    </xsl:template>

    <xsl:template match="mdui:GeolocationHint">
        <xsl:text>
   self.addMarker({'position': '</xsl:text>
        <xsl:call-template name="getPos">
            <xsl:with-param name="path" select="."/>
        </xsl:call-template>
        <xsl:text>','bounds': false});
</xsl:text>
    </xsl:template>

    <xsl:template match="md:Extensions">
        <!-- xsl:apply-templates select=".//mdattr:EntityAttributes"/ -->
    </xsl:template>

    <xsl:template match="md:SPSSODescriptor">
        <div class="tab-pane" id="sp">
            <div class="well">
                <h2>Properties</h2>
                <dl>
                    <dt>EntityID</dt>
                    <dd><xsl:value-of select="../@entityID"/></dd>
                    <dt>Protocols</dt>
                    <dd>
                        <xsl:call-template name="output-tokens">
                            <xsl:with-param name="list">
                                <xsl:value-of select="@protocolSupportEnumeration"/>
                            </xsl:with-param>
                        </xsl:call-template>
                    </dd>
                    <xsl:apply-templates select="md:AttributeConsumingService"/>
                </dl>
                <xsl:if test="mdattr:EntityAttributes">
                    <h2>Entity Attributes</h2>
                    <xsl:apply-templates select="..//mdattr:EntityAttributes"/>
                </xsl:if>
                <xsl:apply-templates select=".//md:Extensions"/>
            </div>
        </div>
    </xsl:template>

    <xsl:template match="mdattr:EntityAttributes">
        <html:dl>
            <xsl:apply-templates select="saml:Attribute"/>
        </html:dl>
    </xsl:template>

    <xsl:template match="saml:Attribute">
        <xsl:call-template name="dtlist">
            <xsl:with-param name="path" select=".//saml:AttributeValue"/>
            <xsl:with-param name="term"><xsl:value-of select="@Name"/></xsl:with-param>
        </xsl:call-template>
    </xsl:template>

    <xsl:template match="md:AttributeConsumingService">
        <xsl:call-template name="dtlist">
            <xsl:with-param name="path" select=".//md:ServiceName"/>
            <xsl:with-param name="term">Service Name(s)</xsl:with-param>
        </xsl:call-template>
        <xsl:call-template name="dtlist">
            <xsl:with-param name="path" select=".//md:ServiceDescription"/>
            <xsl:with-param name="term">Service Description(s)</xsl:with-param>
        </xsl:call-template>
        <xsl:call-template name="dtlist">
            <xsl:with-param name="path" select=".//md:RequestedAttribute"/>
            <xsl:with-param name="term">Requested Attribute(s)</xsl:with-param>
        </xsl:call-template>
    </xsl:template>

    <xsl:template match="md:ContactPerson">
        <html:div class="well">
            <html:h4><xsl:value-of select="@contactType"></xsl:value-of></html:h4>
            <html:address>
                <xsl:if test="md:GivenName">
                    <xsl:value-of select="md:GivenName"/><xsl:text> </xsl:text>
                </xsl:if>
                <xsl:if test="md:SurName">
                    <xsl:value-of select="md:SurName"/>
                </xsl:if>
                <xsl:if test="md:GivenName|md:SurName">
                    <html:br/>
                </xsl:if>
                <xsl:apply-templates select="md:Organization|md:EmailAddress"/>
            </html:address>
        </html:div>
    </xsl:template>

    <xsl:template match="md:Organization">
        <xsl:value-of select="text()"/><br/>
    </xsl:template>

    <xsl:template match="md:EmailAddress">
        <a>
            <xsl:attribute name="href">
                <xsl:text>mailto:</xsl:text><xsl:value-of select="text()"></xsl:value-of>
            </xsl:attribute>
            <xsl:value-of select="text()"/>
        </a><html:br/>
    </xsl:template>

    <xsl:template match="md:IDPSSODescriptor">
        <div class="tab-pane" id="idp">
            <div class="well">
                <dl>
                    <dt>EntityID</dt>
                    <dd><xsl:value-of select="../@entityID"/></dd>
                    <dt>Protocols</dt>
                    <dd>
                        <xsl:call-template name="output-tokens">
                            <xsl:with-param name="list">
                                <xsl:value-of select="@protocolSupportEnumeration"/>
                            </xsl:with-param>
                        </xsl:call-template>
                    </dd>
                    <xsl:call-template name="dtlist">
                        <xsl:with-param name="path" select=".//shibmd:Scope"/>
                        <xsl:with-param name="term">Shibboleth scope(s)</xsl:with-param>
                    </xsl:call-template>
                    <xsl:call-template name="dtlist">
                        <xsl:with-param name="path" select=".//md:NameIDFormat"/>
                        <xsl:with-param name="term">NameID format(s)</xsl:with-param>
                    </xsl:call-template>
                </dl>
                <xsl:apply-templates select=".//md:Extensions"/>
            </div>
        </div>
    </xsl:template>

    <xsl:template match="md:RequestedAttribute">
        <html:div>
            <xsl:attribute name="style">
                <xsl:choose>
                    <xsl:when test="@isRequired='1' or @isRequired='true'">
                        <xsl:text>font-weight: bold;</xsl:text>
                    </xsl:when>
                    <xsl:when test="@isRequired='0' or @isRequired='false'">
                        <xsl:text>font-style: italic;</xsl:text>
                    </xsl:when>
                </xsl:choose>
            </xsl:attribute>
            <xsl:value-of select="@Name"/>
            <xsl:call-template name="attribute-links"/>
        </html:div>

    </xsl:template>

    <!-- utilities -->

    <xsl:template name="attribute-links">
        <xsl:if test="@NameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:uri' and substring(@Name,0,8)='urn:oid'">
            <a>
                <xsl:attribute name="class">
                    <xsl:text>label label-info</xsl:text>
                </xsl:attribute>
                <xsl:attribute name="style">
                    <xsl:text>margin-left: 2px;</xsl:text>
                </xsl:attribute>
                <xsl:attribute name="href">
                    <xsl:text>http://www.alvestrand.no/objectid/</xsl:text><xsl:value-of select="substring(@Name,9)"/><xsl:text>.html</xsl:text>
                </xsl:attribute>
                <xsl:text>alvestrand.no</xsl:text>
            </a>
            <a>
                <xsl:attribute name="class">
                    <xsl:text>label label-info</xsl:text>
                </xsl:attribute>
                <xsl:attribute name="style">
                    <xsl:text>margin-left: 2px;</xsl:text>
                </xsl:attribute>
                <xsl:attribute name="href">
                    <xsl:text>http://oid-info.com/get/</xsl:text><xsl:value-of select="substring(@Name,9)"/>
                </xsl:attribute>
                <xsl:text>oid-info.com</xsl:text>
            </a><xsl:text> </xsl:text>
        </xsl:if>
    </xsl:template>

    <xsl:template name="output-tokens">
        <xsl:param name="list" />
        <xsl:variable name="newlist" select="concat(normalize-space($list), ' ')" />
        <xsl:variable name="first" select="substring-before($newlist, ' ')" />
        <xsl:variable name="remaining" select="substring-after($newlist, ' ')" />
        <dd>
            <xsl:value-of select="$first" />
        </dd>
        <xsl:if test="$remaining">
            <xsl:call-template name="output-tokens">
                <xsl:with-param name="list" select="$remaining" />
            </xsl:call-template>
        </xsl:if>
    </xsl:template>

    <xsl:template name="dtlist">
        <xsl:param name="path"/>
        <xsl:param name="term"/>
        <html:dt><xsl:value-of select="$term"/></html:dt>
        <xsl:for-each select="$path">
            <html:dd><xsl:apply-templates select="."/></html:dd>
        </xsl:for-each>
    </xsl:template>

    <xsl:template name="getString">
        <xsl:param name="path"/>
        <xsl:variable name="str" select="$path"/>
        <xsl:choose>
            <xsl:when test="$str[lang('en')]">
                <xsl:value-of select="$str[lang('en')]"/>
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

    <xsl:template name="getPos">
        <xsl:param name="path"/>
        <xsl:variable name="geo" select="$path"/>
        <xsl:value-of select="substring($geo/text(),5)"/>
    </xsl:template>

    <xsl:template name="truncate">
        <xsl:param name="str"/>
        <xsl:param name="maxlen"/>
        <xsl:if test="string-length($str) > $maxlen">
            <xsl:value-of select="substring($str,0,$maxlen)"/><xsl:text>...</xsl:text>
        </xsl:if>
        <xsl:if test="not(string-length($str) > $maxlen)">
            <xsl:value-of select="$str"/>
        </xsl:if>
    </xsl:template>

</xsl:stylesheet>