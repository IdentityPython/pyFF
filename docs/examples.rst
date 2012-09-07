Examples
========

Examples are king.

Example 1 - A simple pull
-------------------------

Fetch SWAMID metadata, split it up into EntityDescriptor elements and store each as a separate file in /tmp/swamid.

.. code-block:: yaml

   - remote:
        - http://md.swamid.se/md/swamid-2.0.xml
   - store: "/tmp/swamid"
   - stats

Example 2 - Grab the IdPs from edugain
--------------------------------------

Grab edugain metadata, select the IdPs (using an XPath expression), run it through the built-in 'tidy' XSL
stylesheet (cf below) which cleans up some known problems, sign the result and write the lot to a file.

.. code-block:: yaml

    - remote:
       - http://mds.edugain.org edugain-signer.crt
    - select: "http://mds.edugain.org!//md:EntityDescriptor[md:IDPSSODescriptor]"
    - xslt:
        stylesheet: tidy.xsl
    - sign:
        key: sign.key
        cert: sign.crt
    - publish: /tmp/edugain-idp.xml
    - stats

For reference the 'tidy' xsl is included with pyFF and looks like this:

.. code-block:: xml

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
