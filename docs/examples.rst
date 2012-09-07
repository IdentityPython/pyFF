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

Example 3 - Sign using a PKCS#11 module
---------------------------------------

Fetch SWAMID metadata (and validate the signature using a certificate matching the given SHA1 fingerprint), select
the Identity Providers, tidy it up a bit and sign with the key with the label 'signer' in the PKCS#11 module
/usr/lib/libsofthsm.so. If a certificate is found in the same PKCS#11 object, that certificate is included in
the Singature object.

.. code-block:: yaml

    - remote:
       - http://md.swamid.se/md/swamid-2.0.xml 12:60:D7:09:6A:D9:C1:43:AD:31:88:14:3C:A8:C4:B7:33:8A:4F:CB
    - select: "!//md:EntityDescriptor[md:IDPSSODescriptor]"
    - xslt:
        stylesheet: tidy.xsl
    - sign:
        key: pkcs11:///usr/lib/libsofthsm.so/signer
    - publish: /tmp/idp.xml
    - stats

Running this example requires some preparation. Run the 'p11setup.sh' script in the examples directory. This
This results in a SoftHSM token. Now run pyff:

.. code-block:: bash

    # env PYKCS11PIN=secret1 SOFTHSM_CONF=softhsm.conf pyff --loglevel=DEBUG p11.fd


