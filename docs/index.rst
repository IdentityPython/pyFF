=============================================
pyFF Documentation
=============================================

:Author: `Leif Johansson <leifj@sunet.se>`
:Release: |release|

**pyFF** is a simple but reasonably complete SAML metadata processor. It is intended to be
used by anyone who needs to aggregate, validate, combine, transform, sign or publish
SAML metadata.

**pyFF** is used to run infrastructure for several identity federations of signifficant 
size including edugain.org.

**pyFF** supports producing and validating digital signatures on SAML metadata using
the pyXMLSecurity package which in turn supports PKCS#11 and other mechanisms for
talking to HSMs and other cryptographic hardware.

**pyFF** is also a complete implementation of the SAML metadata query protocol as 
described in draft-young-md-query and draft-young-md-query-saml and implements
extensions to MDQ for searching which means pyFF can be used as the backend for
a discovery service for large-scale identity federations.

Possible usecases include running an federation aggregator, filtering metadata for use
by a discovery service, generating reports from metadata (eg certificate expiration reports),
transforming metadata to add custom elements.

.. toctree::
   :maxdepth: 2
   :caption: Documentation

   usage/install
   usage/quickstart
   usage/deploying
   examples
   coding
   faq


.. toctree::
   :maxdepth: 2
   :caption: API

   pyFF API <code/pyff>



The pyFF logo is the chemical symbol for sublimation - a process by which elements
are transitioned from solid to gas without becoming liquids.
