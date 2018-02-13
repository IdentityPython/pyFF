=============================================
pyFF Documentation
=============================================

:Author: `Leif Johansson <leifj@sunet.se>`
:Release: |release|

pyFF is a simple but reasonably complete SAML metadata processor. It is intended to be
used by anyone who needs to aggregate, validate, combine, transform, sign or publish
SAML metadata.

Possible usecases include running an federation aggregator, filtering metadata for use
by a discovery service, generating reports from metadata (eg certificate expiration reports),
transforming metadata to add custom elements.

pyFF supports producing and validating digital signatures on SAML metadata using
the pyXMLSecurity package which in turn supports using PKCS#11-modules - notoriously
difficult to achieve using other tools.

pyFF is not a SAML metadata registry. If you need one of those have a look at the
PEER project (also on pypi).

.. toctree::
   :maxdepth: 2

   install
   using
   examples
   coding
   faq
   api/modules


The pyFF logo is the chemical symbol for sublimation - a process by which elements
are transitioned from solid to gas without becoming liquids.
