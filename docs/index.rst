=============================================
pyFF Documentation
=============================================

:Author: `Leif Johansson <leifj@sunet.se>`
:Release: |release|

pyFF is a simple but reasonably complete SAML metadata aggregator,
processor and publisher. It is intended to be used by anyone who 
needs to manage multiple streams of SAML metadata. 

pyFF is not a SAML metadata registry. If you need one of those 
have a look at PEER. pyFF will happily co-exist with PEER though.

pyFF is based on a plugin-architecture which allows it to be 
configured for a wide variety of tasks including

- fetching and validating metadata
- reading metadata stored in local files
- transforming metadata using a wide range of plugins
- splitting and joining metadata
- signing and publishing metadata

Contents:

.. toctree::
   :maxdepth: 2

   install
   using


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

