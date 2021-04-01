python SAML metadata aggregator
===============================

.. image:: https://img.shields.io/pypi/l/pyXMLSecurity.svg
   :target: https://github.com/leifj/pyXMLSecurity/blob/master/LICENSE.txt
   :alt: License
.. image:: https://img.shields.io/travis/IdentityPython/pyFF.svg
   :target: https://travis-ci.org/IdentityPython/pyFF
   :alt: Travis Build
.. image:: https://img.shields.io/coveralls/IdentityPython/pyFF.svg
   :target: https://coveralls.io/r/leifj/pyFF?branch=master
   :alt: Coverage
.. image:: https://api.codeclimate.com/v1/badges/133c2c109b680c6868c1/maintainability
   :target: https://codeclimate.com/github/IdentityPython/pyFF/maintainability
   :alt: Maintainability
.. image:: https://img.shields.io/pypi/format/pyFF.svg
   :target: https://pypi.python.org/pypi/pyFF
   :alt: Format
.. image:: https://img.shields.io/pypi/v/pyFF.svg
   :target: https://pypi.python.org/pypi/pyFF
   :alt: PyPI Version
.. image:: https://readthedocs.org/projects/pyff/badge/
   :target: https://pyff.readthedocs.org/
   :alt: Documentation
   

This is a SAML metadata aggregator written in python. It is based on the model 
for metadata exchange by Ian Young: http://iay.org.uk/blog/2008/10/metadata_interc.html

Features 
========

* Fully customizable processing pipelines in yaml.
* Easy to retrieve, analyze, transform, sign and publish SAML metadata.
* Operate in batch or online mode using embedded HTTP server.
* Provide a full MDX implementation.
* Make use of PKCS#11 tokens and HSMs for key protection.
* Fully compatible with `thiss.io discovery service <https://thiss.io>`_.
* Fully compatible with `mdq-browser frontend app <https://github.com/SUNET/mdq-browser>`_.

About 2.0
=========

The 2.0 release of pyFF contains several changes that are in some sense backwards *in*compatible with the 1.x releases:

* No built-in discovery service. The discovery service code that was once part of pyFF has been forked off into its own project: https://github.com/TheIdentitySelector/thiss-js
* No built-in admin-UI. The https://github.com/SUNET/mdq-browser is a simple single-page application that replaces most of the functions of the old UI and also makes it easier to deploy pyFF in situations where access to the admin UI needs to be limited.

Dependencies
============

* pyXMLSecurity
* PyKCS11 (optional)
* pygments
* gunicorn (for the standalone pyffd server)
* ... cf requirements.txt

More information
================

Project homepage: https://pyff.io/
