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
.. image:: https://img.shields.io/requires/github/IdentityPython/pyFF.svg
   :target: https://requires.io/github/IdentityPython/pyFF/requirements/?branch=master
   :alt: Requirements Status
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

* http://github.com/IdentityPython/pyFF
* http://pypi.python.org/pypi/pyFF
* http://packages.python.org/pyFF

Features 
========

* Fully customizable processing pipelines in yaml.
* Easy to retrieve, analyze, transform, sign and publish SAML metadata.
* Operate in batch or online mode using embedded HTTP server.
* Provide a full MDX implementation.
* Make use of PKCS#11 tokens and HSMs for key protection.
* Fully compatible with `thiss.io discovery service <https://thiss.io>`_.
* Fully compatible with `mdq-browser frontend app <https://github.com/SUNET/mdq-browser>`_.


Dependencies
============

* pyXMLSecurity
* PyKCS11 (optional)
