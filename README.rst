python SAML metadata aggregator
===============================

.. image:: https://img.shields.io/travis/leifj/pyFF.svg
   :target: https://travis-ci.org/leifj/pyFF
   :alt: Travis Build
.. image:: https://img.shields.io/coveralls/leifj/pyFF.svg
   :target: https://coveralls.io/r/leifj/pyFF?branch=master
   :alt: Coverage
.. image:: https://img.shields.io/requires/github/leifj/pyFF.svg
   :target: https://requires.io/github/leifj/pyFF/requirements/?branch=master
   :alt: Requirements Status
.. image:: https://img.shields.io/codeclimate/github/leifj/pyFF.svg
   :target: https://codeclimate.com/github/leifj/pyFF
   :alt: Code Climate
.. image:: https://img.shields.io/pypi/l/pyFF.svg
   :target: https://github.com/leifj/pyFF/blob/master/LICENSE.txt
   :alt: License
.. image:: https://img.shields.io/pypi/format/pyFF.svg
   :target: https://pypi.python.org/pypi/pyFF
   :alt: Format
.. image:: https://img.shields.io/pypi/v/pyFF.svg
   :target: https://pypi.python.org/pypi/pyFF
   :alt: PyPI Version

This is a SAML metadata aggregator written in python. It is based on the model 
for metadata exchange by Ian Young: http://iay.org.uk/blog/2008/10/metadata_interc.html

* http://github.com/leifj/pyFF
* http://pypi.python.org/pypi/pyFF
* http://packages.python.org/pyFF

Features 
========

* Pluggable "pipelines" for processing SAML metadata
* Signature validation and creation
* Support for using PKCS#11 tokens for signing
* Certificate expiration checking and reporting
* Fast parallel fetching of multiple streams
* Integrated discovery service in part based on RA21.org P3W project
* Support for eIDAS metadata service list format

Dependencies
============

* pyXMLSecurity
* PyKCS11 (optional)
