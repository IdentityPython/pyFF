python SAML metadata aggregator
===============================

.. image:: https://travis-ci.org/leifj/pyFF.svg?branch=master
    :target: https://travis-ci.org/leifj/pyFF
.. image:: https://coveralls.io/repos/leifj/pyFF/badge.png?branch=master
   :target: https://coveralls.io/r/leifj/pyFF?branch=master
   :alt: Coverage
.. image:: https://requires.io/github/leifj/pyFF/requirements.svg?branch=master
   :target: https://requires.io/github/leifj/pyFF/requirements/?branch=master
   :alt: Requirements Status
.. image:: https://pypip.in/license/pyFF/badge.svg
    :target: https://pypi.python.org/pypi/pyFF/
    :alt: License
.. image:: https://requires.io/github/leifj/pyFF/requirements.svg?branch=master
     :target: https://requires.io/github/leifj/pyFF/requirements/?branch=master
     :alt: Requirements Status


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

Dependencies
============

* pyXMLSecurity
* PyKCS11 (optional)
