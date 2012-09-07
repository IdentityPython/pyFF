Using pyFF
=============

pyFF has a single command-line tool: pyff.

.. code-block:: bash

  # pyff --loglevel=INFO pipeline.fd [pipeline2.fd]


pyff operates by setting up and running "pipelines". Each pipeline starts with an empty "active repository" - an
in-memory representation of a set of SAML metadata documents - and an empty "working document" - a subset of the
EntityDescriptor elements in the active repository.

Pipeline files are *yaml* document representing a list of processing steps:

.. code-block:: yaml

    - step1
    - step2
    - step3

Each step represents a processing instruction. pyFF has a library of built-in instructions to choose from that
include fetching local and remote metadata, xslt transforms, signing, validation and various forms of output and
statistics.

Processing steps are called pipes. Many pipes take arguments. For instance the sign pipe takes the key and certificate
as arguments.

Documentation for each pipe is in :ref:api/pyff.pipes