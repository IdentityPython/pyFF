Using pyFF
=============

pyFF has two command-line tools: pyff and pyffd.

.. code-block:: bash

  # pyff --loglevel=INFO [pipeline.fd]+
  # pyffd --loglevel=INFO [pipeline.fd]+


pyFF operates by setting up and running "pipelines". Each pipeline starts with an empty "active repository" - an
in-memory representation of a set of SAML metadata documents - and an empty "working document" - a subset of the
EntityDescriptor elements in the active repository.

The pyffd tool starts a metadata server with an HTTP-based interface for viewing and downloading metadata. The
HTTP interface can produce *XML*, *HTML* and *JSON* output (as well as other formats with a bit of configuration) and
implements the MDX specification for online SAML metadata query.

To start the pyFF daemon

.. code-block:: bash

  # CACHE=-C
  # PYFF_LOGLEVEL=DEBUG
  # PYFF_UPDATE_FREQUENCY=28800
  # PYFF_HOST=0.0.0.0
  # PYFF_PORT=8080
  # PYFF_PIDFILE=/tmp/pyff.pid

  # pyffd -f ${CACHE} --loglevel=${PYFF_LOGLEVEL} --frequency=${PYFF_UPDATE_FREQUENCY} --host=${PYFF_HOST} --port=${PYFF_PORT} -p ${PYFF_PIDFILE} --proxy test_mdx.yaml

Pipeline files are *yaml* documents representing a list of processing steps:

.. code-block:: yaml

    - step1
    - step2
    - step3

Each step represents a processing instruction. pyFF has a library of built-in instructions to choose from that
include fetching local and remote metadata, xslt transforms, signing, validation and various forms of output and
statistics.

Processing steps are called pipes. A pipe can have arguments and options:

.. code-block:: yaml

    - step [option]*:
        - argument1
        - argument2
        ...

    - step [option]*:
        key1: value1
        key2: value2
        ...

Typically options are used to modify the behaviour of the pipe itself (think macros), while arguments provide
runtime data to operate on.

Documentation for each pipe is in the :py:mod:`pyff.pipes.builtins` Module. Also take a look at the :doc:`examples`.
