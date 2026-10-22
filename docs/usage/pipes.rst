Pipes
=====

A pipeline is a YAML list of steps, called pipes. Each step is the name of a pipe, optionally
followed by options on the same line and arguments after the colon:

.. code-block:: yaml

    - load fail_on_error True:
        - http://example.com/metadata.xml
    - select
    - publish: /tmp/metadata.xml

This page is generated from the docstrings of the pipes in :py:mod:`pyff.builtins`.

.. pyff-pipes::
