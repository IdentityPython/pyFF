Installation
============

Before you install
------------------

Make sure you have a reasonably modern python. pyFF is developed using 2.7 but 2.6
should work just fine. It is recommended that you install pyFF into a virtualenv
but there are two ways: with or without site packages.

For both methods start by installing a few basic OS packages. Here we illustrate
with commands for a debian/ubuntu install, similar commands using 'yum' exist for
Fedora or other rpm-based systems:

.. code-block:: bash

  # apt-get install build-essential libxml2-dev libxslt1-dev libyaml-dev

If you want to use OS packages instead of python packages from pypi then
consider installing the following packages before you begin:

* python-lxml
* python-yaml
* python-eventlet
* python-setuptools

With Sitepackages
~~~~~~~~~~~~~~~~~

This method re-uses existing OS-level python packages. This means you'll have 
fewer worries keeping your python environment in sync with OS-level libraries.

.. code-block:: bash

  # apt-get install python-virtualenv
  # mkdir -p /opt/pyff
  # virtualenv /opt/pyff

Without Sitepackages
~~~~~~~~~~~~~~~~~

This method keeps everything inside your virtualenv. Use this method if you
are developing pyFF or want to run multiple python-based applications in 
parallell without having to worry about conflicts between packages.

.. code-block:: bash

  # apt-get install python-virtualenv
  # mkdir -p /opt/pyff
  # virtualenv /opt/pyff --no-site-packages

Installing 
----------

Now that you have a virtualenv, its time to install pyFF into it. Start by 
activating your virtualenv:

.. code-block:: bash

  # . /opt/pyff/bin/activate

Next install pyFF:

.. code-block:: bash

  # pip install pyFF

This will install a bunch of dependencies and compile bindings for both lxml, pyyaml
aswell as xmlsec. This may take some time to complete. If there are no errors and if
you have the *pyff* binary in your path you should be done.
