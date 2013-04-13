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

  # apt-get install build-essential python-dev libxml2-dev libxslt1-dev libyaml-dev

If you want to use OS packages instead of python packages from pypi then
consider also installing the following packages before you begin:

.. code-block:: bash

  # apt-get install python-lxml python-yaml python-eventlet python-setuptools

With Sitepackages
~~~~~~~~~~~~~~~~~

This method re-uses existing OS-level python packages. This means you'll have 
fewer worries keeping your python environment in sync with OS-level libraries.

.. code-block:: bash

  # apt-get install python-virtualenv
  # mkdir -p /opt/pyff
  # virtualenv /opt/pyff

Choose this method if you want the OS to keep as many of your packages up to
date for you.

Without Sitepackages
~~~~~~~~~~~~~~~~~~~~

This method keeps everything inside your virtualenv. Use this method if you
are developing pyFF or want to run multiple python-based applications in 
parallell without having to worry about conflicts between packages.

.. code-block:: bash

  # apt-get install python-virtualenv
  # mkdir -p /opt/pyff
  # virtualenv /opt/pyff --no-site-packages

Choose this method for maximum control - ideal for development setups.

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
aswell as pyXMLSecurity. This may take some time to complete. If there are no errors and if
you have the *pyff* binary in your **$PATH** you should be done.

Upgrading
---------

Unless you've made modifications, upgrading should be as simple as running 

.. code-block:: bash

  # . /opt/pyff/bin/activate
  # pip install -U pyff

This should bring your virtualenv up to the latest version of pyff and its
dependencies. You probably need to restart pyffd manually though.
