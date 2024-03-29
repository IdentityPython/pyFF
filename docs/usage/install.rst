Installation
============

Before you install
------------------

Make sure you have a reasonably modern python. pyFF is developed using 3.6 but 3.7 will
probably become the norm soon. It is recommended that you install pyFF into a virtualenv

Start by installing some basic OS packages. For a debian/ubuntu install:

.. code-block:: bash

  # apt-get install build-essential python-dev libxml2-dev libxslt1-dev libyaml-dev

and if you're on a centos system (or other yum-based systems):

.. code-block:: bash

  # yum install python-devel  libxml2-devel libxslt-devel libyaml-devel
  # pip install pyyaml
  # yum install make gcc kernel-devel kernel-headers glibc-headers

If you want to use OS packages instead of python packages from pypi then consider also 
installing the following packages before you begin:

With Sitepackages
~~~~~~~~~~~~~~~~~

This method re-uses existing OS-level python packages. This means you'll have fewer worries 
keeping your python environment in sync with OS-level libraries.

.. code-block:: bash

  # apt-get install python-virtualenv
  # virtualenv python-pyff

Choose this method if you want the OS to keep as many of your packages up to date for you.

Without Sitepackages
~~~~~~~~~~~~~~~~~~~~

This method keeps everything inside your virtualenv. Use this method if you are developing 
pyFF or want to run multiple python-based applications in parallell without having to worry 
about conflicts between packages.

.. code-block:: bash
  
  # cd $HOME
  # apt-get install python-virtualenv
  # virtualenv -p python3 python-pyff --no-site-packages

Choose this method for maximum control - ideal for development setups.


Verifying
----------

To verify that python 3.6 is the default python in the pyFF environment run

.. code-block:: bash

  # python --version

The result should be Python 3.6 or later.

To verify that the version of pip you have is the latest run.

.. code-block:: bash
  
 # pip install --upgrade pip

Installing 
----------

Now that you have a virtualenv, its time to install pyFF into it. Start by 
activating your virtualenv:

.. code-block:: bash

  # source python-pyff/bin/activate

Next install pyFF:

.. code-block:: bash

  # cd $HOME
  # cd pyFF
  # LANG=en_US.UTF-8 pip install -e .

This will install a bunch of dependencies and compile bindings for both lxml, pyyaml
as well as pyXMLSecurity. This may take some time to complete. If there are no errors and if
you have the *pyff* binary in your **$PATH** you should be done.

.. code-block:: bash

 # cd $HOME
 # mkdir pyff-config
 # cd pyff-config

Upgrading
---------

Unless you've made modifications, upgrading should be as simple as running 

.. code-block:: bash

  # source python-pyff/bin/activate
  # pip install -U pyff

This should bring your virtualenv up to the latest version of pyff and its dependencies. You probably 
need to restart pyffd manually though.

Next Steps
----------

Now that you hopefully have a working installation of pyFF you are ready to start exploring all the
ways pyFF can help you manage metadata. It may be good to go read the :ref:`quickstart-label` now but
in general pyFF should be run in the same directory that contains a pipeline in *yaml* format and 
depending on the nature of the pipeline additional files may be needed including things like...

- A list of metadata URLs.
- A set of files containing metadata URLs - eg *XRD* or *MDSL* files.
- A *key*  and *crt* signing key pair which can be generated from *genkey.sh* in the scripts directory.

