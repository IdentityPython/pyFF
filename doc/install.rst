Installation
============

Before you install
------------------

Make sure you have a reasonably modern python. pyFF is developed using 2.7 but 2.6
should work just fine. It is recommended that you install pyFF into a virtualenv:

.. code-block:: bash

  # apt-get install python-virtualenv
  # mkdir -p /opt/pyff
  # virtualenv /opt/pyff --no-site-packages

You also need to install a couple of requisite libraries needed for XML processing
plus a basic toolchain for compling c/c++ code (which is needed for some of the 
python packages that pyFF uses, notably lxml):

.. code-block:: bash

  # apt-get install build-essential libxml2-dev libxslt1-dev libxmlsec1-dev libyaml-dev

Installing 
----------

Start by activating your virtualenv:

.. code-block:: bash

  # . /opt/pyff/bin/activate

Next install pyFF:

.. code-block:: bash

  # pip install pyFF

This will install a bunch of dependencies and compile bindings for both lxml, pyyaml
aswell as xmlsec. This may take some time to complete. If there are no errors and if
you have the *pyff* binary in your path you should be done.
