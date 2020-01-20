.. _quickstart-label:

Quick Start Instructions
========================

There are a lot of options and knobs in pyFF - in many ways pyFF is a toolchain that can be configured to
do a lot of tasks. In order to start exploring pyFF it is best to start with a simple example. Assuming
you have read the installation instructions and have created and activated a virtualenv with pyFF installed
do the following:

First create an empty directory and cd into it. In the directory create a file called edugain.fd with
the following contents:

.. code-block:: yaml

   - load:
      - http://mds.edugain.org
   - select:
   - stats:

Now run pyFF like this:

.. code-block:: bash

   # pyff edugain.fd

You should see output like this after a few seconds depending on the speed of your Internet connection 
you should see something like this:

.. code-block:: bash

  ---
  total size:     5568
  selected:       5567
            idps: 3079
             sps: 2487
  ---

Congratulations - you have successfully fetched, parsed, selected and printed stats for the edugain
metadata feed. This is of course not a useful example (probably) but it illustrates a few points 
about how pyFF works:

* pyFF configuration is (mostly) in the form of yaml files
* The yaml file reprsents a list of instructions which are processed in order
* The *load* statement retrieves (and parses) SAML metadata from edugain.org
* The *select* statement is used to form an *active document* on which subsequent instructions operate
* Finally, the stats statement prints out some information about the current active document.

Next we'll learn how to do more than print statistics.
