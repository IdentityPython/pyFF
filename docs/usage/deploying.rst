Deploying pyFF
==============

Running pyFF in docker
----------------------

Building a docker image
~~~~~~~~~~~~~~~~~~~~~~~

There is a build environment for docker available at https://github.com/SUNET/docker-pyff. In order to 
build your own docker image, clone this repository and use `make` to build the latest version of pyFF:

.. code-block:: bash

  # git clone https://github.com/SUNET/docker-pyff
  ...
  # cd docker-pyff
  # make 

At the end of this you should be able to run pyff:<version> where <version> will depend on what is
currently the latest supported version. Sometimes a version of docker is uploaded to dockerhub but
there is no guarantee that those are current or even made by anyone affiliated with the pyFF project.

Running the docker image
~~~~~~~~~~~~~~~~~~~~~~~~

The docker image is based on debian:stable and contains a full install of pyFF along with most of the
optional components including PyKCS11. If you start pyFF with no arguments it launches a default 
pipeline that fetches edugain and exposes it as an MDQ server: 

.. code-block:: bash

  # docker run -ti -p 8080:8080 

A pyFF MDQ service should now be exposed on port 8080. If you are running the old pyFF 1.x branch
you may also have access to the default admin interface. If you are running pyFF 2.x you can now
point an MDQ frontend to to port 8080 - eg `mdq-browser`.
