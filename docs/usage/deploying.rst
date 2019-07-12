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

Running pyFF in production
--------------------------

There are several aspects to consider when deploying pyFF in production. Sometimes you want to 
emphasize simplicity and then you can simply run a pyFF instance and combine with a management
application (eg mdq-browser) and a discovery service to quickly setup a federation hub. This
model is suitable if you are setting up a collaboration hub or an SP proxy that needs to keep
track of a local metadata set along with a matching discovery service.

Scenario 1: all-in-one
~~~~~~~~~~~~~~~~~~~~~~

If you are using docker you might deploy something like that using docker-compose (or something
similar implemented using k8s etc). Assuming your.public.domain is the public address of the
service you wish to deploy the follwoing compose file would give you a discovery service on
port 80 and an admin UI on port 8080.

.. code-block:: yaml

  version: "3"
  services:
     mdq-browser:
        image: docker.sunet.se/mdq-browser:1.0.1
        container_name: mdq_browser
        ports:
           - "8080:80"
        environment:
           - MDQ_URL=http://pyff
           - PYFF_APIS=true
     thiss:
        image: docker.sunet.se/thiss-js:1.0.0
        container_name: thiss
        ports:
           - "80:80"
        environment:
           - MDQ_URL=http://pyff/entities/
           - BASE_URL=https://your.public.domain
           - STORAGE_DOMAIN=your.public.domain
           - SEARCH_URL=http://pyff/api/search
     pyff:
        image: docker.sunet.se/pyff:stable
        container_name: pyff-api


Scenario 2: offline signing
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Sometimes security is paramount and it may be prudent to firewall the signing keys for your
identity federation but you still want to provide a scalable MDQ service. The MDQ specification
doesn't actually require online access to the signing key. It is possible to create an MDQ 
service that only consists of static files served from a simple webserver or even from a CDN.

The pyFF wsgi server implements the webfinger protocol as described in :rfc:`7033` and this 
endpoint can be use to list all objects in the MDQ server. A simple script provided in the 
scripts directory of the pyFF distribution uses webfinger and wget to make an isomorphic 
copy of the pyFF instance.

# Run an instance of pyff on a firewalled system with access to the signing keys - eg via an HSM
# Use the script to mirror the pyFF instance to a local directory and copy that directory over 
to the public webserver or CDN

.. code-block:: bash

  # docker run -d -p 8080:8080 pyff:1.1.0
  # docker run -ti pyff:1.1.0 mirror-mdq.sh -A http://localhost:8080/ /some/dir

This will create an offline copy of http://localhost:8080/ in /some/dir. You can use rsync+ssh
syntax instead (eg user@host:/some/dir) to make a copy to a remote host using rsync+ssh. This
way it is possible to have a lot of control over how metadata is generated and published while
at the same time providing a scalable public interface to your metadata feed.

Currently the script traverses all objects in the pyFF instance everytime it is called so 
allow for enough time to sign every object when you setup your mirror cycle.
