Running pyFF
============

There are two ways to use pyFF: 

# a "batch" command-line tool called pyff
# a wsgi application you can use with your favorite wsgi server - eg gunicorn

In either case you need to provide some configuration and a *pipeline* - instructions to tell pyFF what to do - in order for anything
intersting to happen. In the :ref:`quickstart-label` guide you saw how pyFF pipelines are constructed by creating yaml files. The full
set of piplines is documented in :py:mod:`pyff.builtins`. When you run pyFF in batch-mode you typically want a fairly simple pipline
that loads & transforms metadata and saves some form of output format.

Batch mode: pyff
----------------

The typical way to run pyFF in batch mode is something like this:

.. code-block:: bash

  # pyff [--loglevel=<DEBUG|INFO|WARN|ERROR>] pipeline.yaml

For various historic reasons the yaml files in the examples directory all have the '.fd' extension but pyFF doesn't care how you name
your pipeline files as long as they contain valid yaml.

This is in many ways the easiest way to run pyFF but it is also somewhat limited - eg it is not possible to produce an MDQ server 
using this method.

WSGI application: pyffd
-----------------------

Development of pyFF uses gunicorn to test but othe wsgi servers (eg apache mod-wsgi etc) should work equally well. Since all 
configuration of pyFF can be done using environment variables (cf :ref:`pyff.constants:Config`) it is pretty easy to integrate
in most environments.

Running pyFFd using gunicorn goes something like this (incidentally this is also how the standard docker-image launches pyFFd):

.. code-block:: bash

  # gunicorn --workers=1 --preload --bind 0.0.0.0:8080 -e PYFF_PIPELINE=pipeline.yaml --threads 4 --worker-tmp-dir=/dev/shm  pyff.wsgi:app

The wsgi app is a lot more sophisticated than batch-mode and in particular interaction with workers/threads in gunicorn can be 
a bit unpredictable depending on which implementation of the various interfaces (metadata stores, schedulers, caches etc) you
choose. It is usually easiest to use a single worker and multiple threads - at least until you know what you're doing.

The example above would launch the pyFF wsgi app on port 8080. However using pyFF in this way requires that you structure your
pipeline a bit differently. In the name of flexibility, most of the request processing (with the exception of a few APIs such 
as webfinger and search which are always available) of the pyFF wsgi app is actually delegated to the pipeline. Lets look at
a basic example:

.. code-block:: yaml

  - when update:
    - load:
        - http://mds.edugain.org
  - when request:
    - select:
    - pipe:
        - when accept application/samlmetadata+xml application/xml:
            - first
            - finalize:
                cacheDuration: PT12H
                validUntil: P10D
            - sign:
                key: sign.key
                cert: sign.crt
            - emit application/samlmetadata+xml
            - break
        - when accept application/json:
            - discojson
            - emit application/json
            - break


Lets pick this pipeline apart. First notice the two *when* instructions. The :ref:`pyff.builtins:when` pipe is used to 
conditionally execute a set of instructions. There is essentially only one type of condition. When processing a pipeline
pyFF keeps a state variable (a dict-like object) which changes as the instructions are processed. When the pipeline is
launched the state is initialized with a set of key-value pairs used to control execution of the pipeline.

There are a few pre-defined states, in this case we're dealing with two: the execution mode `update` or `request` (we'll
get to that one later) or the `accept` state used to implement content negotiation in the pyFF wsgi app. In fact there are
two ways to express a condition for `when`: with one parameter in which case the condition evaluates to `True` iff the 
parameter is present as a key in the state object, or with two parameters in which case the condition evaluates to `True`
iff the parameter is present and has the prescribed value.

Looking at our example the first when clause evaluates to `True` when `update` is present in state. This happens when
pyFF is in an update loop. The other when clause gets triggered when `request` is present in state which happens when
pyFF is processing an incoming HTTP request.

There 'update' state name is only slightly "magical" - you could call it "foo" if you like. The way to trigger any 
branch like this is to POST to the `/api/call/{state}` endpoint (eg using cURL) like so:

.. code-block:: bash
  
  # curl -XPOST -s http://localhost:8080/api/call/update

This will trigger the update state (or foo if you like). You can have any number of entry-points like this in your
pipeline and trigger them from external processes using the API. The result of the pipeline is returned to the caller
(which means it is probably a good idea to use the `-t` option to gunicorn to increase the worker timeout a bit).

The `request` state is triggered when pyFF gets an incoming request on any of the URI contexts other than
`/api` and `/.well-known/webfinger`, eg the main MDQ context `/entities`. This is typically where you do most of 
the work in a pyFF MDQ server. 

The example above uses the `select` pipe (:py:func:`pyff.builtins.select`) to setup an active document. When in 
request mode pyFF provides parameters for the request call by parsing the query parameters and URI path of the
request according to the MDQ specification. Therefore the call to `select` in the pipeline above, while it may
appear to have no parameters, is actually "fed" from the request processing of pyFF.

The subsequent calls to `when` implements content negotiation to provide a discojuice and XML version of the 
metadata depending on what the caller is asking for. This is key to using pyFF as a backend to the thiss.io discovery 
service. More than one content type may be specified to accommodate noncompliant MDQ clients.

The rest of the XML "branch" of the pipeline should be pretty easy to understand. First we use the 
:py:func:`pyff.builtins.first` pipe to ensure that we only return a single EntityDescriptor if our select
match a single object. Next we set cacheDuration and validUntil parameters and sign the XML before returning it.

The rest of the JSON "branch" of the pipeline is even simpler: transform the XML in the active document to
discojson format and return with the correct Content-Type.

The structure of a pipeline
---------------------------

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
runtime data to operate on. Documentation for each pipe is in the :py:mod:`pyff.builtins` Module. Also take a 
look at the :doc:`examples`.


