.. py:currentmodule:: pyff

Pipeline Options
================

This document outlines the available pipes that can be used in a pyFF pipeline configuration file. Each pipe is a step in the processing chain that can be used to load, select, transform, sign, or output SAML metadata.

.. contents::
   :local:

dump
----

Print a representation of the entities set on stdout. Useful for testing.

**Example**

.. code-block:: yaml

    - dump

map
---

Loop over the entities in a selection.

**Example**

.. code-block:: yaml

    - map:
       - ...statements...

Executes a set of statements in parallell (using a thread pool).

then
----

Call a named 'when' clause and return - akin to macro invocations for pyFF.

log_entity
----------

Log the request id as it is processed (typically the entity_id).

print
-----

Print whatever is in the active tree without transformation.

**Example**

.. code-block:: yaml

    - print:
        output: "somewhere.foo"

end
---

Exit with optional error code and message.

**Example**

.. code-block:: yaml

    - end
    - unreachable

**Warning**: This is very bad if used with pyffd - the server will stop running. If you just want to break out of the pipeline, use break instead.

fork
----

Make a copy of the working tree and process the arguments as a pipleline. This essentially resets the working tree and allows a new plumbing to run. Useful for producing multiple outputs from a single source.

**Example**

.. code-block:: yaml

    - select  # select all entities
    - fork:
        - certreport
        - publish:
             output: "/tmp/annotated.xml"
    - fork:
        - xslt:
             stylesheet: tidy.xml
        - publish:
             output: "/tmp/clean.xml"

The second fork in this example is strictly speaking not necessary since the main plumbing is still active but it may help to structure your plumbings this way.

**Merging**

Normally the result of the "inner" plumbing is disgarded - unless published or emit:ed to a calling client in the case of the MDX server - but by adding 'merge' to the options with an optional 'merge strategy' the behaviour can be changed to merge the result of the inner pipeline back to the parent working document.

The default merge strategy is 'replace_existing' which replaces each EntityDescriptor found in the resulting document in the parent document (using the entityID as a pointer). Any python module path ('a.mod.u.le:callable') ending in a callable is accepted. If the path doesn't contain a ':' then it is assumed to reference one of the standard merge strategies in pyff.merge_strategies.

For instance the following block can be used to set an attribute on a single entity:

.. code-block:: yaml

    - fork merge:
        - select: http://sp.example.com/shibboleth-sp
        - setattr:
            attribute: value

Note that unless you have a select statement before your fork merge you'll be merging into an empty active document which with the default merge strategy of replace_existing will result in an empty active document. To avoid this do a select before your fork, thus:

.. code-block:: yaml

    - select
    - fork merge:
        - select: http://sp.example.com/shibboleth-sp
        - setattr:
            attribute: value

**parsecopy**

Due to a hard to find bug, fork which uses deepcopy can lose some namespaces. The parsecopy argument is a workaround. It uses a brute force serialisation and deserialisation to get around the bug.

.. code-block:: yaml

    - select  # select all entities
    - fork parsecopy:
        - certreport
        - publish:
             output: "/tmp/annotated.xml"
    - fork:
        - xslt:
             stylesheet: tidy.xml
        - publish:
             output: "/tmp/clean.xml"

break
-----

Break out of a pipeline. This sets the 'done' request property to True which causes the pipeline to terminate at that point.

**Example**

.. code-block:: yaml

    - one
    - two
    - break
    - unreachable

pipe
----

Run the argument list as a pipleine. Unlike fork, pipe does not copy the working document but instead operates on the current active document. The done request property is reset to False after the pipeline has been processed. This allows for a classical switch/case flow using the following construction:

.. code-block:: yaml

    - pipe:
        - when a:
            - one
            - break
        - when b:
            - two
            - break

In this case if 'a' is present in the request state, then 'one' will be executed and the 'when b' condition will not be tested at all. Note that at the topmost level the pipe is implicit and may be left out.

.. code-block:: yaml

    - pipe:
        - one
        - two

is equivalent to

.. code-block:: yaml

    - one
    - two

when
----

Conditionally execute part of the pipeline. The inner pipeline is executed if the at least one of the condition values is present for the specified key in the request state.

**Example**

.. code-block:: yaml

    - when foo
        - something
    - when bar bill
        - other

The condition operates on the state: if 'foo' is present in the state (with any value), then the something branch is followed. If 'bar' is present in the state with the value 'bill' then the other branch is followed.

info
----

Dumps the working document on stdout. Useful for testing.

sort
----

Sorts the working entities by the value returned by the given xpath. By default, entities are sorted by 'entityID' when the 'order_by [xpath]' option is omitted and otherwise as second criteria. Entities where no value exists for a given xpath are sorted last.

**Options**

- ``order_by [xpath]``: xpath expression selecting to the value used for sorting the entities.

**Example**

.. code-block:: yaml

    - sort order_by [xpath]

publish
-------

Publish the working document in XML form. Publish takes one argument: path to a file where the document tree will be written.

**Example**

.. code-block:: yaml

    - publish: /tmp/idp.xml

The full set of options with their corresponding defaults:

.. code-block:: yaml

    - publish:
         output: output
         raw: false
         pretty_print: false
         urlencode_filenames: false
         hash_link: false
         update_store: true
         ext: .xml

If output is an existing directory, publish will write the working tree to a filename in the directory based on the @entityID or @Name attribute. Unless 'raw' is set to true the working tree will be serialized to a string before writing, with minimal formatting if 'pretty_print' is true (see 'indent' action for more extensive control). If true, 'hash_link' will generate a symlink based on the hash id (sha1) for compatibility with MDQ. Unless false, 'update_store' will cause the the current store to be updated with the published artifact. Setting 'ext' allows control over the file extension.

load
----

General-purpose resource fetcher. Supports both remote and local resources. Fetching remote resources is done in parallel using threads.

Note: When downloading remote files over HTTPS the TLS server certificate is not validated by default
Note: Default behaviour is to ignore metadata files or entities in MD files that cannot be loaded

**Options**

Defaults are marked with (*).

- ``max_workers <5>``: Number of parallel threads to use for loading MD files
- ``timeout <120>``: Socket timeout when downloading files
- ``validate <True*|False>``: When true downloaded metadata files are validated (schema validation)
- ``fail_on_error <True|False*>``: Control whether an error during download, parsing or (optional)validation of a MD file does not abort processing of the pipeline. When true a failure aborts and causes pyff to exit with a non zero exit code. Otherwise errors are logged but ignored.
- ``filter_invalid <True*|False>``: Controls validation behaviour. When true Entities that fail validation are filtered I.e. are not loaded. When false the entire metadata file is either loaded, or not. fail_on_error controls whether failure to validating the entire MD file will abort processing of the pipeline.
- ``verify_tls <True|False*>``: Controls the validation of the host's TLS certificate on fetching the resources

**Example**

.. code-block:: yaml

    - load fail_on_error True filter_invalid False:
      - http://example.com/some_remote_metadata.xml
      - local_file.xml
      - /opt/directory_containing_md_files/

select
------

Select a set of EntityDescriptor elements as the working document. Select picks and expands elements (with optional filtering) from the active repository you setup using calls to :py:mod:`pyff.pipes.builtins.load`. See :py:mod:`pyff.mdrepo.MDRepository.lookup` for a description of the syntax for selectors.

**Examples**

.. code-block:: yaml

    - select

This would select all entities in the active repository.

.. code-block:: yaml

    - select: "/var/local-metadata"

This would select all entities found in the directory /var/local-metadata. You must have a call to local to load entities from this directory before select statement.

.. code-block:: yaml

    - select: "/var/local-metadata!//md:EntityDescriptor[md:IDPSSODescriptor]"

This would selects all IdPs from /var/local-metadata

.. code-block:: yaml

    - select: "!//md:EntityDescriptor[md:SPSSODescriptor]"

This would select all SPs

Select statements are not cumulative - a select followed by another select in the plumbing resets the working documents to the result of the second select.

Most statements except local and remote depend on having a select somewhere in your plumbing and will stop the plumbing if the current working document is empty. For instance, running

.. code-block:: yaml

    - select: "!//md:EntityDescriptor[md:SPSSODescriptor]"

would terminate the plumbing at select if there are no SPs in the local repository. This is useful in combination with fork for handling multiple cases in your plumbings.

**Options**

Defaults are marked with (*).

- ``as <name>``: The 'as' keyword allows a select to be stored as an alias in the local repository. For instance

    .. code-block:: yaml

        - select as /foo-2.0: "!//md:EntityDescriptor[md:IDPSSODescriptor]"

    would allow you to use /foo-2.0.json to refer to the JSON-version of all IdPs in the current repository. Note that you should not include an extension in your "as foo-bla-something" since that would make your alias invisible for anything except the corresponding mime type.

- ``dedup <True*|False>``: Whether to deduplicate the results by entityID.

    Note: When select is used after a load pipe with more than one source, if dedup is set to True and there are entity properties that may differ from one source to another, these will be squashed rather than merged.

filter
------

Refines the working document by applying a filter. The filter expression is a subset of the select semantics and syntax.

**Example**

.. code-block:: yaml

    - filter:
        - "!//md:EntityDescriptor[md:SPSSODescriptor]"
        - "https://idp.example.com/shibboleth"

This would select all SPs and any entity with entityID "https://idp.example.com/shibboleth" from the current working document and return as the new working document. Filter also supports the "as <alias>" construction from select allowing new synthetic collections to be created from filtered documents.

pick
----

Select a set of EntityDescriptor elements as a working document but don't validate it. Useful for testing. See :py:mod:`pyff.pipes.builtins.select` for more information about selecting the document.

first
-----

If the working document is a single EntityDescriptor, strip the outer EntitiesDescriptor element and return it. Sometimes (eg when running an MDX pipeline) it is usually expected that if a single EntityDescriptor is being returned then the outer EntitiesDescriptor is stripped. This method does exactly that.

discojson
---------

Return a discojuice-compatible json representation of the tree. If the config.load_icons directive is set the icons will be returned from a (possibly persistent) local cache & converted to data: URIs.

**Example**

.. code-block:: yaml

    - discojson

discojson_sp
------------

Return a json representation of the trust information. The returned json doc will have the following structure.

The root is a dictionary, in which the keys are the entityID's of the SP entities that have trust information in their metadata, and the values are a representation of that trust information.

For the XML structure of the trust information see the XML Schema in this repo at ``/src/pyff/schema/saml-metadata-trustinfo-v1.0.xsd``.

For each SP with trust information, the representation of that information is as follows.

If there are MetadataSource elements, there will be a key 'extra_md' pointing to a dictionary of the metadata from those additional sources, with entityIDs as keys and entities (with the format provided by the discojson function above) as values.

Then there will be a key 'profiles' pointing to a dictionary in which the keys are the names of the trust profiles, and the values are json representations of those trust profiles.

Each trust profile will have the following keys.

If the trust profile includes a FallbackHandler element, there will be a key 'fallback_handler' pointing to a dict with 2 keys, 'profile' which by default is 'href', and handler which is a string, commonly a URL.

Then there will be an 'entity' key pointing to a list of representations of individual trusted/untrusted entities, each of them a dictionary, with 2 keys: 'entity_id' pointing to a string with the entityID, and 'include', pointing to a boolean.

Finally there will be a key 'entities' pointing to a list of representations of groups of trusted/untrusted entities, each of them a dictionary with 3 keys: a 'match' key pointing to the property of the entities by which they will be selected, by default 'registrationAuthority', a key 'select' with the value that will be used to select the 'match' property, and 'include', pointing to a boolean.

**Example**

.. code-block:: yaml

    - discojson_sp

discojson_sp_attr
-----------------

Return a json representation of the trust information. SP Entities can carry trust information as a base64 encoded json blob as an entity attribute with name `https://refeds.org/entity-selection-profile`. The schema of this json is the same as the one produced above from XML with the pipe `discojson_sp`, and published at: https://github.com/TheIdentitySelector/thiss-mdq/blob/master/trustinfo.schema.json

**Example**

.. code-block:: yaml

    - discojson_sp_attr

sign
----

Sign the working document. Sign expects a single dict with at least a 'key' key and optionally a 'cert' key. The 'key' argument references either a PKCS#11 uri or the filename containing a PEM-encoded non-password protected private RSA key. The 'cert' argument may be empty in which case the cert is looked up using the PKCS#11 token, or may point to a file containing a PEM-encoded X.509 certificate.

**PKCS11 URIs**

A pkcs11 URI has the form:

.. code-block:: xml

    pkcs11://<absolute path to SO/DLL>[:slot]/<object label>[?pin=<pin>]

The pin parameter can be used to point to an environment variable containing the pin: "env:<ENV variable>". By default pin is "env:PYKCS11PIN" which tells sign to use the pin found in the PYKCS11PIN environment variable. This is also the default for PyKCS11 which is used to communicate with the PKCS#11 module.

**Examples**

.. code-block:: yaml

    - sign:
        key: pkcs11:///usr/lib/libsofthsm.so/signer

This would sign the document using the key with label 'signer' in slot 0 of the /usr/lib/libsofthsm.so module. Note that you may need to run pyff with env PYKCS11PIN=<pin> .... for this to work. Consult the documentation of your PKCS#11 module to find out about any other configuration you may need.

.. code-block:: yaml

    - sign:
        key: signer.key
        cert: signer.crt

This example signs the document using the plain key and cert found in the signer.key and signer.crt files.

stats
-----

Display statistics about the current working document.

**Example**

.. code-block:: yaml

    - stats

summary
-------

Display a summary of the repository.

store
-----

Save the working document as separate files. Split the working document into EntityDescriptor-parts and save in directory/sha1(@entityID).xml. Note that this does not erase files that may already be in the directory. If you want a "clean" directory, remove it before you call store.

xslt
----

Transform the working document using an XSLT file. Apply an XSLT stylesheet to the working document. The xslt pipe takes a set of keyword arguments. The only required argument is 'stylesheet' which identifies the xslt resource. This is looked up either in the package or as a user-supplied file. The rest of the keyword arguments are made available as string parameters to the XSLT transform.

**Example**

.. code-block:: yaml

    - xslt:
        stylesheet: foo.xsl
        x: foo
        y: bar

indent
------

Transform the working document using proper indentation. Requires lxml >= 4.5.

**Example**

.. code-block:: yaml

    - indent:
        space: '    '

validate
--------

Validate the working document. Generate an exception unless the working tree validates. Validation is done automatically during publication and loading of metadata so this call is seldom needed.

prune
-----

Prune the active tree, removing all elements matching.

**Examples**

.. code-block:: yaml

    - prune:
        - .//{http://www.w3.org/2000/09/xmldsig#}Signature

This example would drop all Signature elements. Note the use of namespaces.

.. code-block:: yaml

    - prune:
        - .//{http://www.w3.org/2000/09/xmldsig#}Signature[1]

This example would drop the first Signature element only.

check_xml_namespaces
--------------------

Ensure that all namespaces are http or httpd scheme URLs.

drop_xsi_type
-------------

Remove all xsi namespaces from the tree.

certreport
----------

Generate a report of the certificates (optionally limited by expiration time or key size) found in the selection.

**Example**

.. code-block:: yaml

    - certreport:
         error_seconds: 0
         warning_seconds: 864000
         error_bits: 1024
         warning_bits: 2048

For key size checking this will report keys with a size *less* than the size specified, defaulting to errors for keys smaller than 1024 bits and warnings for keys smaller than 2048 bits. It should be understood as the minimum key size for each report level, as such everything below will create report entries.

Remember that you need a 'publish' or 'emit' call after certreport in your plumbing to get useful output. PyFF ships with a couple of xslt transforms that are useful for turning metadata with certreport annotation into HTML.

emit
----

Returns a UTF-8 encoded representation of the working tree. Renders the working tree as text and sets the digest of the tree as the ETag. If the tree has already been rendered as text by an earlier step the text is returned as utf-8 encoded unicode. The mimetype (ctype) will be set in the Content-Type HTTP response header.

**Example**

.. code-block:: yaml

    - emit application/xml:
    - break

signcerts
---------

Logs the fingerprints of the signing certs found in the current working tree. Useful for testing.

**Example**

.. code-block:: yaml

    - signcerts

finalize
--------

Prepares the working document for publication/rendering. Set Name, ID, cacheDuration and validUntil on the toplevel EntitiesDescriptor element of the working document. Unless explicitly provided the @Name is set from the request URI if the pipeline is executed in the pyFF server. The @ID is set to a string representing the current date/time and will be prefixed with the string provided, which defaults to '_'. The @cacheDuration element must be a valid xsd duration (eg PT5H for 5 hrs) and @validUntil can be either an absolute ISO 8601 time string or (more commonly) a relative time in the form:

.. code-block:: none

    \+?([0-9]+d)?\s*([0-9]+h)?\s*([0-9]+m)?\s*([0-9]+s)?

For instance +45d 2m results in a time delta of 45 days and 2 minutes. The '+' sign is optional.

If operating on a single EntityDescriptor then @Name is ignored (cf :py:mod:`pyff.pipes.builtins.first`).

**Example**

.. code-block:: yaml

    - finalize:
        cacheDuration: PT8H
        validUntil: +10d
        ID: pyff

reginfo
-------

Sets registration info extension on EntityDescription element. Transforms the working document by setting the specified attribute on all of the EntityDescriptor elements of the active document.

**Example**

.. code-block:: yaml

    - reginfo:
       [policy:
            <lang>: <registration policy URL>]
       authority: <registrationAuthority URL>

pubinfo
-------

Sets publication info extension on EntityDescription element. Transforms the working document by setting the specified attribute on all of the EntityDescriptor elements of the active document.

**Example**

.. code-block:: yaml

    - pubinfo:
       publisher: <publisher URL>

setattr
-------

Sets entity attributes on the working document. Transforms the working document by setting the specified attribute on all of the EntityDescriptor elements of the active document. Normally this would be combined with the 'merge' feature of fork to add attributes to the working document for later processing.

**Example**

.. code-block:: yaml

    - setattr:
        attr1: value1
        attr2: value2
        ...

nodecountry
-----------

Sets eidas:NodeCountry. Transforms the working document by setting NodeCountry. Normally this would be combined with the 'merge' feature of fork or in a cleanup pipline to add attributes to the working document for later processing.

**Example**

.. code-block:: yaml

    - nodecountry:
        country: XX
