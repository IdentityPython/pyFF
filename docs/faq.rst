Frequently Asked Questions
=========================


I get 'select is empty' but I know my xpath should match. What is wrong?
------------------------------------------------------------------------

You may have forgotten to include namespaces in your xpath expression. For instance `//EntityDescriptor` won't 
match anything - `//md:EntityDescriptor` is what you want etc. PyFF is not a full XML processor and supports a 
set of well-known XML namespaces commonly used in SAML metadata by prefix only. The full list of prefixes can 
be found in :py:mod:`pyff.constants` 
