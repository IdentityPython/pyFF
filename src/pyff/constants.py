"""
Useful constants for pyFF. Mostly XML namespace declarations.
"""
__author__ = 'leifj'

NF_URI="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"

NS={"md": "urn:oasis:names:tc:SAML:2.0:metadata",
    'ds': 'http://www.w3.org/2000/09/xmldsig#',
    'mdui': "urn:oasis:names:tc:SAML:metadata:ui",
    'mdattr': "urn:oasis:names:tc:SAML:metadata:attribute",
    'mdrpi': "urn:oasis:names:tc:SAML:metadata:rpi",
    'xrd': 'http://docs.oasis-open.org/ns/xri/xrd-1.0',
    'saml': "urn:oasis:names:tc:SAML:2.0:assertion"}

ATTRS = {'collection': 'http://pyff-project.org/collection',
         'entity-category': 'http://macedir.org/entity-category',
         'role': 'http://pyff-project.org/role'}

DIGESTS = ['sha1','md5','null']