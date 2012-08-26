#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright ©2011 Andrew D. Yates
# andrewyates.name@gmail.com
"""Parse x509 PEM Certificates.

The objective of this script is to parse elements from x509
certificates in PEM binary format which use RSA cryptographic keys for
use in XML digital signature (xmldsig) signatures and
verification. Much of this module has been adapted from the pyasn1
source code example "pyasn1/examples/x509.py" [pyasn1].

USE:

>>> data = open("cert.pem").read()
... dict = x509_pem.parse(data)
... n, e = dict['modulus'], dict['publicExponent']
... subject = dict['subject']

REFERENCES:

pyasn1
"ASN.1 tools for Python"
http://pyasn1.sourceforge.net/

RFC5480
"Elliptic Curve Cryptography Subject Public Key Information"
http://www.ietf.org/rfc/rfc5480.txt

X500attr
"2.5.4 - X.500 attribute types"
http://www.alvestrand.no/objectid/2.5.4.html

X500email
"1.2.840.113549.1.9.1 - e-mailAddress"
http://www.alvestrand.no/objectid/1.2.840.113549.1.9.1.html
"""
import re

from pyasn1.type import tag,namedtype,namedval,univ,constraint,char,useful
from pyasn1.codec.der import decoder, encoder
from pyasn1 import error

from sequence_parser import SequenceParser


MAX = 64
CERT_FILE = "keys/cacert_pass_helloworld.pem"

RSA_ID = "1.2.840.113549.1.1.1"
RSA_SHA1_ID = "1.2.840.113549.1.1.5"

RX_PUBLIC_KEY = re.compile("subjectPublicKey='([01]+)'B")
RX_SUBJECT = re.compile(" +subject=Name:.*?\n\n\n", re.M | re.S)
RX_SUBJECT_ATTR = re.compile("""
RelativeDistinguishedName:.*?
type=(\S+).*?
AttributeValue:\n\s+?
[^=]+=([^\n]*)\n
""", re.M | re.S | re.X)

# abbreviated code map
X500_CODE_MAP = {
  '2.5.4.3':  'CN',            # commonName
  '2.5.4.6':  'C',             # countryName
  '2.5.4.7':  'L',             # localityName (City)
  '2.5.4.8':  'ST',            # stateOrProvinceName (State)
  '2.5.4.9':  'STREET',        # streetAddress
  '2.5.4.10': 'O',             # organizationName
  '2.5.4.11': 'OU',            # organizationalUnitName
  '2.5.4.12': 'T',             # title
  '1.2.840.113549.1.9.1': 'E', # e-mailAddress
  }


class DirectoryString(univ.Choice):
  componentType = namedtype.NamedTypes(
    namedtype.NamedType('teletexString', char.TeletexString().subtype(subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),
    namedtype.NamedType('printableString', char.PrintableString().subtype(subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),
    namedtype.NamedType('universalString', char.UniversalString().subtype(subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),
    namedtype.NamedType('utf8String', char.UTF8String().subtype(subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),
    namedtype.NamedType('bmpString', char.BMPString().subtype(subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),
    namedtype.NamedType('ia5String', char.IA5String().subtype(subtypeSpec=constraint.ValueSizeConstraint(1, MAX)))
    )

class AttributeValue(DirectoryString): pass

class AttributeType(univ.ObjectIdentifier): pass

class AttributeTypeAndValue(univ.Sequence):
  componentType = namedtype.NamedTypes(
    namedtype.NamedType('type', AttributeType()),
    namedtype.NamedType('value', AttributeValue())
    )

class RelativeDistinguishedName(univ.SetOf):
  componentType = AttributeTypeAndValue()

class RDNSequence(univ.SequenceOf):
  componentType = RelativeDistinguishedName()

class Name(univ.Choice):
  componentType = namedtype.NamedTypes(
    namedtype.NamedType('', RDNSequence())
    )
                          
class AlgorithmIdentifier(univ.Sequence):
  componentType = namedtype.NamedTypes(
    namedtype.NamedType('algorithm', univ.ObjectIdentifier()),
    namedtype.OptionalNamedType('parameters', univ.Null())
    )

class Extension(univ.Sequence):
  componentType = namedtype.NamedTypes(
    namedtype.NamedType('extnID', univ.ObjectIdentifier()),
    namedtype.DefaultedNamedType('critical', univ.Boolean('False')),
    namedtype.NamedType('extnValue', univ.OctetString())
    )

class Extensions(univ.SequenceOf):
  componentType = Extension()
  sizeSpec = univ.SequenceOf.sizeSpec + constraint.ValueSizeConstraint(1, MAX)

class SubjectPublicKeyInfo(univ.Sequence):
  componentType = namedtype.NamedTypes(
    namedtype.NamedType('algorithm', AlgorithmIdentifier()),
    namedtype.NamedType('subjectPublicKey', univ.BitString())
    )

class UniqueIdentifier(univ.BitString): pass

class Time(univ.Choice):
  componentType = namedtype.NamedTypes(
    namedtype.NamedType('utcTime', useful.UTCTime()),
    namedtype.NamedType('generalTime', useful.GeneralizedTime())
    )
    
class Validity(univ.Sequence):
  componentType = namedtype.NamedTypes(
    namedtype.NamedType('notBefore', Time()),
    namedtype.NamedType('notAfter', Time())
    )

class CertificateSerialNumber(univ.Integer): pass

class Version(univ.Integer):
  namedValues = namedval.NamedValues(
    ('v1', 0), ('v2', 1), ('v3', 2)
    )

class TBSCertificate(univ.Sequence):
  componentType = namedtype.NamedTypes(
    namedtype.DefaultedNamedType('version', Version('v1', tagSet=Version.tagSet.tagExplicitly(tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)))),
    namedtype.NamedType('serialNumber', CertificateSerialNumber()),
    namedtype.NamedType('signature', AlgorithmIdentifier()),
    namedtype.NamedType('issuer', Name()),
    namedtype.NamedType('validity', Validity()),
    namedtype.NamedType('subject', Name()),
    namedtype.NamedType('subjectPublicKeyInfo', SubjectPublicKeyInfo()),
    namedtype.OptionalNamedType('issuerUniqueID', UniqueIdentifier().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
    namedtype.OptionalNamedType('subjectUniqueID', UniqueIdentifier().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))),
    namedtype.OptionalNamedType('extensions', Extensions().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)))
    )

class Certificate(univ.Sequence):
  componentType = namedtype.NamedTypes(
    namedtype.NamedType('tbsCertificate', TBSCertificate()),
    namedtype.NamedType('signatureAlgorithm', AlgorithmIdentifier()),
    namedtype.NamedType('signatureValue', univ.BitString())
    )

  def dict(self):
    """Return simple dictionary of key elements as simple types.

    Note: this only returns the RSA Public key information for this certificate.

    Returns:
      {str, value} where `value` is simple type like `long`
    """
    dict = {}

    # hack directly from prettyPrint
    # we just want to verify that this is RSA-SHA1 and get the public key
    text = self.prettyPrint()
    if not (RSA_ID in text or RSA_SHA1_ID in text):
      raise NotImplementedError("Only RSA-SHA1 X509 certificates are supported.")
    # rip out public key binary
    bits = RX_PUBLIC_KEY.search(text).group(1)
    binhex = hex(int(bits, 2))[2:-1]
    bin = binhex.decode("hex")

    # Get X509SubjectName string
    # fake this for now; generate later using RX
    dict['subject'] = 'SubjectName'

    # reparse RSA Public Key PEM binary
    pubkey = RSAPublicKey()
    key = decoder.decode(bin, asn1Spec=pubkey)[0]
    dict.update(key.dict())
    
    return dict


class RSAPublicKey(SequenceParser):
  componentType = namedtype.NamedTypes(
    namedtype.NamedType('modulus', univ.Integer()),
    namedtype.NamedType('publicExponent', univ.Integer())
    )


def rfc2253_name(map):
  """Return subjectName formatted string from list of pairs.

  Args:
    map: [(str, str)] pairs such that:
      (str, str) = ([x.500 attribute type], value)
  Returns:
    str of rfc2253 formmated name

  Example:
   map = [('2.5.4.3', 'Kille, Steve'), ('2.5.4.10', 'Isode')
   returs: "CN=Kille\, Steve,O=Isode"
  """
  pairs = []
  for code, value in map:
    s = "%s=%s" % (X500_CODE_MAP[code], value.replace(',','\,'))
    pairs.append(s)
  name = ','.join(pairs)
  return name

  
def parse(data):
  """Return elements from parsed X509 certificate data.

  Args:
    data: str of X509 certificate file contents
  Returns:
    {str: value} of notable certificate elements s.t.:
      ['modulus'] = int of included RSA public key
      ['publicExponent'] = int of included RSA public key
      ['subject'] = str of compiled subject in rfc2253 format
      ['body'] = str of X509 DER binary in base64
      ['type'] = str of "X509 PRIVATE"
  """
  # initialize empty return dictionary
  dict = {}
  
  lines = []
  for s in data.splitlines():
    if '-----' == s[:5] and "BEGIN" in s:
      if not "CERTIFICATE" in s:
        raise NotImplementedError(\
          "Only PEM Certificates are supported. Header: %s", s)
    else:
      # include this b64 data for decoding
      lines.append(s.strip())


  body = ''.join(lines)
  raw_data = body.decode("base64")

  cert = decoder.decode(raw_data, asn1Spec=Certificate())[0]

  # dump parsed PEM data to text
  text = cert.prettyPrint()
  
  # GET RSA KEY
  # ===========
  if not (RSA_ID in text):
    raise NotImplementedError("Only RSA X509 certificates are supported.")
  # rip out RSA public key binary
  key_bits = RX_PUBLIC_KEY.search(text).group(1)
  key_binhex = hex(int(key_bits, 2))[2:-1]
  key_bin = key_binhex.decode("hex")
  # reparse RSA Public Key PEM binary
  key = decoder.decode(key_bin, asn1Spec=RSAPublicKey())[0]
  # add RSA key elements to return dictionary
  dict.update(key.dict())

  # GET CERTIFICATE SUBJECT
  # =======================
  subject_text = RX_SUBJECT.search(text).group(0)
  attrs = RX_SUBJECT_ATTR.findall(subject_text)
  dict['subject'] = rfc2253_name(attrs)

  # add base64 encoding and type to return dictionary
  dict['body'] = body
  dict['type'] = "X509 CERTIFICATE"

  return dict


def dict_to_tuple(dict):
  """Return RSA PyCrypto tuple from parsed X509 dict with public RSA key.

  Args:
    dict: dict of {str: value} returned from `parse`
  Returns:
    tuple of (int) of RSA public key integers for PyCrypto key construction
  """
  tuple = (
    dict['modulus'],
    dict['publicExponent'],
    )
  return tuple
