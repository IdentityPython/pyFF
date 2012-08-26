
__author__ = 'leifj'

import os
import rsa_x509_pem
import lxml.etree as etree
import logging
from pyff.constants import NS
import base64
import hashlib
import copy
import int_to_bytes as itb

# SHA1 digest with ASN.1 BER SHA1 algorithm designator prefix [RSA-SHA1]
PREFIX = '\x30\x21\x30\x09\x06\x05\x2B\x0E\x03\x02\x1A\x05\x00\x04\x14'

TRANSFORM_ENVELOPED_SIGNATURE = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
TRANSFORM_C14_EXC = "http://www.w3.org/2001/10/xml-exc-c14n"
TRANSFORM_C14_EXC_WITH_COMMENTS = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"

# This code was inspired by https://github.com/andrewdyates/xmldsig
# and includes https://github.com/andrewdyates/rsa_x509_pem with
# permission from the author.

class XMLSigException(Exception):
    pass

def _find_matching_cert(t,fp):
    for cd in t.findall(".//{%s}X509Certificate" % NS['ds']):
        fp = fp.lower().replace(":","")
        cert_pem = cd.text
        cert_der = base64.b64decode(cert_pem)
        m = hashlib.sha1()
        m.update(cert_der)
        fingerprint = m.hexdigest().lower()
        if fingerprint == fp:
            return cert_pem
    return None

def number_of_bits(num):
    assert num>=0
    nbits = 1
    max = 2
    while max<=num:
        nbits += 1
        max += max
    return nbits

def sign(t,key,cert):
    pass

b64d = lambda s: s.decode('base64')

def b64e(s):
    if type(s) in (int, long):
        s = itb.int_to_bytes(s)
    return s.encode('base64').replace('\n', '')

def _signed_value(data, key_size):
    """Return unencrypted rsa-sha1 signature value `padded_digest` from `data`.

    The resulting signed value will be in the form:
    (01 | FF* | 00 | prefix | digest) [RSA-SHA1]
    where "digest" is of the generated c14n xml for <SignedInfo>.

    Args:
      data: str of bytes to sign
      key_size: int of key length in bits; => len(`data`) + 3
    Returns:
      str: rsa-sha1 signature value of `data`
    """

    asn_digest = PREFIX + data

    # Pad to "one octet shorter than the RSA modulus" [RSA-SHA1]
    # WARNING: key size is in bits, not bytes!
    padded_size = key_size/8 - 1
    pad_size = padded_size - len(asn_digest) - 2
    pad = '\x01' + '\xFF' * pad_size + '\x00'
    padded_digest = pad + asn_digest

    return padded_digest

def _digest(str,hash_alg):
    h = getattr(hashlib,hash_alg)()
    h.update(str)
    digest = b64e(h.digest())
    return digest

def _process_references(t,sig=None):
    if sig is None:
        sig = t.find(".//{%s}Signature" % NS['ds'])
    for ref in sig.findall(".//{%s}Reference" % NS['ds']):
        object = None
        uri = ref.get('URI',None)
        if uri is not None or uri == '#' or uri == '':
            ct = copy.deepcopy(t)
            object = ct.getroot()
        else:
            raise ValueError("unknown reference %s" % uri)

        for tr in ref.findall(".//{%s}Transform" % NS['ds']):
            object = _transform(tr.get('Algorithm',None),object)

        dm = ref.find(".//{%s}DigestMethod" % NS['ds'])
        if dm is None:
            raise ValueError("Unable to find DigestMethod")
        hash_alg = (dm.get('Algorithm').split("#"))[1]
        logging.debug("using hash algorithm %s" % hash_alg)
        digest = _digest(object,hash_alg)
        logging.debug("digest for %s: %s" % (uri,digest))
        dv = ref.find(".//{%s}DigestValue" % NS['ds'])
        logging.debug(etree.tostring(dv))
        dv.text = digest

def _cert(sig,keyspec):
    data = None
    if os.path.isfile(keyspec):
        with open(keyspec) as c:
            data = c.read()
    elif ':' in keyspec:
        cd = _find_matching_cert(sig,keyspec)
        if cd is not None:
            data = "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----" % cd
    else:
        data = keyspec

    if data is None:
        raise ValueError("Unable to find anything useful to verify with")

    return data

import re, htmlentitydefs

TRANSFORM_ENVELOPED_SIGNATURE = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature'
TRANSFORM_C14N_EXCLUSIVE_WITH_COMMENTS = 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments'
TRANSFORM_C14N_EXCLUSIVE = 'http://www.w3.org/2001/10/xml-exc-c14n'
TRANSFORM_C14N_INCLUSIVE = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315'

##
# Removes HTML or XML character references and entities from a text string.
#
# @param text The HTML (or XML) source text.
# @return The plain text, as a Unicode string, if necessary.

def _unescape(text):
    def fixup(m):
        text = m.group(0)
        if text[:2] == "&#":
            # character reference
            try:
                if text[:3] == "&#x":
                    return unichr(int(text[3:-1], 16))
                else:
                    return unichr(int(text[2:-1]))
            except ValueError:
                pass
        else:
            # named entity
            try:
                text = unichr(htmlentitydefs.name2codepoint[text[1:-1]])
            except KeyError:
                pass
        return text # leave as is
    return re.sub("&#?\w+;", fixup, text)

def _enveloped_signature(t):
    sig = t.find('.//{http://www.w3.org/2000/09/xmldsig#}Signature')
    p = sig.getprevious()
    if sig.tail is not None:
        if p is not None:
            p.tail += sig.tail
        else:
            sig.getparent().text += sig.tail
    sig.getparent().remove(sig)
    return t

def _c14n(t,exclusive,with_comments):
    cxml = etree.tostring(t,method="c14n",exclusive=exclusive,with_comments=with_comments)
    u = _unescape(cxml.decode("utf8",errors='replace')).encode("utf8").strip()
    assert u[0] == '<',XMLSigException("C14N buffer doesn't start with '<'")
    assert u[-1] == '>',XMLSigException("C14N buffer doesn't end with '>'")
    return u

def _transform(uri,t,**kwargs):
    if uri == TRANSFORM_ENVELOPED_SIGNATURE:
        return _enveloped_signature(t)

    if uri == TRANSFORM_C14N_EXCLUSIVE_WITH_COMMENTS:
        return _c14n(t,exclusive=True,with_comments=True)

    if uri == TRANSFORM_C14N_EXCLUSIVE:
        return _c14n(t,exclusive=True,with_comments=False)

    if uri == TRANSFORM_C14N_INCLUSIVE:
        return _c14n(t,exclusive=False,with_comments=False)

    raise ValueError("unknown or unimplemented transform %s" % uri)

def verify(t,keyspec):
    with open("/tmp/foo-signed.xml","w") as fd:
        fd.write(etree.tostring(t))

    for sig in t.findall(".//{%s}Signature" % NS['ds']):
        sv = sig.findtext(".//{%s}SignatureValue" % NS['ds'])
        assert sv is not None,XMLSigException("No SignatureValue")

        data = _cert(sig,keyspec)
        cert = rsa_x509_pem.parse(data)
        key = rsa_x509_pem.get_key(cert)
        key_f_public = rsa_x509_pem.f_public(key)

        expected = key_f_public(b64d(sv))

        _process_references(t,sig)

        si = sig.find(".//{%s}SignedInfo" % NS['ds'])
        cm = si.find(".//{%s}CanonicalizationMethod" % NS['ds'])
        assert cm is not None and cm.get('Algorithm',None) is not None,XMLSigException("No CanonicalizationMethod")
        sic = _transform(cm.get('Algorithm'),si)
        digest = _digest(sic,"sha1")
        logging.debug("SignedInfo digest: %s" % digest)
        b_digest = b64d(digest)

        sz = int(key.size())+1
        logging.debug("key size: %d" % sz)
        actual = _signed_value(b_digest, sz)

        assert expected == actual,XMLSigException("Signature validation failed")

    return True