"""
XML security implementation using on dm.xmlsec.binding
"""

from dm.xmlsec.binding.tmpl import Signature
import dm.xmlsec.binding as xmlsec
import logging
import os
import hashlib
import base64
from pyff.constants import NS

__author__ = 'leifj'

def _find_matching_cert(t,fp):
    cn = t.xpath('//ds:X509Certificate',namespaces=NS)
    if cn is None or len(cn) == 0:
        return None

    for cd in cn:
        fp = fp.lower().replace(":","")
        cert_pem = cd.text
        cert_der = base64.b64decode(cert_pem)
        m = hashlib.sha1()
        m.update(cert_der)
        fingerprint = m.hexdigest().lower()
        if fingerprint == fp:
            return cert_der
    return None


def verify(t,key):
    """
    Verify a signed tree using *key*. This implementation uses cython bindings to libxmlsec.
    """
    xmlsec.initialize()
    xmlsec.set_error_callback(log_error)
    xmlsec.addIDs(t.find('.'),['ID'])

    sn = t.find('.//{%s}Signature' % xmlsec.DSigNs)
    if sn is None:
        raise ValueError('cannot find signature node')

    if os.path.isfile(key):
        mngr = xmlsec.KeysMngr()
        dsigCtx = xmlsec.DSigCtx(mngr)
        mngr.loadCert(key,xmlsec.KeyDataFormatPem,xmlsec.KeyDataTypeTrusted)
        dsigCtx.verify(sn)
    elif ":" in key: # looks like a fingerprint - untested, probably doesn't work
        cert_der = _find_matching_cert(t,key)
        if cert_der:
            mngr = xmlsec.KeysMngr()
            dsigCtx = xmlsec.DSigCtx(mngr)
            mngr.loadCertMemory(cert_der,xmlsec.KeyDataFormatDer,xmlsec.KeyDataTypeTrusted)
            dsigCtx.verify(sn)
        else:
            raise ValueError("unable to find a certificate matching fingerprint in signature")
    else:
        raise ValueError("don't know how to validate signatures using %s" % key)

def sign(t,key,cert):
    """
    Sign a tree using *key* and include *cert* as an <X509Certificate/> element.
    This implementation uses cython bindings to libxmlsec.
    """
    xmlsec.initialize()
    xmlsec.set_error_callback(log_error)
    xmlsec.addIDs(t.find('.'),['ID'])
    signature = Signature(xmlsec.TransformExclC14NWithComments,xmlsec.TransformRsaSha1)
    cm = signature.find("{%s}SignedInfo/{%s}CanonicalizationMethod" % (xmlsec.DSigNs,xmlsec.DSigNs))
    cm.set('Algorithm','http://www.w3.org/TR/2001/REC-xml-c14n-20010315')
    t.insert(0,signature)
    ref = signature.addReference(xmlsec.TransformSha1,uri="")
    ref.set('URI',"")
    ref.addTransform(xmlsec.TransformEnveloped)
    ref.addTransform(xmlsec.TransformExclC14NWithComments)
    key_info = signature.ensureKeyInfo()
    #key_info.addKeyName()
    key_info.addX509Data()
    dsigCtx = xmlsec.DSigCtx()
    signKey = xmlsec.Key.load(key, xmlsec.KeyDataFormatPem, None)
    signKey.loadCert(cert, xmlsec.KeyDataFormatPem)
    dsigCtx.signKey = signKey
    dsigCtx.sign(signature)


def log_error(filename, line, func, errorObject, errorSubject, reason, msg):
    # this would give complete but often not very usefull) information
    # print "%(filename)s:%(line)d(%(func)s) error %(reason)d obj=%(errorObject)s subject=%(errorSubject)s: %(msg)s" % locals()
    # the following prints if we get something with relation to the application
    info = []
    if errorObject != "unknown": info.append("obj=" + errorObject)
    if errorSubject != "unknown": info.append("subject=" + errorSubject)
    if msg.strip(): info.append("msg=" + msg)
    if info:
        logging.error("%s:%d(%s) - %s" % (filename, line, func," ".join(info)))


def log_errors(ebuf):
    """
    Summarize a list of error messages from xmlsec captured using capture_errors
    """
    for e in ebuf:
        info = []
        if e['object'] != "unknown": info.append("obj=" + e['object'])
        if e['subject'] != "unknown": info.append("subject=" + e['subject'])
        if e['message'].strip(): info.append("msg=" + e['message'].strip())
        logging.error("%s:%d(%s) - %s" % (e['filename'],e['line'],e['func']," ".join(info)))


def capture_errors(filename, line, func, errorObject, errorSubject, reason, msg, buf):
    """
    Capture error information from xmlsec into a list for processing
    """
    buf.append({'filename':filename,
                'line':line,
                'func':func,
                'object': errorObject,
                'reason': reason,
                'subject':errorSubject,
                'message': msg.strip()})