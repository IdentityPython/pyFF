from dm.xmlsec.binding.tmpl import Signature
import dm.xmlsec.binding as xmlsec
import logging
import os
import hashlib
import base64
from pyff.constants import NS
from M2Crypto import X509

__author__ = 'leifj'

def verify(t,key):
    """
    Verify a signed tree using *key*. This implementation uses cython bindings to libxmlsec.
    """
    xmlsec.initialize()
    xmlsec.set_error_callback(log_error)
    sn = t.find('.//{%s}Signature' % xmlsec.DSigNs)
    if sn is None:
        logging.error('cannot find signature node')
        return []
    if os.path.isfile(key):
        dsigCtx = xmlsec.DSigCtx()
        cert = X509.load_cert(key)
        pub_key = cert.get_pubkey().get_rsa()
        sk = xmlsec.Key.loadMemory(pub_key.as_pem(cipher=None),xmlsec.KeyDataFormatPem)
        sk.name = key
        logging.debug("Key name %s" % sk.name)
        dsigCtx.signKey = sk
        dsigCtx.verify(sn)
    elif ":" in key: # looks like a fingerprint
        cn = t.xpath('//ds:X509Certificate',namespaces=NS)
        if cn:
            for cd in cn:
                try:
                    mngr = xmlsec.KeysMngr()
                    dsigCtx = xmlsec.DSigCtx(mngr)
                    certpem = cd.text()
                    certder = base64.b64decode(certpem)
                    m = hashlib.sha1()
                    m.update(certder)
                    fingerprint = m.hexdigest()
                    logging.info("checking fingerprint %s" % fingerprint)
                    if fingerprint.tolower() == key.tolower():
                        mngr.loadCertMemory(certder,xmlsec.KeyDataFormatDer,xmlsec.KeyDataTypeTrusted)
                        logging.debug('fingerprint OK')
                        dsigCtx.verify(sn)
                    else:
                        raise ValueError('fingerprint missmatch %s != %s' % (fingerprint,key))
                except Exception,ex:
                    raise ex
        else:
            raise ValueError('unable to verify without embedded X.509 certificate!')
    else:
        raise ValueError('don\'t know how to verify using %s' % key)

    #logging.debug('verifying at %s' % sn)
    #dsigCtx.verify(sn)

def sign(t,key,cert):
    """
    Sign a tree using *key* and include *cert* as an <X509Certificate/> element.
    This implementation uses cython bindings to libxmlsec.
    """
    xmlsec.initialize()
    xmlsec.set_error_callback(log_error)
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