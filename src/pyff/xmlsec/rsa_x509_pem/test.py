#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright ©2011 Andrew D Yates
# andrewyates.name@gmail.com
"""Test RSA cryptographic PEM reader modules using example files.
"""
import unittest

from Crypto.PublicKey import RSA

import rsa_pem
import x509_pem
import __init__ as top


KEY_FILE_PAIRS = (
  ('keys/privkey_1_rsa_512.pem', 'keys/rsa_cert_1_512.pem'),
  ('keys/privkey_1_rsa_1024.pem', 'keys/rsa_cert_1_1024.pem'),
  ('keys/privkey_1_rsa_2048.pem', 'keys/rsa_cert_1_2048.pem'),
)

RSA_PARTS = (
  ('version', long),
  ('modulus', long),
  ('publicExponent', long),
  ('privateExponent', long),
  ('prime1', long),
  ('prime2', long),
  ('exponent1', long),
  ('exponent2', long),
  ('coefficient', long),
  ('body', basestring),
  ('type', basestring),
  )

X509_PARTS = (
  ('modulus', long),
  ('publicExponent', long),
  ('subject', basestring),
  ('body', basestring),
  ('type', basestring),
  )

X509_SUBJECT = "C=US,ST=Ohio,L=Columbus,CN=Andrew Yates,O=http://github.com/andrewdyates"

MSG1 = "Hello, World!"
MSG2 = "This is a test message to sign."
MSG_LONG = "I dedicate this essay to the two-dozen-odd people whose refutations of Cantor’s diagonal argument have come to me either as referee or as editor in the last twenty years or so. Sadly these submissions were all quite unpublishable; I sent them back with what I hope were helpful comments. A few years ago it occurred to me to wonder why so many people devote so much energy to refuting this harmless little argument — what had it done to make them angry with it? So I started to keep notes of these papers, in the hope that some pattern would emerge. These pages report the results."

DUMMY_SIG = (1234567890,)


class TestParse(unittest.TestCase):
  """Test parsing PEM formats into labeled dictionaries."""
  
  def setUp(self):
    self.data = {}
    for key, cert in KEY_FILE_PAIRS:
      with open(key, "r") as f:
        self.data[key] = f.read()
      with open(cert, "r") as f:
        self.data[cert] = f.read()
    
  def test_key_parse(self):
    for key, cert in KEY_FILE_PAIRS:
      data = self.data[key]
      self.assertTrue(data)
      dict = rsa_pem.parse(data)
      self.assertTrue(dict)
      # 20 chars is enough of a sanity check
      self.assertTrue(dict['body'][:20] in data)
      self.assertEqual(dict['type'], "RSA PRIVATE")

  def test_key_parse_elements(self):
    for key, cert in KEY_FILE_PAIRS:
      data = self.data[key]
      dict = rsa_pem.parse(data)
      for part, dtype in RSA_PARTS:
        self.assertTrue(part in dict)
        self.assertTrue(isinstance(dict[part], dtype))

  def test_cert_parse(self):
    for key, cert in KEY_FILE_PAIRS:
      data = self.data[cert]
      self.assertTrue(data)
      dict = x509_pem.parse(data)
      self.assertTrue(dict)
      # 20 chars is enough of a sanity check
      self.assertTrue(dict['body'][:20] in data)
      self.assertEqual(dict['type'], "X509 CERTIFICATE")

  def test_cert_parse_elements(self):
    for key, cert in KEY_FILE_PAIRS:
      data = self.data[cert]
      dict = x509_pem.parse(data)
      self.assertEqual(dict['subject'], X509_SUBJECT)
      for part, dtype in X509_PARTS:
        self.assertTrue(part in dict)
        self.assertTrue(isinstance(dict[part], dtype))


class TestGenKey(unittest.TestCase):
  """Test RSA Keys from parameters parsed from file."""
  
  def setUp(self):
    self.dicts = {}
    for key, cert in KEY_FILE_PAIRS:
      with open(key, "r") as f:
        data = f.read()
        self.dicts[key] = rsa_pem.parse(data)
      with open(cert, "r") as f:
        data = f.read()
        self.dicts[cert] = x509_pem.parse(data)
        
  def test_rsa_tuple_generation(self):
    for key, cert in KEY_FILE_PAIRS:
      rsa_dict = self.dicts[key]
      t = rsa_pem.dict_to_tuple(rsa_dict)
      self.assertTrue(t)
      self.assertEqual(len(t), 6)

  def test_x509_tuple_generation(self):
    for key, cert in KEY_FILE_PAIRS:
      x509_dict = self.dicts[cert]
      t = x509_pem.dict_to_tuple(x509_dict)
      self.assertTrue(t)
      self.assertEqual(len(t), 2)

  def test_rsa_keys(self):
    for key, cert in KEY_FILE_PAIRS:
      rsa_dict = self.dicts[key]
      rsa_t = rsa_pem.dict_to_tuple(rsa_dict)
      rsa_key = RSA.construct(rsa_t)
      self.assertTrue(rsa_key)
      self.assertEqual(rsa_key.e, 65537)

  def test_x509_keys(self):
    for key, cert in KEY_FILE_PAIRS:
      x509_dict = self.dicts[cert]
      x509_t = x509_pem.dict_to_tuple(x509_dict)
      x509_key = RSA.construct(x509_t)
      self.assertTrue(x509_key)
      self.assertEqual(x509_key.e, 65537)

      
class TestRSAKey(unittest.TestCase):
  """Test correct operation of RSA keys generated from key files."""
  
  def setUp(self):
    self.keys = {}

    for key, cert in KEY_FILE_PAIRS:
      with open(key, "r") as f:
        data = f.read()
        dict = rsa_pem.parse(data)
        t = rsa_pem.dict_to_tuple(dict)
        self.keys[key] = RSA.construct(t)
      with open(cert, "r") as f:
        data = f.read()
        dict = x509_pem.parse(data)
        t = x509_pem.dict_to_tuple(dict)
        self.keys[cert] = RSA.construct(t)

  def test_key_encryption(self):
    for key_name, v in KEY_FILE_PAIRS:
      key = self.keys[key_name]
      cipher1 = key.encrypt(MSG1, None)
      cipher2 = key.encrypt(MSG2, None)
      self.assertNotEqual(MSG1, MSG2)
      self.assertNotEqual(cipher1, cipher2)

  def test_key_decryption(self):
    for key_name, v in KEY_FILE_PAIRS:
      key = self.keys[key_name]
      # Message 1
      cipher1 = key.encrypt(MSG1, None)
      plain1 = key.decrypt(cipher1)
      self.assertEqual(MSG1, plain1)
      # Message 2
      cipher2 = key.encrypt(MSG2, None)
      plain2 = key.decrypt(cipher2)
      self.assertEqual(MSG2, plain2)

  def test_key_signature(self):
    for key_name, v in KEY_FILE_PAIRS:
      key = self.keys[key_name]
      signature1 = key.sign(MSG1, None)
      signature2 = key.sign(MSG2, None)
      self.assertNotEqual(MSG1, MSG2)
      self.assertNotEqual(signature1, signature2)

  def test_key_verification(self):
    for key_name, v in KEY_FILE_PAIRS:
      key = self.keys[key_name]
      # Message 1
      signature1 = key.sign(MSG1, None)
      verified1 = key.verify(MSG1, signature1)
      fail1 = key.verify(MSG2, signature1)
      self.assertTrue(verified1)
      self.assertFalse(fail1)
      # Message 2
      signature2 = key.sign(MSG2, None)
      verified2 = key.verify(MSG2, signature2)
      fail2 = key.verify(MSG1, signature2)
      self.assertTrue(verified2)
      self.assertFalse(fail1)

  def test_too_long(self):
    for key_name, cert_name in KEY_FILE_PAIRS:
      key = self.keys[key_name]
      cert = self.keys[cert_name]
      self.assertRaises(Exception, key.encrypt, MSG_LONG, None)
      self.assertRaises(Exception, key.decrypt, MSG_LONG)
      self.assertRaises(Exception, key.sign, MSG_LONG, None)
      self.assertRaises(Exception, cert.encrypt, MSG_LONG, None)

  def test_certs_public_only(self):
    for k, cert_name in KEY_FILE_PAIRS:
      cert = self.keys[cert_name]
      self.assertRaises(Exception, cert.sign, MSG_LONG, None)
      self.assertRaises(Exception, cert.decrypt, MSG_LONG)

  def test_cert_verification(self):
     for k, cert_name in KEY_FILE_PAIRS:
       cert = self.keys[k]
       fail = cert.verify(MSG1, DUMMY_SIG)
       self.assertFalse(fail)

  def test_bad_sig_types(self):
    k, c = KEY_FILE_PAIRS[0]
    key = self.keys[k]
    self.assertRaises(TypeError, key.verify, MSG1, 1234567890)
    self.assertRaises(Exception, key.verify, MSG1, "1234567890")
    key.verify(MSG1, DUMMY_SIG)

  def test_cert_encryption(self):
    for k, cert_name in KEY_FILE_PAIRS:
      cert = self.keys[cert_name]
      cipher1 = cert.encrypt(MSG1, None)
      cipher2 = cert.encrypt(MSG2, None)
      self.assertNotEqual(MSG1, MSG2)
      self.assertNotEqual(cipher1, cipher2)

  def test_key_pairs(self):
    for key_name, cert_name in KEY_FILE_PAIRS:
      key, cert = self.keys[key_name], self.keys[cert_name]
      # sign with private, verify with public cert
      signature1 = key.sign(MSG1, None)
      verified1 = cert.verify(MSG1, signature1)
      fail1 = cert.verify(MSG2, signature1)
      self.assertTrue(verified1)
      self.assertFalse(fail1)
      signature2 = key.sign(MSG2, None)
      verified2 = cert.verify(MSG2, signature2)
      fail2 = cert.verify(MSG1, signature2)
      self.assertTrue(verified2)
      self.assertFalse(fail2)

  def test_mismatch_key_pair(self):
    # select mismatched keypair
    key_name, cert_name = KEY_FILE_PAIRS[0][0], KEY_FILE_PAIRS[1][1]
    key, cert = self.keys[key_name], self.keys[cert_name]
    # verify signature failure
    signature = key.sign(MSG1, None)
    fail_verify = cert.verify(MSG1, signature)
    self.assertFalse(fail_verify)
    # verify encryption failure
    cipher = cert.encrypt(MSG1, None)
    try:
      plain = key.decrypt(cipher)
    except Exception, e:
      self.assertTrue("Ciphertext too large" in e, e)
    else:
      self.assertNotEqual(MSG1, plain)


class TestTop(unittest.TestCase):
  
  def test_rsa_parse(self):
    self.assertEqual(top.rsa_parse, rsa_pem.parse)
    data = open(KEY_FILE_PAIRS[0][0]).read()
    rsa_dict = top.parse(data)
    self.assertTrue(rsa_dict)
    
  def test_x509_parse(self):
    self.assertEqual(top.x509_parse, x509_pem.parse)
    data = open(KEY_FILE_PAIRS[0][1]).read()
    x509_dict = top.parse(data)
    self.assertTrue(x509_dict)

  def test_rsa_dict_to_key(self):
    data = open(KEY_FILE_PAIRS[0][0]).read()
    rsa_dict = top.parse(data)
    key = top.get_key(rsa_dict)
    self.assertTrue(key)
    self.assertTrue(key.e)
    self.assertTrue(key.d)
  
  def test_x509_dict_to_key(self):
    data = open(KEY_FILE_PAIRS[0][1]).read()
    x509_dict = top.parse(data)
    key = top.get_key(x509_dict)
    self.assertTrue(key)
    self.assertTrue(key.e)
    # "lambda" suppresses exception until called by the test handler
    self.assertRaises(AttributeError, lambda: key.d)

  def test_RSA_obj(self):
    self.assertEqual(top.RSAKey, RSA.RSAobj)

class TestFunctionWrappers(unittest.TestCase):

  def setUp(self):
    self.pubkey = top.get_key(top.parse(open(KEY_FILE_PAIRS[0][1]).read()))
    self.privkey = top.get_key(top.parse(open(KEY_FILE_PAIRS[0][0]).read()))

  def test_public(self):
    f_my_public = top.f_public(self.pubkey)
    self.assertTrue(f_my_public(MSG1))
    f_my_public2 = top.f_public(self.privkey)
    self.assertTrue(f_my_public2(MSG1))

  def test_private(self):
    f_my_private = top.f_private(self.privkey)
    self.assertTrue(f_my_private(MSG1))
    f_my_private2 = top.f_private(self.pubkey)
    # cannot use private function on a public key
    self.assertRaises(Exception, f_my_private2, MSG1)

  def test_inverse(self):
    f_my_private = top.f_private(self.privkey)
    f_my_public = top.f_public(self.privkey)
    self.assertEqual(MSG1, f_my_public(f_my_private(MSG1)))
    self.assertEqual(MSG1, f_my_private(f_my_public(MSG1)))
    self.assertNotEqual(MSG1, f_my_public(f_my_public(MSG1)))
    self.assertNotEqual(MSG1, f_my_private(f_my_private(MSG1)))

      
def main():
  unittest.main()

if __name__ == '__main__':
  main()
