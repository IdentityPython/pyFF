#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright ©2011 Andrew D Yates
# andrewyates.name@gmail.com
"""Package module into well organized interface.
"""
from Crypto.PublicKey import RSA

import rsa_pem
import x509_pem

# *_parse accepts file data to be parsed as a single parameter
# >>> key_dict = rsa_parse(open("my_key.pem").read())
# ... cert_dict = cert_parse(open("my_cert.pem").read())
rsa_parse = rsa_pem.parse
x509_parse = x509_pem.parse

RSAKey = RSA.RSAobj


def parse(data):
  """Return parsed dictionary from parsed PEM file; based on header.

  Args:
    data: str of PEM file data
  Returns:
    {str:str} as returned from appropriate *_parse parser
  """
  if "RSA PRIVATE" in data:
    dict = rsa_pem.parse(data)
  elif "CERTIFICATE" in data:
    dict = x509_pem.parse(data)
  else:
    raise Exception("PEM data type not supported.")
  return dict


def get_key(parse_dict):
  """Return RSA object from parsed PEM key file dictionary.

  Args:
    parse_dict: {str:str} as returned by `parse`
  Returns:
    `RSAKey` RSA key object as specified by `parse_dict`
  """
  if parse_dict['type'] == "RSA PRIVATE":
    key_tuple = rsa_pem.dict_to_tuple(parse_dict)
  elif parse_dict['type'] == "X509 CERTIFICATE":
    key_tuple = x509_pem.dict_to_tuple(parse_dict)
  else:
    raise Exception("parse_dict type '%s' not supported." % parse_dict['type'])
  key = RSA.construct(key_tuple)
  return key

def f_public(key):
  """Return a convenient public key function.

  Args:
    key: `RSAKey` as returned by get_key(parse_dict).
  Returns:
    function(msg) => str of RSA() using `key`
  """
  return lambda x: key.encrypt(x, None)[0]

def f_private(key):
  """Return a convenient public key function.

  Args:
    key: `RSAKey` as returned by get_key(parse_dict).
  Returns:
    function(msg) => str of RSA^-1() using `key`
  """
  return key.decrypt
