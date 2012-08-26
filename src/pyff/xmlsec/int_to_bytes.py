#!/usr/bin/python2.5
# -*- coding: utf-8 -*-
# Copyright © 2011 Andrew D. Yates
# All Rights Reserved
"""Bytes to Integer Functions.

`int` types may be cast as `long`
"""
__authors__ = ['"Andrew D. Yates" <andrewyates.name@gmail.com>']

def bytes_to_int(s):
  """Return converted bytestring to integer.

  Args:
    s: str of bytes
  Returns:
    int: numeric interpretation of binary string `s`
  """
  # int type casts may return a long type
  return int(s.encode('hex'), 16)


def int_to_bytes(num):
  """Return converted integer to bytestring.

  Note: string encoding is faster than divmod(num, 256) in Python.

  Args:
    num: integer, non-negative
  Returns:
    str: bytestring of binary data to represent `num`
  Raises:
    ValueError: `num` is not a non-negative integer
  """
  if not is_natural(num, include_zero=True):
    raise ValueError("%s is not a non-negative integer.")
  hexed = "%x" % num
  # align hexadecimal string to byte boundaries
  if len(hexed) % 2 == 1:
    hexed = '0%s' % hexed
  return hexed.decode('hex')


def is_natural(value, include_zero=False):
  """Return if value is a natural integer in Python.
  
  Returns:
    bool: is value a natural number?
  """
  return all((
    isinstance(value, (int, long)),
    value >= 0,
    not (value == 0 and not include_zero),
  ))
