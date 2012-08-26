#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright ©2011 Andrew D. Yates
# andrewyates.name@gmail.com
"""Self-descriptive PEM decoder for 'univ.Sequence'.
"""
from pyasn1.type import univ


class SequenceParser(univ.Sequence):
  """Base type for self-reporting PEM binary format templates.
  x509_pem and rsa_pem use this like a "Key Parser" base class.

  Properties:
    componentType: `namedtype.NamedTypes` instance; defined per child class
  """
  # OVERRIDE
  componentType = None

  def dict(self):
    """Return simple dictionary of labeled key elements as simple types.

    Returns:
      {str, value} where `value` is simple type like `long`
    """
    dict = {}
    for i in range(len(self._componentValues)):
      if self._componentValues[i] is not None:
        componentType = self.getComponentType()
        if componentType is not None:
          name = componentType.getNameByPosition(i)
          value = self._componentValues[i]._value
          dict[name] = value
    return dict
