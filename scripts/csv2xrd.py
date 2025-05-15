#!/usr/bin/env python

import sys

from lxml import etree

ns = {None: "http://docs.oasis-open.org/ns/xri/xrd-1.0"}

xrds = etree.Element("{http://docs.oasis-open.org/ns/xri/xrd-1.0}XRDS", nsmap=ns)
with open(sys.argv[1]) as fd:
    for line in fd:
        line = line.strip()
        e = [x.strip('"') for x in line.split(",")]
        xrd = etree.Element("{http://docs.oasis-open.org/ns/xri/xrd-1.0}XRD", nsmap=ns)
        xrds.append(xrd)
        subject = etree.Element("{http://docs.oasis-open.org/ns/xri/xrd-1.0}Subject", nsmap=ns)
        subject.text = e[3]
        link = etree.Element("{http://docs.oasis-open.org/ns/xri/xrd-1.0}Link", nsmap=ns)
        link.set('rel', "urn:oasis:names:tc:SAML:2.0:metadata")
        link.set('href', e[3])
        xrd.append(subject)
        xrd.append(link)
        title = etree.Element("{http://docs.oasis-open.org/ns/xri/xrd-1.0}Title", nsmap=ns)
        title.text = e[1]
        link.append(title)

print(etree.tostring(xrds, pretty_print=True))
