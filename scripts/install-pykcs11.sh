#!/bin/sh

CUR=`pwd`
WORK=`mktemp -d`
VERSION=1.3.1
wget -O$WORK/PyKCS11-${VERSION}.tar.gz https://pypi.python.org/packages/source/p/pykcs11/PyKCS11-${VERSION}.tar.gz
cd $WORK
tar xzvf PyKCS11-${VERSION}.tar.gz
cd PyKCS11-${VERSION}
make src/pykcs11_wrap.cpp
./setup.py install
cd $CUR
rm -rf $WORK
