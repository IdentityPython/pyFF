#!/bin/bash

if [ ! -f softhsm.conf -o ! -f openssl.conf ]; then
   echo "Run this script in the directory where softhsm.conf and openssl.conf is"
fi

export SOFTHSM_CONF=softhsm.conf

softhsm --slot 0 --label test --init-token --pin secret1 --so-pin secret2 || exit -1
pkcs11-tool --module /usr/lib/libsofthsm.so -l -k --key-type rsa:4096 --slot 0 --id a1b2 --label signer --pin secret1 || exit -1
openssl req -new -x509 -subj "/cn=Test Signer" -engine pkcs11 -config openssl.conf  -keyform engine -key a1b2 -passin pass:secret1 > signer.crt || exit -1
openssl x509 -inform pem -outform der < signer.crt > signer.der || exit -1
pkcs11-tool --module /usr/lib/libsofthsm.so -l --slot 0 --id a1b2 --label signer -y cert -w signer.der --pin secret1 || exit -1
pkcs11-tool --module /usr/lib/libsofthsm.so -l -O --pin secret1 || exit -1
