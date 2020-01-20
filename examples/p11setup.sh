#!/bin/bash

if [ ! -f softhsm2.conf -o ! -f openssl.conf ]; then
   echo "Run this script in the directory where softhsm.conf and openssl.conf is"
fi

export SOFTHSM2_CONF=$PWD/softhsm2.conf

softhsm2-util --slot 0 --label test --init-token --pin secret1 --so-pin secret2 || exit -1
pkcs11-tool --module /usr/lib64/libsofthsm2.so -l -k --key-type rsa:4096 --slot 0 --id a1b2 --label signer --pin secret1 || exit -1
openssl 
req -new -x509 -subj "/CN=Test Signer" -engine pkcs11.so -config openssl.conf  -keyform engine -key a1b2 -passin pass:secret1 -out signer.crt days 365 || exit -1
openssl 
x509 -inform pem -outform der -in signer.crt -out signer.der || exit -1
pkcs11-tool --module /usr/lib64/libsofthsm2.so -l --slot 0 --id a1b2 --label signer -y cert -w signer.der --pin secret1 || exit -1
pkcs11-tool --module /usr/lib64/libsofthsm2.so -l -O --pin secret1 || exit -1
