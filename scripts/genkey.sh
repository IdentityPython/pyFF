#!/bin/sh

openssl genrsa 2048 > sign.key
openssl req -x509 -sha1 -new -subj "/CN=Signer" -key sign.key -out sign.crt
