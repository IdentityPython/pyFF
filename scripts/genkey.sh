#!/bin/sh

openssl genrsa 4096 > sign.key
openssl req -x509 -new -subj "/CN=Signer" -key sign.key -out sign.crt
