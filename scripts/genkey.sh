#!/bin/sh

# RSA - 4096 bit
openssl genrsa 4096 > sign-rsa.key
openssl req -x509 -sha256 -new -subj "/CN=Signer (RSA)" -key sign-rsa.key -out sign-rsa.crt -days 10000

# ECDSA - NIST curve p384
openssl ecparam -out sign-ecdsa.key -name secp384r1 -genkey 
openssl req -x509 -new -key sign-ecdsa.key -out sign-ecdsa.crt -subj "/CN=Signer (ECDSA)" -days 10000

# SLH-DSA - 256 bit - short
openssl genpkey -algorithm SLH-DSA-SHA2-256s -out sign-slhdsa.key
openssl req -x509 -new -key sign-slhdsa.key -out sign-slhdsa.crt -subj "/CN=Signer (SLH-DSA)" -days 10000

# ML-DSA - 87
openssl genpkey -algorithm ML-DSA-87 -out sign-mldsa.key
openssl req -x509 -new -key sign-mldsa.key -out sign-mldsa.crt -subj "/CN=Signer (ML-DSA)" -days 10000
