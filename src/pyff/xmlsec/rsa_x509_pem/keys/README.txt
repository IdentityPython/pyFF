This directory contains a collection of sample cryptographic keys and
certificates used for testing.

Example generation commands using example file names:

Generate unencrypted 2048 bit private RSA key
=============================================
$ openssl genrsa -out privkey_1_rsa_2048.pem 2048

Generate certificate using private RSA key
==========================================
$ openssl req -new -x509 -days 365 \
  -subj '/C=US/ST=Ohio/L=Columbus/CN=www.github.com/andrewdyates' \
  -key privkey_1_rsa_2048.pem \
  -out rsa_cert_1_2048.pem

i.e.
$ openssl req -new -x509 -days 365 -subj '/C=US/ST=Ohio/L=Columbus/CN=Andrew Yates/O=http:\/\/github.com\/andrewdyates' -key privkey_1_rsa_2048.pem -out rsa_cert_1_2048.pem

Print certificate to text
=========================
$ openssl x509 -text -in rsa_cert_1_2048.pem

Print RSA key to text
=====================
$ openssl rsa -text -in privkey_1_rsa_2048.pem
