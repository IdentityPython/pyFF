#!/bin/sh

openssl req -x509 -new -newkey rsa:4096 -nodes -keyout sign.key -out sign.crt
