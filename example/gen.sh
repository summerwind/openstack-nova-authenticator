#!/bin/bash

set -e

# Generate server certificate
cfssl selfsign 127.0.0.1 csr.json | cfssljson -bare server

# Generate signing key pair
openssl genrsa 4096 > signing-key.pem
openssl rsa -pubout < signing-key.pem > signing-pub.pem
