#!/bin/bash

set -eu

#
# Prepare the client's stuff.
#
cd /home/client

# Generate a private RSA key.
openssl genrsa -out key.pem 2048

# Generate a certificate from our private key.
openssl req -new -key key.pem -out req.pem -outform PEM -subj /CN=$(hostname)/O=client/ -nodes

# Sign the certificate with our CA.
cd /home/testca
openssl ca -config openssl.cnf -in /home/client/req.pem -out /home/client/cert.pem -notext -batch -extensions client_ca_extensions

# Create a key store that will contain our certificate.
cd /home/client
openssl pkcs12 -export -out key-store.p12 -in cert.pem -inkey key.pem -passout pass:roboconf

# Create a trust store that will contain the certificate of our CA.
openssl pkcs12 -export -out trust-store.p12 -in /home/testca/cacert.pem -inkey /home/testca/private/cakey.pem -passout pass:roboconf
