#!/bin/bash

set -eu

#
# Prepare the certificate authority (self-signed).
#
cd /home/testca

# Create a self-signed certificate that will serve a certificate authority (CA).
# The private key is located under "private".
openssl req -x509 -config openssl.cnf -newkey rsa:4096 -days 365 -out cacert.pem -outform PEM -subj /CN=MyTestCA/ -nodes

# Encode our certificate with DER.
openssl x509 -in cacert.pem -out cacert.cer -outform DER



#
# Prepare the server's stuff.
#
cd /home/server

# Generate a private RSA key.
openssl genrsa -out key.pem 2048

# Generate a certificate from our private key.
openssl req -new -key key.pem -out req.pem -outform PEM -subj /CN=queue/O=server/ -nodes

# Sign the certificate with our CA.
cd /home/testca
openssl ca -config openssl.cnf -in /home/server/req.pem -out /home/server/cert.pem -notext -batch -extensions server_ca_extensions

# Create a key store that will contain our certificate.
cd /home/server
openssl pkcs12 -export -out keycert.p12 -in cert.pem -inkey key.pem -passout pass:roboconf
