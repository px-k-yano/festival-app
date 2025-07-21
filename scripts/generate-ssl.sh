#!/bin/bash
# scripts/generate-ssl.sh

set -e

CERT_DIR="./ssl"
DOMAIN="localhost"

# Azure VMのパブリックIPを設定する場合は以下を変更
# DOMAIN="your-azure-vm-public-ip"

echo "Creating SSL certificate directory..."
mkdir -p $CERT_DIR

echo "Generating private key..."
openssl genrsa -out $CERT_DIR/server.key 2048

echo "Generating certificate signing request..."
openssl req -new -key $CERT_DIR/server.key -out $CERT_DIR/server.csr -subj "/C=JP/ST=Tokyo/L=Tokyo/O=Organization/CN=$DOMAIN"

echo "Generating self-signed certificate..."
openssl x509 -req -in $CERT_DIR/server.csr -signkey $CERT_DIR/server.key -out $CERT_DIR/server.crt -days 365 -extensions v3_req -extfile <(
cat << EOF
[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = $DOMAIN
DNS.2 = localhost
IP.1 = 127.0.0.1
IP.2 = ::1
EOF
)

echo "Setting appropriate permissions..."
chmod 600 $CERT_DIR/server.key
chmod 644 $CERT_DIR/server.crt

echo "SSL certificate generated successfully!"
echo "Certificate: $CERT_DIR/server.crt"
echo "Private Key: $CERT_DIR/server.key"
echo ""
echo "Note: This is a self-signed certificate. Browsers will show security warnings."
echo "For production use, obtain a certificate from a trusted CA."