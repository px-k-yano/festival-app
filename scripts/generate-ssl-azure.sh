#!/bin/bash
VM_PUBLIC_IP=$(curl -s http://checkip.amazonaws.com)
echo "Detected public IP: $VM_PUBLIC_IP"

CERT_DIR="./ssl"
mkdir -p $CERT_DIR

openssl genrsa -out $CERT_DIR/server.key 2048
openssl req -new -key $CERT_DIR/server.key -out $CERT_DIR/server.csr \
    -subj "/C=JP/ST=Tokyo/L=Tokyo/O=AppServer/CN=$VM_PUBLIC_IP"

openssl x509 -req -in $CERT_DIR/server.csr -signkey $CERT_DIR/server.key \
    -out $CERT_DIR/server.crt -days 365 -extensions v3_req -extfile <(
cat << EOL
[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
IP.1 = $VM_PUBLIC_IP
IP.2 = 127.0.0.1
DNS.1 = localhost
EOL
)

chmod 600 $CERT_DIR/server.key
chmod 644 $CERT_DIR/server.crt
echo "SSL certificate generated for IP: $VM_PUBLIC_IP"
