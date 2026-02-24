#!/bin/bash
####################################################################
#  Unified Open-Source SOC Platform
#  Author : Boni Yeamin
#  Open Source V:1.0
#  File   : nginx/certs/generate_certs.sh
#  Purpose: Generates self-signed TLS certificates for all SOC
#           services using a shared Root CA. Import ca.crt into
#           your browser to trust all service certificates.
####################################################################
#
# Usage:
#   Step 1: cd nginx/certs/
#   Step 2: bash generate_certs.sh
#   Step 3: Import ca.crt into your browser/OS trust store
#
# =============================================================
set -euo pipefail

CERT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CA_DAYS=3650
CERT_DAYS=3650

echo "=========================================="
echo " SOC Platform TLS Certificate Generator"
echo "=========================================="

# --- Generate Root CA ---
if [[ ! -f "$CERT_DIR/ca.key" ]]; then
    echo "[*] Generating Root CA..."
    openssl genrsa -out "$CERT_DIR/ca.key" 4096 2>/dev/null
    openssl req -new -x509 -days $CA_DAYS \
        -key "$CERT_DIR/ca.key" \
        -out "$CERT_DIR/ca.crt" \
        -subj "/C=US/ST=Security/L=SOC/O=SOC Platform/CN=SOC Root CA" 2>/dev/null
    echo "[+] Root CA generated: ca.crt / ca.key"
else
    echo "[*] Root CA already exists, skipping."
fi

# --- Generate service certificates ---
services=("wazuh" "misp" "thehive" "cortex" "openvas" "shuffle" "keycloak")

for svc in "${services[@]}"; do
    if [[ -f "$CERT_DIR/${svc}.crt" ]]; then
        echo "[*] Certificate for $svc already exists, skipping."
        continue
    fi

    echo "[*] Generating certificate for: $svc"

    # Generate key
    openssl genrsa -out "$CERT_DIR/${svc}.key" 2048 2>/dev/null

    # Generate CSR
    openssl req -new \
        -key "$CERT_DIR/${svc}.key" \
        -out "$CERT_DIR/${svc}.csr" \
        -subj "/C=US/ST=Security/L=SOC/O=SOC Platform/CN=${svc}.soc.local" 2>/dev/null

    # SAN extension
    cat > "/tmp/${svc}-san.ext" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${svc}.soc.local
DNS.2 = ${svc}
DNS.3 = localhost
IP.1 = 127.0.0.1
EOF

    # Sign with CA
    openssl x509 -req -days $CERT_DAYS \
        -in "$CERT_DIR/${svc}.csr" \
        -CA "$CERT_DIR/ca.crt" \
        -CAkey "$CERT_DIR/ca.key" \
        -CAcreateserial \
        -out "$CERT_DIR/${svc}.crt" \
        -extfile "/tmp/${svc}-san.ext" 2>/dev/null

    # Cleanup CSR
    rm -f "$CERT_DIR/${svc}.csr" "/tmp/${svc}-san.ext"

    echo "[+] $svc: ${svc}.crt / ${svc}.key"
done

# Lock down private keys
chmod 600 "$CERT_DIR"/*.key

echo ""
echo "=========================================="
echo " All certificates generated!"
echo " Import ca.crt into your browser/OS"
echo " to trust these certificates."
echo "=========================================="
