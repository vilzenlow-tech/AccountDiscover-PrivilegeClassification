#!/usr/bin/env bash
# generate-certs.sh — create a self-signed TLS certificate for local dev.
#
# Usage:
#   ./nginx/generate-certs.sh
#
# Outputs:
#   nginx/certs/server.key  (private key)
#   nginx/certs/server.crt  (self-signed certificate, 825-day validity)
#
# For production, replace these files with certificates issued by a trusted CA
# (e.g. Let's Encrypt via Certbot, or your internal PKI).

set -euo pipefail

CERT_DIR="$(dirname "$0")/certs"
mkdir -p "$CERT_DIR"

if [[ -f "$CERT_DIR/server.crt" && -f "$CERT_DIR/server.key" ]]; then
  echo "Certificates already exist in $CERT_DIR — skipping generation."
  echo "Delete them and re-run this script to regenerate."
  exit 0
fi

echo "Generating self-signed certificate in $CERT_DIR ..."

openssl req -x509 \
  -newkey rsa:4096 \
  -keyout "$CERT_DIR/server.key" \
  -out    "$CERT_DIR/server.crt" \
  -days   825 \
  -nodes \
  -subj "/C=US/ST=Local/L=Dev/O=ADPCT/OU=Security/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

chmod 600 "$CERT_DIR/server.key"
chmod 644 "$CERT_DIR/server.crt"

echo ""
echo "Done. Files written to:"
echo "  $CERT_DIR/server.key"
echo "  $CERT_DIR/server.crt"
echo ""
echo "Add an exception in your browser for https://localhost (self-signed cert)."
