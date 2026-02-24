#!/bin/bash
# =============================================================
# OpenVAS / Greenbone Community Edition Setup Script
# SOC Platform – Vulnerability Management
# =============================================================
set -euo pipefail

echo "======================================================"
echo " OpenVAS/Greenbone Community Edition - SOC Setup"
echo "======================================================"

CONTAINER_NAME="openvas"

# Wait for container to be healthy
echo "[*] Waiting for OpenVAS container to be ready..."
until docker inspect --format='{{.State.Health.Status}}' "$CONTAINER_NAME" 2>/dev/null | grep -q "healthy"; do
    echo "    Container status: $(docker inspect --format='{{.State.Health.Status}}' $CONTAINER_NAME 2>/dev/null || echo 'starting...')"
    sleep 15
done

echo "[+] OpenVAS is healthy!"

# Update NVT feeds
echo "[*] Updating NVT vulnerability feeds (this may take 30+ minutes)..."
docker exec "$CONTAINER_NAME" bash -c "greenbone-nvt-sync" || echo "[WARN] NVT sync may still be in progress."

# Update SCAP feeds
echo "[*] Updating SCAP data feeds..."
docker exec "$CONTAINER_NAME" bash -c "greenbone-scapdata-sync" || echo "[WARN] SCAP sync may still be in progress."

# Update CERT feeds
echo "[*] Updating CERT feeds..."
docker exec "$CONTAINER_NAME" bash -c "greenbone-certdata-sync" || echo "[WARN] CERT sync may still be in progress."

echo ""
echo "======================================================"
echo " Setup Complete!"
echo "======================================================"
echo " Web UI: https://localhost:9392"
echo " Default user: admin"
echo " Default pass: (set via GVMD_PASSWORD in .env)"
echo "======================================================"
