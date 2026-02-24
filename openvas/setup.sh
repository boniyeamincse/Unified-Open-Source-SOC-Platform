#!/bin/bash
####################################################################
#  Unified Open-Source SOC Platform
#  Author : Boni Yeamin
#  Open Source V:1.0
#  File   : openvas/setup.sh
#  Purpose: OpenVAS / Greenbone setup script. Syncs NVT, SCAP, and
#           CERT vulnerability feeds, then verifies scanner status.
####################################################################
#
# Usage:
#   Step 1: bash openvas/setup.sh    (run after container is up)
#   Step 2: Wait for feed sync to complete (~10-30 minutes)
#   Step 3: Access OpenVAS at https://openvas.soc.local
#
# ========================================================================================
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
