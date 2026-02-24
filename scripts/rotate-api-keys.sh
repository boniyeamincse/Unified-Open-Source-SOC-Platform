#!/bin/bash
####################################################################
#  Unified Open-Source SOC Platform
#  Author : Boni Yeamin
#  Open Source V:1.0
#  File   : scripts/rotate-api-keys.sh
#  Purpose: Automated API key rotation for SOC services.
#           Generates new keys, updates .env, restarts services.
####################################################################
#
# Usage:
#   bash scripts/rotate-api-keys.sh              (interactive)
#   bash scripts/rotate-api-keys.sh --auto        (cron mode)
#
# Cron example (monthly rotation):
#   0 0 1 * * /opt/soc/scripts/rotate-api-keys.sh --auto >> /var/log/soc/key-rotation.log 2>&1
#

set -euo pipefail

# ── Configuration ─────────────────────────────────────────
ENV_FILE="${SOC_ENV_FILE:-$(dirname "$0")/../.env}"
LOG_FILE="${SOC_AUDIT_LOG:-/var/log/soc/audit.json}"
AUTO_MODE=false
RESTART_SERVICES=true

# Parse arguments
for arg in "$@"; do
    case $arg in
        --auto)     AUTO_MODE=true ;;
        --no-restart) RESTART_SERVICES=false ;;
        --help)
            echo "Usage: $0 [--auto] [--no-restart]"
            echo "  --auto       Run without confirmation prompts (for cron)"
            echo "  --no-restart Skip container restart after rotation"
            exit 0
            ;;
    esac
done

# ── Functions ─────────────────────────────────────────────

generate_key() {
    # Generate a 32-character URL-safe random key
    python3 -c "import secrets; print(secrets.token_urlsafe(24))" 2>/dev/null \
        || openssl rand -base64 24 | tr -d '/+=' | head -c 32
}

generate_password() {
    # Generate a 24-character password with mixed chars
    python3 -c "
import secrets, string
chars = string.ascii_letters + string.digits + '!@#\$%&'
print(''.join(secrets.choice(chars) for _ in range(24)))
" 2>/dev/null || openssl rand -base64 24 | head -c 24
}

log_audit() {
    local action="$1"
    local detail="$2"
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    mkdir -p "$(dirname "$LOG_FILE")"

    echo "{\"timestamp\":\"${timestamp}\",\"user\":\"system\",\"action\":\"${action}\",\"detail\":\"${detail}\",\"source\":\"rotate-api-keys.sh\"}" >> "$LOG_FILE"
}

rotate_key() {
    local key_name="$1"
    local new_value="$2"

    if grep -q "^${key_name}=" "$ENV_FILE"; then
        # Replace existing key
        sed -i "s|^${key_name}=.*|${key_name}=${new_value}|" "$ENV_FILE"
        echo "  ✅ Rotated: ${key_name}"
    else
        # Add new key
        echo "${key_name}=${new_value}" >> "$ENV_FILE"
        echo "  ✅ Added:   ${key_name}"
    fi

    log_audit "KEY_ROTATION" "Rotated ${key_name}"
}

# ── Preflight Checks ─────────────────────────────────────

if [ ! -f "$ENV_FILE" ]; then
    echo "❌ Error: .env file not found at: $ENV_FILE"
    exit 1
fi

echo "═══════════════════════════════════════════════════════"
echo "  🔑 SOC Platform — API Key Rotation"
echo "  Date: $(date -u +"%Y-%m-%d %H:%M UTC")"
echo "  Env:  $ENV_FILE"
echo "═══════════════════════════════════════════════════════"
echo ""

# ── Confirmation (interactive mode) ──────────────────────

if [ "$AUTO_MODE" = false ]; then
    echo "⚠️  This will rotate ALL API keys and passwords."
    echo "    Services will be restarted to apply changes."
    echo ""
    read -rp "Continue? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 0
    fi
    echo ""
fi

# ── Backup Current .env ──────────────────────────────────

backup_file="${ENV_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
cp "$ENV_FILE" "$backup_file"
echo "📦 Backup saved: $backup_file"
log_audit "KEY_ROTATION_START" "Backup saved to ${backup_file}"
echo ""

# ── Rotate Keys ──────────────────────────────────────────

echo "🔄 Rotating API keys..."

rotate_key "CORTEX_API_KEY"      "$(generate_key)"
rotate_key "CORTEX_SECRET"       "$(generate_key)"
rotate_key "SHUFFLE_API_KEY"     "$(generate_key)"
rotate_key "WEBHOOK_HMAC_SECRET" "$(generate_key)"
rotate_key "REDIS_PASSWORD"      "$(generate_password)"
rotate_key "MISP_ZMQ_PASSWORD"   "$(generate_password)"
rotate_key "THEHIVE_SECRET"      "$(generate_key)"

echo ""
echo "🔄 Rotating service passwords..."

rotate_key "WAZUH_PASSWORD"      "$(generate_password)"
rotate_key "MISP_ADMIN_PASSPHRASE" "$(generate_password)"
rotate_key "MISP_DB_PASSWORD"    "$(generate_password)"
rotate_key "POSTGRES_PASSWORD"   "$(generate_password)"
rotate_key "GVMD_PASSWORD"       "$(generate_password)"
rotate_key "OPENSEARCH_INITIAL_ADMIN_PASSWORD" "$(generate_password)"

echo ""

# ── Restart Services ─────────────────────────────────────

if [ "$RESTART_SERVICES" = true ]; then
    echo "🔄 Restarting SOC services to apply new keys..."

    COMPOSE_DIR="$(dirname "$ENV_FILE")"
    if [ -f "${COMPOSE_DIR}/docker-compose.yml" ]; then
        cd "$COMPOSE_DIR"
        docker compose restart cortex shuffle thehive misp wazuh.manager 2>/dev/null || true
        echo "  ✅ Services restarted"
    else
        echo "  ⚠️  docker-compose.yml not found — restart services manually"
    fi
else
    echo "⏭️  Skipping service restart (--no-restart)"
fi

echo ""

# ── Summary ──────────────────────────────────────────────

log_audit "KEY_ROTATION_COMPLETE" "All 13 keys/passwords rotated successfully"

echo "═══════════════════════════════════════════════════════"
echo "  ✅ Key rotation complete"
echo "  📦 Backup: $backup_file"
echo "  📋 Audit:  $LOG_FILE"
echo ""
echo "  Next rotation recommended: $(date -d '+30 days' +%Y-%m-%d 2>/dev/null || date -v+30d +%Y-%m-%d 2>/dev/null || echo 'in 30 days')"
echo "═══════════════════════════════════════════════════════"
