#!/usr/bin/env bash
####################################################################
#  Unified Open-Source SOC Platform
#  Author : Boni Yeamin
#  File   : scripts/backup-dr.sh
#  Purpose: Automated backup & disaster recovery for all SOC data.
#           Supports daily cron, cross-region copy, restore, verify.
#           Target RTO ≤ 4h, RPO ≤ 24h.
####################################################################
set -euo pipefail

# ── Configuration ────────────────────────────────────────
BACKUP_BASE="${SOC_BACKUP_DIR:-/opt/soc-backups}"
TIMESTAMP=$(date +%Y%m%dT%H%M%SZ)
BACKUP_DIR="${BACKUP_BASE}/${TIMESTAMP}"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"
REMOTE_TARGET="${SOC_BACKUP_REMOTE:-}"   # e.g. s3://soc-backups/
LOG_FILE="/var/log/soc/backup.log"
SOC_DIR="${SOC_BASE_DIR:-/home/boni/Documents/unlimited_SOC}"

# Services to back up
DOCKER_VOLUMES=(
  "wazuh-data"
  "wazuh-indexer-data"
  "thehive-data"
  "postgres-data"
  "misp-data"
  "keycloak-postgres-data"
  "cortex-data"
  "audit_logs"
)

CONFIG_FILES=(
  "docker-compose.yml"
  ".env"
  "nginx/nginx.conf"
  "thehive/application.conf"
  "wazuh/ossec.conf"
  "wazuh/rules/soc-correlation.xml"
  "keycloak/realm-soc.json"
  "suricata/suricata.yaml"
  "suricata/rules/local.rules"
  "config/tenants.yaml"
)

# ── Logging ──────────────────────────────────────────────
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"; }

# ── Pre-flight Checks ───────────────────────────────────
preflight() {
  log "═══════════════════════════════════════════════"
  log "  SOC Backup — Starting at ${TIMESTAMP}"
  log "═══════════════════════════════════════════════"

  mkdir -p "$BACKUP_DIR"/{volumes,configs,databases,checksums}
  mkdir -p "$(dirname "$LOG_FILE")"
  touch "$LOG_FILE"

  # Check disk space (need at least 10GB free)
  local free_gb=$(df "$BACKUP_BASE" --output=avail -BG | tail -1 | tr -dc '0-9')
  if [ "$free_gb" -lt 10 ]; then
    log "❌ ERROR: Only ${free_gb}GB free on backup volume. Need >= 10GB."
    exit 1
  fi
  log "📏 Disk space: ${free_gb}GB available"
}

# ── Backup Docker Volumes ────────────────────────────────
backup_volumes() {
  log "📦 Backing up Docker volumes..."

  for vol in "${DOCKER_VOLUMES[@]}"; do
    local vol_name="${COMPOSE_PROJECT_NAME:-soc}_${vol}"
    if docker volume inspect "$vol_name" &>/dev/null; then
      log "  ✅ ${vol}..."
      docker run --rm \
        -v "${vol_name}:/source:ro" \
        -v "${BACKUP_DIR}/volumes:/backup" \
        alpine:3.19 \
        tar czf "/backup/${vol}.tar.gz" -C /source .
    else
      log "  ⏭️  ${vol}: volume not found (skipped)"
    fi
  done
}

# ── Backup Configuration Files ──────────────────────────
backup_configs() {
  log "📋 Backing up configuration files..."

  for cfg in "${CONFIG_FILES[@]}"; do
    local src="${SOC_DIR}/${cfg}"
    if [ -f "$src" ]; then
      local dst="${BACKUP_DIR}/configs/${cfg}"
      mkdir -p "$(dirname "$dst")"
      cp -p "$src" "$dst"
      log "  ✅ ${cfg}"
    else
      log "  ⏭️  ${cfg}: not found"
    fi
  done
}

# ── Database Dumps ───────────────────────────────────────
backup_databases() {
  log "🗄️  Backing up databases..."

  # PostgreSQL (TheHive + Keycloak)
  if docker ps --format '{{.Names}}' | grep -q postgres; then
    log "  ✅ PostgreSQL dump..."
    docker exec soc_postgres pg_dumpall -U postgres \
      | gzip > "${BACKUP_DIR}/databases/postgres-all.sql.gz"
  fi

  # OpenSearch snapshot
  if docker ps --format '{{.Names}}' | grep -q indexer; then
    log "  ✅ OpenSearch snapshot..."
    curl -s -XPUT "localhost:9200/_snapshot/backup" \
      -H 'Content-Type: application/json' \
      -d '{"type":"fs","settings":{"location":"/backup"}}' \
      > /dev/null 2>&1 || true
    curl -s -XPUT "localhost:9200/_snapshot/backup/${TIMESTAMP}?wait_for_completion=true" \
      > "${BACKUP_DIR}/databases/opensearch-snapshot.json" 2>&1 || true
  fi
}

# ── Generate Checksums ───────────────────────────────────
generate_checksums() {
  log "🔒 Generating checksums..."
  cd "$BACKUP_DIR"
  find . -type f ! -path './checksums/*' -exec sha256sum {} \; \
    > checksums/SHA256SUMS
  log "  ✅ $(wc -l < checksums/SHA256SUMS) files checksummed"
}

# ── Create Tarball ───────────────────────────────────────
create_archive() {
  log "📦 Creating backup archive..."
  local archive="${BACKUP_BASE}/soc-backup-${TIMESTAMP}.tar.gz"
  tar czf "$archive" -C "$BACKUP_BASE" "$TIMESTAMP"
  rm -rf "$BACKUP_DIR"

  local size_mb=$(du -sm "$archive" | cut -f1)
  local sha=$(sha256sum "$archive" | cut -d' ' -f1)
  echo "${sha}  $(basename "$archive")" > "${archive}.sha256"

  log "  📏 Size: ${size_mb}MB"
  log "  🔒 SHA-256: ${sha}"
}

# ── Cross-Region Replication ────────────────────────────
replicate_remote() {
  if [ -z "$REMOTE_TARGET" ]; then
    log "ℹ️  No remote target configured. Skipping replication."
    return
  fi

  log "☁️  Replicating to ${REMOTE_TARGET}..."
  local archive="${BACKUP_BASE}/soc-backup-${TIMESTAMP}.tar.gz"

  if command -v aws &>/dev/null; then
    aws s3 cp "$archive" "${REMOTE_TARGET}/" --storage-class STANDARD_IA
    aws s3 cp "${archive}.sha256" "${REMOTE_TARGET}/"
    log "  ✅ Replicated to S3"
  elif command -v gsutil &>/dev/null; then
    gsutil cp "$archive" "${REMOTE_TARGET}/"
    gsutil cp "${archive}.sha256" "${REMOTE_TARGET}/"
    log "  ✅ Replicated to GCS"
  elif command -v rclone &>/dev/null; then
    rclone copy "$archive" "${REMOTE_TARGET}/"
    rclone copy "${archive}.sha256" "${REMOTE_TARGET}/"
    log "  ✅ Replicated via rclone"
  else
    log "  ⚠️  No cloud CLI found. Install aws, gsutil, or rclone."
  fi
}

# ── Retention Cleanup ────────────────────────────────────
cleanup_old() {
  log "🧹 Cleaning backups older than ${RETENTION_DAYS} days..."
  find "$BACKUP_BASE" -name "soc-backup-*.tar.gz" -mtime "+${RETENTION_DAYS}" -delete -print \
    | while read f; do log "  🗑️  $(basename "$f")"; done
  find "$BACKUP_BASE" -name "*.sha256" -mtime "+${RETENTION_DAYS}" -delete 2>/dev/null || true
}

# ── Restore ──────────────────────────────────────────────
restore() {
  local archive="${1:?Usage: backup-dr.sh restore <archive.tar.gz>}"

  if [ ! -f "$archive" ]; then
    log "❌ Archive not found: $archive"
    exit 1
  fi

  # Verify integrity
  if [ -f "${archive}.sha256" ]; then
    if sha256sum -c "${archive}.sha256" --quiet; then
      log "✅ Archive integrity verified"
    else
      log "❌ INTEGRITY FAILURE — archive may be corrupted"
      exit 1
    fi
  fi

  log "🔄 Restoring from $(basename "$archive")..."
  local restore_dir=$(mktemp -d)
  tar xzf "$archive" -C "$restore_dir"

  # Restore config files
  log "  📋 Restoring configuration..."
  find "$restore_dir" -path '*/configs/*' -type f | while read f; do
    local rel=${f#*configs/}
    mkdir -p "$(dirname "${SOC_DIR}/${rel}")"
    cp -p "$f" "${SOC_DIR}/${rel}"
    log "    ✅ ${rel}"
  done

  # Restore volumes
  log "  📦 Restoring volumes..."
  for vol_tar in "$restore_dir"/*/volumes/*.tar.gz; do
    local vol_name=$(basename "$vol_tar" .tar.gz)
    local full_name="${COMPOSE_PROJECT_NAME:-soc}_${vol_name}"
    if docker volume inspect "$full_name" &>/dev/null; then
      docker run --rm \
        -v "${full_name}:/target" \
        -v "$(dirname "$vol_tar"):/backup:ro" \
        alpine:3.19 \
        sh -c "rm -rf /target/* && tar xzf /backup/$(basename "$vol_tar") -C /target"
      log "    ✅ ${vol_name}"
    fi
  done

  # Restore database
  log "  🗄️  Restoring PostgreSQL..."
  if [ -f "$restore_dir"/*/databases/postgres-all.sql.gz ]; then
    zcat "$restore_dir"/*/databases/postgres-all.sql.gz \
      | docker exec -i soc_postgres psql -U postgres
    log "    ✅ PostgreSQL restored"
  fi

  rm -rf "$restore_dir"

  log "🔄 Restarting services..."
  cd "$SOC_DIR" && docker compose restart

  log "✅ Restore complete. RTO target: ≤ 4 hours."
}

# ── Verify Backup ────────────────────────────────────────
verify() {
  local archive="${1:?Usage: backup-dr.sh verify <archive.tar.gz>}"

  log "🔍 Verifying backup: $(basename "$archive")"

  # Check archive integrity
  if [ -f "${archive}.sha256" ]; then
    if sha256sum -c "${archive}.sha256" --quiet; then
      log "  ✅ SHA-256 checksum OK"
    else
      log "  ❌ SHA-256 MISMATCH"
      exit 1
    fi
  fi

  # Check archive contents
  local count=$(tar tzf "$archive" | wc -l)
  local size_mb=$(du -sm "$archive" | cut -f1)
  log "  📏 ${count} files, ${size_mb}MB"

  # Check internal checksums
  local tmpdir=$(mktemp -d)
  tar xzf "$archive" -C "$tmpdir"
  if [ -f "$tmpdir"/*/checksums/SHA256SUMS ]; then
    cd "$tmpdir"/*/
    if sha256sum -c checksums/SHA256SUMS --quiet 2>/dev/null; then
      log "  ✅ All internal checksums verified"
    else
      log "  ❌ Some internal checksums failed"
      sha256sum -c checksums/SHA256SUMS 2>&1 | grep FAILED
    fi
  fi
  rm -rf "$tmpdir"

  log "✅ Backup verification complete"
}

# ── Main ─────────────────────────────────────────────────
case "${1:-backup}" in
  backup)
    preflight
    backup_configs
    backup_databases
    backup_volumes
    generate_checksums
    create_archive
    replicate_remote
    cleanup_old
    log "✅ Backup complete: soc-backup-${TIMESTAMP}.tar.gz"
    ;;
  restore)
    restore "$2"
    ;;
  verify)
    verify "$2"
    ;;
  list)
    echo "Available backups:"
    ls -lhS "$BACKUP_BASE"/soc-backup-*.tar.gz 2>/dev/null || echo "  No backups found"
    ;;
  *)
    echo "Usage: backup-dr.sh [backup|restore <file>|verify <file>|list]"
    echo "  backup   Full backup of configs, databases, volumes"
    echo "  restore  Restore from archive with integrity check"
    echo "  verify   Verify archive integrity without restoring"
    echo "  list     List available backups"
    ;;
esac
