#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════
#  Unified SOC Platform — Deployment Script
#  Automated setup for the full open-source SOC stack
# ═══════════════════════════════════════════════════════════

set -euo pipefail
IFS=$'\n\t'

# ── Colors ────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ── Logging ───────────────────────────────────────────────
log()   { echo -e "${GREEN}[✔]${NC} $1"; }
info()  { echo -e "${BLUE}[ℹ]${NC} $1"; }
warn()  { echo -e "${YELLOW}[⚠]${NC} $1"; }
error() { echo -e "${RED}[✖]${NC} $1"; exit 1; }
step()  { echo -e "\n${BOLD}${CYAN}══ $1 ══${NC}"; }

# ── Banner ────────────────────────────────────────────────
banner() {
cat << 'EOF'
╔══════════════════════════════════════════════════════════╗
║         UNIFIED OPEN-SOURCE SOC PLATFORM                ║
║   SIEM │ XDR │ IDS/IPS │ SOAR │ TIP │ VULN MGMT        ║
╚══════════════════════════════════════════════════════════╝
EOF
}

# ── Variables ─────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
MIN_RAM_GB=16
MIN_DISK_GB=100

# ── Preflight Checks ──────────────────────────────────────
preflight_checks() {
    step "Preflight Checks"

    # OS check
    if [[ ! -f /etc/os-release ]]; then
        error "Cannot determine OS. This script supports Ubuntu/Debian/CentOS."
    fi
    . /etc/os-release
    log "OS: $PRETTY_NAME"

    # Root check
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root. Use: sudo $0"
    fi
    log "Running as root"

    # Docker check
    if ! command -v docker &>/dev/null; then
        warn "Docker not found. Installing..."
        install_docker
    else
        log "Docker: $(docker --version)"
    fi

    # Docker Compose check
    if ! command -v docker-compose &>/dev/null && ! docker compose version &>/dev/null; then
        warn "Docker Compose not found. Installing..."
        install_docker_compose
    else
        log "Docker Compose: available"
    fi

    # RAM check
    TOTAL_RAM_GB=$(awk '/MemTotal/ {printf "%.0f", $2/1024/1024}' /proc/meminfo)
    if [[ $TOTAL_RAM_GB -lt $MIN_RAM_GB ]]; then
        warn "RAM: ${TOTAL_RAM_GB}GB detected. Minimum recommended: ${MIN_RAM_GB}GB"
        warn "Some services may be unstable with low RAM."
    else
        log "RAM: ${TOTAL_RAM_GB}GB — OK"
    fi

    # Disk check
    AVAILABLE_DISK_GB=$(df -BG "$SCRIPT_DIR" | awk 'NR==2 {print $4}' | tr -d 'G')
    if [[ $AVAILABLE_DISK_GB -lt $MIN_DISK_GB ]]; then
        error "Disk: Only ${AVAILABLE_DISK_GB}GB free. Need at least ${MIN_DISK_GB}GB."
    else
        log "Disk: ${AVAILABLE_DISK_GB}GB free — OK"
    fi
}

# ── Install Docker ────────────────────────────────────────
install_docker() {
    info "Installing Docker..."
    curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
    sh /tmp/get-docker.sh
    systemctl enable --now docker
    log "Docker installed"
}

install_docker_compose() {
    info "Installing Docker Compose..."
    COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep '"tag_name"' | cut -d'"' -f4)
    curl -L "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" \
        -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
    log "Docker Compose installed: $COMPOSE_VERSION"
}

# ── Environment Setup ─────────────────────────────────────
setup_environment() {
    step "Environment Configuration"

    if [[ -f "$ENV_FILE" ]]; then
        warn ".env file already exists. Skipping generation."
        return
    fi

    cp "$SCRIPT_DIR/.env.example" "$ENV_FILE"

    # Generate strong random passwords
    generate_password() { openssl rand -base64 32 | tr -dc 'A-Za-z0-9!@#$%' | head -c 24; }

    # Replace placeholder passwords with generated ones
    sed -i "s/SecurePassword123!/$(generate_password)/g" "$ENV_FILE"
    sed -i "s/MISProot123!/$(generate_password)/g" "$ENV_FILE"
    sed -i "s/MISPpassword123!/$(generate_password)/g" "$ENV_FILE"
    sed -i "s/MISPadmin123!/$(generate_password)/g" "$ENV_FILE"
    sed -i "s/OpenVASpass123!/$(generate_password)/g" "$ENV_FILE"
    sed -i "s/ShufflePass123!/$(generate_password)/g" "$ENV_FILE"
    sed -i "s/ShuffleAdmin123!/$(generate_password)/g" "$ENV_FILE"

    log ".env file created with generated passwords"
    warn "Review $ENV_FILE and customize as needed before continuing"
}

# ── Directory Structure ───────────────────────────────────
create_directories() {
    step "Creating Directory Structure"

    directories=(
        "config/wazuh/rules"
        "config/wazuh/decoders"
        "config/suricata/rules"
        "config/nginx/conf.d"
        "config/nginx/certs"
        "config/thehive"
        "config/cortex"
        "config/filebeat"
        "config/shuffle/apps"
        "config/opensearch"
        "data/misp-db"
        "data/cassandra"
        "data/thehive-es"
        "data/cortex-es"
        "data/shuffle-opensearch"
        "logs/wazuh"
        "logs/suricata"
        "logs/openvas"
    )

    for dir in "${directories[@]}"; do
        mkdir -p "$SCRIPT_DIR/$dir"
    done

    log "Directory structure created"
}

# ── TLS Certificate Generation ────────────────────────────
generate_tls_certs() {
    step "Generating TLS Certificates"

    CERT_DIR="$SCRIPT_DIR/config/nginx/certs"

    if [[ -f "$CERT_DIR/soc.crt" ]]; then
        warn "TLS certificates already exist. Skipping."
        return
    fi

    # Generate self-signed CA
    openssl genrsa -out "$CERT_DIR/ca.key" 4096 2>/dev/null
    openssl req -new -x509 -days 3650 -key "$CERT_DIR/ca.key" \
        -out "$CERT_DIR/ca.crt" \
        -subj "/C=US/ST=Security/L=SOC/O=SOC Platform/CN=SOC Root CA" 2>/dev/null

    # Generate server certificate
    openssl genrsa -out "$CERT_DIR/soc.key" 4096 2>/dev/null
    openssl req -new -key "$CERT_DIR/soc.key" \
        -out "$CERT_DIR/soc.csr" \
        -subj "/C=US/ST=Security/L=SOC/O=SOC Platform/CN=soc.local" 2>/dev/null

    # Sign with CA
    cat > /tmp/soc-san.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = *.soc.local
DNS.2 = soc.local
DNS.3 = localhost
IP.1 = 127.0.0.1
EOF

    openssl x509 -req -days 3650 \
        -in "$CERT_DIR/soc.csr" \
        -CA "$CERT_DIR/ca.crt" \
        -CAkey "$CERT_DIR/ca.key" \
        -CAcreateserial \
        -out "$CERT_DIR/soc.crt" \
        -extfile /tmp/soc-san.ext 2>/dev/null

    chmod 600 "$CERT_DIR"/*.key
    log "TLS certificates generated (self-signed, valid 10 years)"
    info "Import $CERT_DIR/ca.crt into your browser to trust the certificates"
}

# ── OS Hardening ──────────────────────────────────────────
apply_os_hardening() {
    step "Applying OS Hardening"

    # Increase vm.max_map_count for OpenSearch / Elasticsearch
    if ! grep -q "vm.max_map_count=262144" /etc/sysctl.conf; then
        echo "vm.max_map_count=262144" >> /etc/sysctl.conf
        sysctl -w vm.max_map_count=262144 >/dev/null
        log "Set vm.max_map_count=262144 for OpenSearch"
    fi

    # Disable swap for OpenSearch performance
    # swapoff -a  # Uncomment to disable swap

    # Increase file descriptor limits
    if ! grep -q "* soft nofile 655360" /etc/security/limits.conf; then
        cat >> /etc/security/limits.conf << 'EOF'
* soft nofile 655360
* hard nofile 655360
* soft memlock unlimited
* hard memlock unlimited
EOF
        log "Updated file descriptor limits"
    fi

    log "OS hardening applied"
}

# ── Deploy Services ───────────────────────────────────────
deploy_services() {
    step "Deploying SOC Stack"

    cd "$SCRIPT_DIR"

    # Load env
    set -a; source "$ENV_FILE"; set +a

    info "Pulling Docker images (this may take several minutes)..."
    docker-compose pull 2>&1 | grep -E "Pulling|pulled|already" | head -30 || true

    info "Starting core services (OpenSearch + Wazuh)..."
    docker-compose up -d opensearch
    sleep 30
    docker-compose up -d wazuh-manager wazuh-dashboard
    sleep 20

    info "Starting network monitoring (Suricata + Filebeat)..."
    docker-compose up -d suricata filebeat
    sleep 10

    info "Starting threat intelligence (MISP)..."
    docker-compose up -d misp-db
    sleep 20
    docker-compose up -d misp
    sleep 15

    info "Starting case management (TheHive + Cortex)..."
    docker-compose up -d thehive-cassandra cortex-elasticsearch
    sleep 40
    docker-compose up -d cortex
    sleep 20
    docker-compose up -d thehive-elasticsearch
    sleep 20
    docker-compose up -d thehive
    sleep 15

    info "Starting vulnerability management (OpenVAS)..."
    docker-compose up -d openvas
    sleep 15

    info "Starting SOAR automation (Shuffle)..."
    docker-compose up -d shuffle-opensearch
    sleep 30
    docker-compose up -d shuffle-backend shuffle-frontend
    sleep 15

    info "Starting reverse proxy (Nginx)..."
    docker-compose up -d nginx

    log "All services deployed!"
}

# ── Health Check ──────────────────────────────────────────
health_check() {
    step "Service Health Check"

    services=(
        "wazuh-manager"
        "opensearch"
        "wazuh-dashboard"
        "suricata"
        "misp"
        "thehive"
        "cortex"
        "openvas"
        "shuffle-backend"
        "nginx"
    )

    echo ""
    printf "%-25s %s\n" "SERVICE" "STATUS"
    printf "%-25s %s\n" "───────────────────────" "──────────"

    for service in "${services[@]}"; do
        status=$(docker inspect --format='{{.State.Status}}' "$service" 2>/dev/null || echo "not found")
        health=$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}N/A{{end}}' "$service" 2>/dev/null || echo "N/A")

        if [[ "$status" == "running" ]]; then
            printf "%-25s ${GREEN}%-12s${NC} %s\n" "$service" "$status" "($health)"
        else
            printf "%-25s ${RED}%-12s${NC}\n" "$service" "$status"
        fi
    done
}

# ── Print Access Info ─────────────────────────────────────
print_access_info() {
    step "Access Information"

    source "$ENV_FILE"

    cat << EOF

${BOLD}╔══════════════════════════════════════════════════════════╗
║              SOC PLATFORM ACCESS URLS                    ║
╚══════════════════════════════════════════════════════════╝${NC}

Add these to /etc/hosts or your DNS:
  <SERVER_IP>  wazuh.soc.local misp.soc.local thehive.soc.local
  <SERVER_IP>  cortex.soc.local openvas.soc.local shuffle.soc.local

${BOLD}Service URLs:${NC}
  Wazuh SIEM Dashboard : https://wazuh.soc.local
  MISP Threat Intel    : https://misp.soc.local
  TheHive Cases        : https://thehive.soc.local
  Cortex Enrichment    : https://cortex.soc.local
  OpenVAS Vuln Mgmt    : https://openvas.soc.local
  Shuffle SOAR         : https://shuffle.soc.local

${BOLD}Default Credentials (change immediately!):${NC}
  Wazuh     : admin / (see .env OPENSEARCH_PASSWORD)
  MISP      : ${MISP_ADMIN_EMAIL:-admin@soc.local} / (see .env MISP_ADMIN_PASS)
  TheHive   : admin@thehive.local / secret
  OpenVAS   : admin / (see .env OPENVAS_PASSWORD)
  Shuffle   : (see .env SHUFFLE_ADMIN_USER / SHUFFLE_ADMIN_PASS)

${YELLOW}⚠  IMPORTANT: Change all default passwords before production use!${NC}
${YELLOW}⚠  Install CA certificate: config/nginx/certs/ca.crt${NC}

EOF
}

# ── Main ──────────────────────────────────────────────────
main() {
    banner
    echo ""

    case "${1:-deploy}" in
        deploy)
            preflight_checks
            setup_environment
            create_directories
            generate_tls_certs
            apply_os_hardening
            deploy_services
            health_check
            print_access_info
            ;;
        health)
            health_check
            ;;
        stop)
            step "Stopping SOC Platform"
            cd "$SCRIPT_DIR"
            docker-compose down
            log "All services stopped"
            ;;
        restart)
            step "Restarting SOC Platform"
            cd "$SCRIPT_DIR"
            docker-compose down
            sleep 5
            docker-compose up -d
            log "Services restarted"
            ;;
        logs)
            service="${2:-}"
            if [[ -n "$service" ]]; then
                docker logs -f "$service"
            else
                cd "$SCRIPT_DIR"
                docker-compose logs -f --tail=50
            fi
            ;;
        update)
            step "Updating SOC Platform"
            cd "$SCRIPT_DIR"
            docker-compose pull
            docker-compose up -d
            log "Update complete"
            ;;
        *)
            echo "Usage: $0 {deploy|health|stop|restart|logs [service]|update}"
            exit 1
            ;;
    esac
}

main "$@"
