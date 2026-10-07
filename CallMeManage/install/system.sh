# System packages and Node.js (sourced by install_service.sh). Anything present is skipped.

APT_PACKAGES=(python3 python3-pip python3-venv postgresql postgresql-contrib redis-server
              openssl curl ca-certificates gnupg)
NODE_MAJOR=22
NODE_MIN="22.12.0"   # Vite 8 needs ^20.19.0 || >=22.12.0; Ubuntu 24.04's own nodejs is 18

install_system_packages() {
    step "System packages"
    # an existing PostgreSQL server of any version (e.g. postgresql-18 from PGDG) counts:
    # never add Ubuntu's default version next to it
    # dpkg-query exits 1 when nothing matches (a fresh machine); with pipefail that ended
    # the installer silently right here, so "nothing found" must count as success
    local existing_pg
    existing_pg="$( { dpkg-query -W -f='${Package} ${Status}\n' 'postgresql-[0-9]*' 2>/dev/null || true; } \
        | awk '/install ok installed/ && $1 ~ /^postgresql-[0-9]+$/ {print $1; exit}')"
    local missing=() package
    for package in "${APT_PACKAGES[@]}"; do
        if [[ -n "$existing_pg" && ( "$package" == "postgresql" || "$package" == "postgresql-contrib" ) ]]; then
            skip "$package (found $existing_pg, contrib modules included)"
        elif apt_installed "$package"; then
            skip "$package"
        else
            todo "$package"; missing+=("$package")
        fi
    done
    if (( ${#missing[@]} )); then
        run apt-get update
        run env DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}"
    fi
}

install_nodejs() {
    step "Node.js >= $NODE_MIN"
    local current
    current="$(/usr/bin/node -v 2>/dev/null | sed 's/^v//' || true)"
    if [[ -n "$current" ]] && version_ge "$current" "$NODE_MIN"; then
        skip "node $current"
        return
    fi
    todo "node ${NODE_MAJOR}.x from NodeSource (system node: ${current:-none})"
    if [[ ! -f /etc/apt/sources.list.d/nodesource.list ]]; then
        run install -d -m 0755 /etc/apt/keyrings
        if [[ "${DRY_RUN:-0}" == "1" ]]; then
            say "  (dry-run) download NodeSource signing key"
        else
            curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
                | gpg --dearmor --yes -o /etc/apt/keyrings/nodesource.gpg
            echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_${NODE_MAJOR}.x nodistro main" \
                > /etc/apt/sources.list.d/nodesource.list
        fi
        run apt-get update
    fi
    # NodeSource's nodejs includes npm and replaces Ubuntu's nodejs/npm packages
    run env DEBIAN_FRONTEND=noninteractive apt-get install -y nodejs
}

start_services() {
    step "PostgreSQL and Redis services"
    local service
    for service in postgresql redis-server; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            skip "$service running"
        else
            todo "enable and start $service"
            run systemctl enable --now "$service"
        fi
    done
}
