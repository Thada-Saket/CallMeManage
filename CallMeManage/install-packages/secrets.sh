# Config file, keys, certificate and call-home address (sourced by install.sh).
# Nothing that already exists is overwritten.

# openssl 3.0 (Ubuntu 24.04) has no -quiet: hide its progress dots, show the output only on failure
run_quiet() {
    if [[ "${DRY_RUN:-0}" == "1" ]]; then printf '  (dry-run) %s\n' "$*"; return; fi
    local output
    if ! output="$("$@" 2>&1)"; then printf '%s\n' "$output" >&2; die "failed: $1 $2"; fi
}
create_config_file() {
    step "Config file ($CONF_FILE)"
    run install -d -m 0750 -o root -g "$APP_GROUP" "$CONF_DIR"
    if [[ -f "$CONF_FILE" ]]; then
        skip "exists (only empty values are filled)"
    else
        todo "create from install-packages/callmemanage.conf.example"
        run install -m 0640 -o root -g "$APP_GROUP" "$PROJECT_ROOT/install-packages/callmemanage.conf.example" "$CONF_FILE"
        if [[ -f "$LEGACY_ENV_FILE" ]]; then migrate_legacy_env; fi
    fi
    if conf_unset JWT_SECRET_KEY; then todo "generate JWT_SECRET_KEY"; conf_set JWT_SECRET_KEY "$(random_secret 32)"; else skip "JWT_SECRET_KEY"; fi
    if conf_unset SSH_KEY_PATH; then conf_set SSH_KEY_PATH "tools/keys/rsa_key.pem"; fi
    if conf_unset TLS_CERT_FILE; then conf_set TLS_CERT_FILE "$CERT_DIR/server.crt"; fi
    if conf_unset TLS_KEY_FILE; then conf_set TLS_KEY_FILE "$CERT_DIR/server.key"; fi
}

# An install from before the config file kept everything in <project>/.env: move every
# value over (renamed where needed), switch on the features that were filled in, then
# keep the old file as .env.migrated so nothing reads it by mistake.
migrate_legacy_env() {
    todo "move the values from .env (the old file stays as .env.migrated)"
    [[ "${DRY_RUN:-0}" == "1" ]] && return
    python3 - "$LEGACY_ENV_FILE" "$CONF_FILE" <<'PY'
import sys
from urllib.parse import urlparse

legacy_path, conf_path = sys.argv[1], sys.argv[2]
old = {}
for line in open(legacy_path, encoding="utf-8"):
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        key, value = line.split("=", 1)
        old[key.strip()] = value.strip()

TEST_SECRETS = {"1x0000000000000000000000000000000AA", "2x0000000000000000000000000000000AA",
                "3x0000000000000000000000000000000AA"}
new = {}
for key, value in old.items():
    if key in {"VITE_API_URL", "GOOGLE_REDIRECT_URI", "FRONTEND_BASE_URL", "TURNSTILE_EXPECTED_HOSTNAME"}:
        continue  # derived from SITE_URL + ROOT_PATH now
    new.update({"VITE_BASE_PATH": {"ROOT_PATH": value},
                "VITE_TURNSTILE_SITE_KEY": {"TURNSTILE_SITE_KEY": value}}.get(key, {key: value}))

frontend = urlparse(old.get("FRONTEND_BASE_URL", ""))
if frontend.scheme and frontend.netloc:
    new["SITE_URL"] = f"{frontend.scheme}://{frontend.netloc}"
elif old.get("TURNSTILE_EXPECTED_HOSTNAME", "localhost") not in {"", "localhost", "127.0.0.1"}:
    new["SITE_URL"] = f"https://{old['TURNSTILE_EXPECTED_HOSTNAME']}"
real_turnstile = old.get("TURNSTILE_SECRET_KEY") and old["TURNSTILE_SECRET_KEY"] not in TEST_SECRETS
new["TURNSTILE_ENABLED"] = "yes" if real_turnstile else "no"
new["EMAIL_ENABLED"] = "yes" if all(old.get(k) for k in ("SMTP_HOST", "SMTP_USERNAME", "SMTP_APP_PASSWORD")) else "no"
new["GOOGLE_ENABLED"] = "yes" if all(old.get(k) for k in ("GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET")) and "SITE_URL" in new else "no"

lines = open(conf_path, encoding="utf-8").read().splitlines()
for index, line in enumerate(lines):
    key = line.split("=", 1)[0] if "=" in line and not line.lstrip().startswith("#") else None
    if key in new:
        lines[index] = f"{key}={new.pop(key)}"
lines += [f"{key}={value}" for key, value in new.items()]  # keys the template does not list
with open(conf_path, "r+", encoding="utf-8") as handle:
    handle.write("\n".join(lines) + "\n")
    handle.truncate()
PY
    mv "$LEGACY_ENV_FILE" "$LEGACY_ENV_FILE.migrated"
}

# The address devices call home to. Cisco/Huawei accept an IPv4 address only.
choose_callhome_address() {
    local force="${1:-no}"
    step "Call-home address for network devices"
    # the template leaves both empty, so a value in either marks "already chosen"
    if [[ "$force" != "force" ]] && { ! conf_unset CALLHOME_INTERFACE || ! conf_unset CALLHOME_ADDRESS; }; then
        skip "already chosen: $(current_callhome_ip) (change with --configure)"
        return
    fi
    mapfile -t rows < <(ip -4 -o addr show scope global | awk '{split($4, a, "/"); print $2" "a[1]}')
    say "  Devices must be able to reach this server at the chosen IPv4 address."
    local index=1 row
    for row in "${rows[@]}"; do say "    $index) $row"; index=$((index + 1)); done
    say "    m) type an IPv4 address myself (e.g. a NAT/public address the devices see)"
    local choice
    while true; do
        choice="$(ask "Choose [1-${#rows[@]} or m]")"
        if [[ "$choice" == "m" ]]; then
            local manual
            manual="$(ask "IPv4 address")"
            if python3 -c "import ipaddress,sys; ipaddress.IPv4Address(sys.argv[1])" "$manual" 2>/dev/null; then
                conf_set CALLHOME_ADDRESS "$manual"; CALLHOME_IP="$manual"; break
            fi
            warn "not an IPv4 address"
        elif [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#rows[@]} )); then
            read -r iface CALLHOME_IP <<<"${rows[$((choice - 1))]}"
            conf_set CALLHOME_INTERFACE "$iface"; conf_set CALLHOME_ADDRESS ""; break
        else
            warn "choose a number from the list or m"
        fi
    done
}

# Which address waits for devices to call home (port CALLHOME_PORT). Every entry is one IPv4;
# the interface name is only a label. Default: all interfaces.
choose_callhome_listen_address() {
    local force="${1:-no}" port
    port="$(conf_get CALLHOME_PORT)"
    step "Call-home listening address (port ${port:-4334})"
    if [[ "$force" != "force" ]] && ! conf_unset CALLHOME_LISTEN_ADDRESS; then
        skip "already chosen: $(conf_get CALLHOME_LISTEN_ADDRESS) (change with --configure)"
        return
    fi
    mapfile -t rows < <(ip -4 -o addr show scope global | awk '{split($4, a, "/"); print $2" "a[1]}')
    say "  Which address of this server waits for devices to call home?"
    say "    0) all interfaces (0.0.0.0)   [default]"
    local index=1 row iface address
    for row in "${rows[@]}"; do
        read -r iface address <<<"$row"
        say "    $index) $iface ($address)"
        index=$((index + 1))
    done
    local choice
    while true; do
        choice="$(ask "Choose [0-${#rows[@]}, Enter = 0]")"
        if [[ -z "$choice" || "$choice" == "0" ]]; then
            conf_set CALLHOME_LISTEN_ADDRESS "0.0.0.0"; break
        elif [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#rows[@]} )); then
            read -r iface address <<<"${rows[$((choice - 1))]}"
            conf_set CALLHOME_LISTEN_ADDRESS "$address"; break
        else
            warn "choose a number from the list"
        fi
    done
    say "  Listening on $(conf_get CALLHOME_LISTEN_ADDRESS)"
}

current_callhome_ip() {
    local address iface
    address="$(conf_get CALLHOME_ADDRESS)"
    if [[ -n "$address" ]]; then printf '%s' "$address"; return; fi
    iface="$(conf_get CALLHOME_INTERFACE)"
    ip -4 -o addr show dev "${iface:-tailscale0}" 2>/dev/null | awk '{split($4, a, "/"); print a[1]; exit}'
}

create_ssh_keys() {
    step "Call-home SSH key (tools/keys)"
    run install -d -m 0700 -o "$APP_USER" -g "$(id -gn "$APP_USER")" "$KEY_DIR"
    if [[ -f "$KEY_DIR/rsa_key.pem" ]]; then
        skip "rsa_key.pem"
    else
        todo "RSA 2048 private key (same format as the original: PKCS#1 PEM)"
        run_quiet openssl genrsa -traditional -out "$KEY_DIR/rsa_key.pem" 2048
    fi
    if [[ -f "$KEY_DIR/rsa_public_key.pem" ]]; then
        skip "rsa_public_key.pem"
    else
        todo "public key from rsa_key.pem"
        run_quiet openssl rsa -in "$KEY_DIR/rsa_key.pem" -pubout -out "$KEY_DIR/rsa_public_key.pem"
    fi
    run chmod 0600 "$KEY_DIR/rsa_key.pem"
    run chmod 0644 "$KEY_DIR/rsa_public_key.pem"
    run chown "$APP_USER:$(id -gn "$APP_USER")" "$KEY_DIR/rsa_key.pem" "$KEY_DIR/rsa_public_key.pem"
}

create_certificate() {
    step "HTTPS certificate (self-signed, tools/keys/cert)"
    run install -d -m 0700 -o "$APP_USER" -g "$(id -gn "$APP_USER")" "$CERT_DIR"
    if [[ -f "$CERT_DIR/server.crt" && -f "$CERT_DIR/server.key" ]]; then
        skip "server.crt / server.key"
        return
    fi
    local ip san
    ip="$(current_callhome_ip)"
    san="DNS:localhost,IP:127.0.0.1${ip:+,IP:$ip}"
    todo "self-signed certificate for $san (browsers will warn - expected)"
    run_quiet openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj "/CN=localhost" \
        -addext "subjectAltName=$san" -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.crt"
    run chmod 0600 "$CERT_DIR/server.key"
    run chown "$APP_USER:$(id -gn "$APP_USER")" "$CERT_DIR/server.key" "$CERT_DIR/server.crt"
}
