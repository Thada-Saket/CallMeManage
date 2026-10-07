# Shared helpers for install_service.sh and the callmemanage command (sourced, not run directly).
# PROJECT_ROOT, APP_USER and DRY_RUN are set by the caller.

FRONTEND_DIR="$PROJECT_ROOT/frontend/cloud_management"
VENV_DIR="$PROJECT_ROOT/.venv"
CONF_DIR="/etc/callmemanage"
CONF_FILE="$CONF_DIR/callmemanage.conf"
LEGACY_ENV_FILE="$PROJECT_ROOT/.env"
KEY_DIR="$PROJECT_ROOT/tools/keys"
CERT_DIR="$KEY_DIR/cert"
APP_GROUP="$(id -gn "$APP_USER" 2>/dev/null || echo "$APP_USER")"

say()  { printf '%s\n' "$*"; }
step() { printf '\n==> %s\n' "$*"; }
skip() { printf '  [skip] %s\n' "$*"; }
todo() { printf '  [do]   %s\n' "$*"; }
warn() { printf '  [!]    %s\n' "$*" >&2; }
die()  { printf '[x] %s\n' "$*" >&2; exit 1; }
run()  { if [[ "${DRY_RUN:-0}" == "1" ]]; then printf '  (dry-run) %s\n' "$*"; else "$@"; fi; }

# run a command string as the project owner (never root), with system Node first in PATH
# and the config file location set, so every tool reads the same file
as_app_user() {
    local command="export PATH=/usr/bin:/bin:/usr/local/bin:\$PATH; export CALLMEMANAGE_CONF='${CALLMEMANAGE_CONF:-$CONF_FILE}' CALLMEMANAGE_CONF_SHOWN='${CALLMEMANAGE_CONF_SHOWN:-}'; $1"
    if [[ "$(id -un)" == "$APP_USER" ]]; then bash -c "$command"; else runuser -u "$APP_USER" -- bash -c "$command"; fi
}

version_ge() { [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" == "$2" ]]; }
apt_installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed"; }
random_secret() { python3 -c "import secrets,sys; print(secrets.token_hex(int(sys.argv[1])))" "${1:-32}"; }

# Config file access without ever printing values. Values travel in environment variables,
# not in command-line arguments (which other users could see in `ps`).
conf_get() {
    ENV_KEY="$1" python3 - "$CONF_FILE" <<'PY'
import os, sys
key = os.environ["ENV_KEY"]
try:
    for line in open(sys.argv[1], encoding="utf-8"):
        if line.startswith(key + "="):
            print(line.rstrip("\n").split("=", 1)[1]); break
except FileNotFoundError:
    pass
PY
}

conf_set() {
    [[ "${DRY_RUN:-0}" == "1" ]] && { printf '  (dry-run) set %s in %s\n' "$1" "$CONF_FILE"; return; }
    ENV_KEY="$1" ENV_VALUE="$2" python3 - "$CONF_FILE" <<'PY'
import os, sys
path, key, value = sys.argv[1], os.environ["ENV_KEY"], os.environ["ENV_VALUE"]
lines = open(path, encoding="utf-8").read().splitlines()
for index, line in enumerate(lines):
    if line.startswith(key + "="):
        lines[index] = f"{key}={value}"
        break
else:
    lines.append(f"{key}={value}")
# rewrite in place: owner, group and mode of the file stay as they are
with open(path, "r+", encoding="utf-8") as handle:
    handle.write("\n".join(lines) + "\n")
    handle.truncate()
PY
}

# true when the config value is empty or still a template placeholder
conf_unset() {
    local value
    value="$(conf_get "$1")"
    [[ -z "$value" || "$value" =~ ^(replace|change-me|your[-_]|generate[-_]) ]]
}

# ask a question; secrets are read without echo. Empty answer keeps the current value.
ask() {
    local prompt="$1" secret="${2:-no}" answer
    if [[ "$secret" == "secret" ]]; then read -r -s -p "  $prompt: " answer; echo >&2; else read -r -p "  $prompt: " answer; fi
    printf '%s' "$answer"
}

# ask with the current value shown in [brackets]; Enter keeps it
ask_default() {
    local prompt="$1" current="$2" answer
    answer="$(ask "$prompt${current:+ [$current]}")"
    printf '%s' "${answer:-$current}"
}

yes_no() {  # yes_no "question" default(y|n) -> exit 0 for yes
    local answer hint="[y/N]"
    [[ "${2:-n}" == "y" ]] && hint="[Y/n]"
    answer="$(ask "$1 $hint")"
    answer="${answer:-${2:-n}}"
    [[ "$answer" =~ ^[Yy] ]]
}

require_root() {
    [[ "${DRY_RUN:-0}" == "1" || "${EUID}" -eq 0 ]] || die "run with sudo: sudo $*"
}
