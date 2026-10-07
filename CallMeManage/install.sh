#!/usr/bin/env bash
# CallMe Manage installer for Ubuntu 24.04. Installs everything, writes the config file
# /etc/callmemanage/callmemanage.conf and runs the system as services that start on boot:
# the website (FRONTEND_PORT, default 8080) and the backend (API 8000, device call-home 4334).
#
#   sudo ./install.sh               install, or update after `git pull` (safe to run again:
#                                   existing things are skipped, answers are kept)
#   sudo ./install.sh --configure   choose the call-home addresses, website address and
#                                   bootstrap URL again
#   sudo ./install.sh --uninstall   same as sudo ./uninstall.sh: remove the services, command and
#                                   config file (asks about the database and keys) to start over
#        ./install.sh --check       check the config file only
#   DRY_RUN=1 ./install.sh          show what would be done, change nothing
#
# Afterwards everything is done with the callmemanage command (callmemanage help).
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRY_RUN="${DRY_RUN:-0}"
MODE="${1:-install}"
APP_USER="${APP_USER:-${SUDO_USER:-$(id -un)}}"

source "$PROJECT_ROOT/install-packages/lib.sh"
source "$PROJECT_ROOT/install-packages/system.sh"
source "$PROJECT_ROOT/install-packages/database.sh"
source "$PROJECT_ROOT/install-packages/secrets.sh"
source "$PROJECT_ROOT/install-packages/backend.sh"
source "$PROJECT_ROOT/install-packages/frontend.sh"
source "$PROJECT_ROOT/install-packages/configure.sh"
source "$PROJECT_ROOT/install-packages/service.sh"
source "$PROJECT_ROOT/install-packages/uninstall.sh"

check_config() {
    step "Checking $CONF_FILE"
    if [[ -x "$VENV_DIR/bin/python" ]]; then
        as_app_user "cd '$PROJECT_ROOT' && '$VENV_DIR/bin/python' tools/env_check.py"
    else
        warn ".venv not created yet - run: sudo ./install.sh"
        return 1
    fi
}

case "$MODE" in
    --check)
        check_config
        exit $?
        ;;
    install|--configure|--uninstall) ;;
    *)
        die "unknown option '$MODE' (use --configure, --uninstall or --check)"
        ;;
esac

if [[ "$DRY_RUN" != "1" && "${EUID}" -ne 0 ]]; then
    die "run with sudo: sudo ./install.sh $([[ "$MODE" == install ]] || echo "$MODE")"
fi
if [[ "$DRY_RUN" != "1" && "$APP_USER" == "root" ]]; then
    die "run through sudo from the user that owns the project (the app must not run as root)"
fi

if [[ "$MODE" == "--uninstall" ]]; then
    uninstall_callmemanage
    exit 0
fi

if [[ "$MODE" == "--configure" ]]; then
    [[ -f "$CONF_FILE" ]] || die "$CONF_FILE not found - run the full install first"
    choose_callhome_address force
    choose_callhome_listen_address force
    configure_site
    configure_bootstrap
    configure_external_services
    configure_signup
    check_config || true
    build_frontend_if_needed
    restart_services || true
    say ""
    say "If the call-home address changed: delete tools/keys/cert/server.* and run the full install"
    say "again to issue a certificate for the new address."
    exit 0
fi

say "CallMe Manage installer (project: $PROJECT_ROOT, user: $APP_USER)"
install_system_packages
install_nodejs
start_services
create_config_file
setup_postgresql
setup_redis
choose_callhome_address
choose_callhome_listen_address
create_ssh_keys
create_certificate
install_backend
migrate_database
install_frontend

# Questions are asked only on the first install; an update after `git pull` keeps the answers
# (change them with `sudo callmemanage config`, `callmemanage setup ...` or --configure).
if [[ ! -f "$BUILT_ROOT_FILE" ]]; then
    configure_site
    configure_bootstrap
    configure_external_services
    configure_signup
fi
create_first_account

# always rebuild: the website code may have changed with `git pull`
build_frontend
install_services

say ""
if check_config && restart_services; then
    say ""
    say "CallMe Manage is running. Open:"
    website_urls
    say ""
    say "Manage it with the callmemanage command:"
    say "  callmemanage status                      is it running? where is the website?"
    say "  sudo callmemanage config                 edit all settings (checked and applied for you)"
    say "  sudo callmemanage setup turnstile|email|google   turn on one service step by step"
    say "  sudo callmemanage user add | passwd <name>       website accounts"
    say "  callmemanage help                        everything else"
else
    say ""
    say "Installed, but the system is not running yet. Fix the items above with:"
    say "  sudo callmemanage config        then it starts by itself"
fi
