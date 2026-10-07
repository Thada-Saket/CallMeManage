# systemd services, the `callmemanage` command and the website build
# (sourced by install.sh and tools/callmemanage).

UNIT_DIR="/etc/systemd/system"
# One name controls both: `systemctl start|stop|restart callmemanage`. The two services
# share callmemanage.slice: `systemctl status callmemanage.slice` shows both at once, and
# each one can still be checked or restarted by its own name.
GROUP_UNIT="callmemanage.service"
GROUP_SLICE="callmemanage.slice"
SERVICES=(callmemanage-backend.service callmemanage-frontend.service)
OLD_UNITS=(callmemanage.target)   # replaced by callmemanage.service
BUILT_ROOT_FILE="$FRONTEND_DIR/dist/.root_path"

# ROOT_PATH as the build writes it into the website ("/" or "/cmm/")
configured_root_path() {
    local value
    value="$(conf_get ROOT_PATH)"
    value="/${value#/}"; value="${value%/}/"
    [[ "$value" == "//" ]] && value="/"
    printf '%s' "$value"
}

build_frontend() {
    step "Website build (ROOT_PATH $(configured_root_path))"
    run as_app_user "cd '$FRONTEND_DIR' && npm run build"
    [[ "${DRY_RUN:-0}" == "1" ]] || as_app_user "printf '%s' '$(configured_root_path)' > '$BUILT_ROOT_FILE'"
}

# ROOT_PATH is the only setting written into the website; rebuild only when it changed
build_frontend_if_needed() {
    if [[ -f "$FRONTEND_DIR/dist/index.html" && "$(cat "$BUILT_ROOT_FILE" 2>/dev/null)" == "$(configured_root_path)" ]]; then
        return 0
    fi
    build_frontend
}

write_unit() {  # write_unit <name> <content>: only rewritten when the content changed
    local target="$UNIT_DIR/$1"
    if [[ -f "$target" ]] && [[ "$(cat "$target")" == "$2" ]]; then return 1; fi
    if [[ "${DRY_RUN:-0}" == "1" ]]; then say "  (dry-run) write $target"; return 0; fi
    printf '%s\n' "$2" > "$target"
}

install_services() {
    step "System services (start on boot, restart after a crash)"
    local changed=0
    # earlier installs grouped the services with callmemanage.target
    local old
    for old in "${OLD_UNITS[@]}"; do
        if [[ -f "$UNIT_DIR/$old" ]]; then
            todo "replace $old with $GROUP_UNIT"
            run systemctl disable --quiet "$old" 2>/dev/null || true
            run rm -f "$UNIT_DIR/$old"
            changed=1
        fi
    done

    write_unit "$GROUP_SLICE" "[Unit]
Description=CallMe Manage (backend + website)" && changed=1

    # Starts both, and stop/restart of it reach both (they are PartOf it). It runs nothing
    # itself, so its own status is only "started" - use callmemanage.slice for the health.
    write_unit "$GROUP_UNIT" "[Unit]
Description=CallMe Manage (backend + website) - start/stop/restart both
Wants=${SERVICES[*]}
After=${SERVICES[*]}

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/true

[Install]
WantedBy=multi-user.target" && changed=1

    write_unit callmemanage-backend.service "[Unit]
Description=CallMe Manage backend (API, device bootstrap downloads, NETCONF call-home)
After=network-online.target postgresql.service redis-server.service
Wants=network-online.target
PartOf=$GROUP_UNIT
# a config mistake stops the retries after 3 tries instead of looping forever
StartLimitIntervalSec=60
StartLimitBurst=3

[Service]
Slice=$GROUP_SLICE
User=$APP_USER
Group=$APP_GROUP
WorkingDirectory=$PROJECT_ROOT
Environment=CALLMEMANAGE_CONF=$CONF_FILE
Environment=PYTHONUNBUFFERED=1
ExecStartPre=$VENV_DIR/bin/python tools/env_check.py
ExecStart=$VENV_DIR/bin/python app.py
Restart=on-failure
RestartSec=5
# lets the service use ports below 1024 (e.g. 443) without running as root
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes

[Install]
WantedBy=$GROUP_UNIT" && changed=1

    write_unit callmemanage-frontend.service "[Unit]
Description=CallMe Manage website (vite preview, forwards <ROOT_PATH>api to the backend)
After=network-online.target callmemanage-backend.service
Wants=network-online.target
PartOf=$GROUP_UNIT
StartLimitIntervalSec=60
StartLimitBurst=3

[Service]
Slice=$GROUP_SLICE
User=$APP_USER
Group=$APP_GROUP
WorkingDirectory=$FRONTEND_DIR
Environment=CALLMEMANAGE_CONF=$CONF_FILE
ExecStart=$FRONTEND_DIR/node_modules/.bin/vite preview
# Node exits with 143 (128 + SIGTERM) when systemd stops it: that is a normal stop
SuccessExitStatus=143
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes

[Install]
WantedBy=$GROUP_UNIT" && changed=1

    if (( changed )); then todo "systemd units"; run systemctl daemon-reload; else skip "systemd units up to date"; fi
    run systemctl enable --quiet "$GROUP_UNIT" "${SERVICES[@]}"

    step "The callmemanage command"
    local wrapper="#!/usr/bin/env bash
# installed by $PROJECT_ROOT/install.sh
export CALLMEMANAGE_PROJECT='$PROJECT_ROOT' CALLMEMANAGE_USER='$APP_USER'
exec '$PROJECT_ROOT/tools/callmemanage' \"\$@\""
    if [[ -f /usr/local/bin/callmemanage && "$(cat /usr/local/bin/callmemanage)" == "$wrapper" ]]; then
        skip "/usr/local/bin/callmemanage"
    elif [[ "${DRY_RUN:-0}" == "1" ]]; then
        say "  (dry-run) write /usr/local/bin/callmemanage"
    else
        todo "/usr/local/bin/callmemanage"
        printf '%s\n' "$wrapper" > /usr/local/bin/callmemanage
        chmod 0755 /usr/local/bin/callmemanage
    fi
}

# ./install-packages/start_service.sh (the old way of running) holds the same ports
foreground_copy_running() {
    pgrep -u "$APP_USER" -f "start_service.sh" >/dev/null 2>&1
}

restart_services() {
    if foreground_copy_running; then
        warn "./install-packages/start_service.sh is still running and holds the ports - stop it (Ctrl+C), then: sudo callmemanage restart"
        return 1
    fi
    run systemctl reset-failed "${SERVICES[@]}" 2>/dev/null || true
    run systemctl restart "$GROUP_UNIT"
    [[ "${DRY_RUN:-0}" == "1" ]] && return 0
    local unit waited
    for waited in 1 2 3 4 5 6 7 8 9 10; do
        sleep 1
        # (is-active with several units succeeds when any one is up, so check each)
        systemctl is-active --quiet "${SERVICES[0]}" && systemctl is-active --quiet "${SERVICES[1]}" && break
    done
    for unit in "${SERVICES[@]}"; do
        if systemctl is-active --quiet "$unit"; then
            say "  [ok] $unit"
        else
            warn "$unit did not start - see: callmemanage logs ${unit#callmemanage-}"
            warn "$(journalctl -u "$unit" -n 8 --no-pager -o cat 2>/dev/null | sed 's/^/        /')"
            return 1
        fi
    done
}

# where people open the website
website_urls() {
    local root site ip port
    root="$(configured_root_path)"
    site="$(conf_get SITE_URL)"
    port="$(conf_get FRONTEND_PORT)"; port="${port:-8080}"
    ip="$(current_callhome_ip)"
    [[ -n "$site" ]] && say "    $site$root"
    say "    https://${ip:-<this machine>}$([[ "$port" == 443 ]] || echo ":$port")$root"
}
