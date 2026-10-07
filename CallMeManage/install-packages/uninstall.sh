# Remove what install.sh set up, so the next install starts from the questions again
# (sourced by install.sh: sudo ./install.sh --uninstall, or callmemanage uninstall).
#
# Always removed: the services, the callmemanage command and /etc/callmemanage (a root-only
# backup copy of the config file is kept). Asked one by one, default "no": the database, the
# Redis password, the files built in the project folder and the call-home key.
# Never removed: PostgreSQL, Redis, Node.js and Python themselves, and the project code.

uninstall_callmemanage() {
    step "Uninstall CallMe Manage"
    say "  Removes the services, the callmemanage command and the config file $CONF_FILE"
    say "  (a backup copy is kept). PostgreSQL, Redis, Node.js and the project code stay installed."
    say ""

    # every question first - nothing changes before the final confirmation
    local drop_db=no redis_pw=no built_files=no keys=no
    if [[ -f "$CONF_FILE" ]] && ! conf_unset DB_URL && uses_managed_local_database; then
        yes_no "Also delete the database ${DB_NAME} and its user? All accounts, sites and devices are lost" n \
            && drop_db=yes
    fi
    if [[ "$(conf_get REDIS_URL)" == redis://:*@* ]]; then
        yes_no "Also remove the Redis password? Only if no other program on this machine uses this Redis" n \
            && redis_pw=yes
    fi
    yes_no "Also delete the files built in the project folder (.venv, node_modules, website build, logs)? Kept = faster reinstall" n \
        && built_files=yes
    if [[ -d "$KEY_DIR" ]]; then
        yes_no "Also delete the call-home SSH key and HTTPS certificate (tools/keys)? Devices already added must then be added again" n \
            && keys=yes
    fi

    say ""
    say "  Will remove: services, callmemanage command, config file"
    [[ "$drop_db" == yes ]] && say "               database ${DB_NAME} and its user"
    [[ "$redis_pw" == yes ]] && say "               the Redis password"
    [[ "$built_files" == yes ]] && say "               .venv, node_modules, website build, logs"
    [[ "$keys" == yes ]] && say "               tools/keys (call-home key, certificate)"
    say ""
    yes_no "Remove everything listed above now?" n || { say "  Cancelled - nothing was changed."; return 0; }

    step "Services"
    local unit
    for unit in "$GROUP_UNIT" "${SERVICES[@]}" "${OLD_UNITS[@]}"; do
        if [[ -f "$UNIT_DIR/$unit" ]]; then
            todo "stop and remove $unit"
            run systemctl disable --now --quiet "$unit" 2>/dev/null || true
            run rm -f "$UNIT_DIR/$unit"
        fi
    done
    [[ -f "$UNIT_DIR/$GROUP_SLICE" ]] && { todo "remove $GROUP_SLICE"; run rm -f "$UNIT_DIR/$GROUP_SLICE"; }
    run systemctl daemon-reload
    run systemctl reset-failed "${SERVICES[@]}" "$GROUP_UNIT" 2>/dev/null || true
    if [[ -f /usr/local/bin/callmemanage ]]; then todo "remove /usr/local/bin/callmemanage"; run rm -f /usr/local/bin/callmemanage; fi

    # read what the config file knows before it goes away
    local redis_url
    redis_url="$(conf_get REDIS_URL)"

    if [[ "$drop_db" == yes ]]; then
        step "PostgreSQL"
        todo "drop database ${DB_NAME} and role ${DB_ROLE}"
        if [[ "${DRY_RUN:-0}" != "1" ]]; then
            runuser -u postgres -- psql -v ON_ERROR_STOP=1 -v db="$DB_NAME" -v role="$DB_ROLE" -q <<'SQL' \
                || warn "could not drop them - is PostgreSQL running? (sudo -u postgres psql to do it by hand)"
SELECT format('DROP DATABASE IF EXISTS %I WITH (FORCE)', :'db') \gexec
SELECT format('DROP ROLE IF EXISTS %I', :'role') \gexec
SQL
        fi
    fi

    if [[ "$redis_pw" == yes ]]; then
        step "Redis"
        todo "remove the Redis password (requirepass) and save redis.conf"
        if [[ "${DRY_RUN:-0}" != "1" ]]; then
            local password
            password="$(REDIS_URL_VALUE="$redis_url" python3 -c 'import os; from urllib.parse import urlsplit, unquote; print(unquote(urlsplit(os.environ["REDIS_URL_VALUE"]).password or ""), end="")')"
            if REDISCLI_AUTH="$password" redis-cli -h 127.0.0.1 -p "$REDIS_PORT" CONFIG SET requirepass "" >/dev/null 2>&1; then
                redis-cli -h 127.0.0.1 -p "$REDIS_PORT" CONFIG REWRITE >/dev/null 2>&1 \
                    || warn "redis.conf not saved - remove the requirepass line from /etc/redis/redis.conf by hand"
            else
                warn "Redis did not accept the saved password - remove requirepass from /etc/redis/redis.conf by hand"
            fi
        fi
    fi

    step "Config file"
    if [[ -f "$CONF_FILE" ]]; then
        local backup
        backup="/root/callmemanage.conf.$(date +%Y%m%d-%H%M%S).bak"
        todo "keep a root-only backup: $backup"
        run install -m 0600 -o root -g root "$CONF_FILE" "$backup"
        run rm -rf "$CONF_DIR"
    else
        skip "$CONF_FILE not found"
    fi

    if [[ "$built_files" == yes ]]; then
        step "Files built in the project folder"
        local path
        for path in "$VENV_DIR" "$FRONTEND_DIR/node_modules" "$FRONTEND_DIR/dist" "$PROJECT_ROOT/logs"; do
            [[ -e "$path" ]] && { todo "remove $path"; run rm -rf "$path"; }
        done
    fi
    if [[ "$keys" == yes ]]; then
        step "Call-home key and certificate"
        todo "remove $KEY_DIR"
        run rm -rf "$KEY_DIR"
    fi

    say ""
    say "CallMe Manage is uninstalled. Install again with:  sudo ./install.sh"
    [[ "$drop_db" == yes ]] || say "The database ${DB_NAME} was kept: the next install asks for a new password for its user and keeps the data."
}
