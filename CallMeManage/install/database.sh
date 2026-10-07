# Local PostgreSQL database/user and Redis connection (sourced by install_service.sh).
# Already-configured DB_URL / REDIS_URL in the config file are left alone (e.g. an existing remote DB).
# Passwords are always chosen by the user - never generated - and may contain any character:
# they are percent-encoded inside DB_URL / REDIS_URL and never pass through a command line.

DB_NAME="callmemanage"
DB_ROLE="callmemanage"
REDIS_PORT="${REDIS_PORT:-6379}"


# Read a new password twice, without echo and without trimming spaces. Prints it on stdout.
ask_new_password() {
    local label="$1" first second
    while true; do
        IFS= read -r -s -p "  $label: " first; echo >&2
        if [[ -z "$first" ]]; then warn "the password cannot be empty"; continue; fi
        IFS= read -r -s -p "  Type it again: " second; echo >&2
        [[ "$first" == "$second" ]] && break
        warn "the two passwords are different - try again"
    done
    printf '%s' "$first"
}

# Read an existing password once (no echo, no trimming)
ask_existing_password() {
    local value
    IFS= read -r -s -p "  $1: " value; echo >&2
    printf '%s' "$value"
}

# Percent-encode a password for use inside a URL (value through the environment, not argv)
url_quote() {
    URL_PART="$1" python3 -c 'import os, urllib.parse; print(urllib.parse.quote(os.environ["URL_PART"], safe=""), end="")'
}

uses_managed_local_database() {
    local url
    url="$(conf_get DB_URL)"
    DB_URL_VALUE="$url" DB_NAME_VALUE="$DB_NAME" DB_ROLE_VALUE="$DB_ROLE" python3 - <<'PY'
import os
from urllib.parse import urlparse

url = os.environ.get("DB_URL_VALUE", "").replace("postgresql+asyncpg://", "postgresql://", 1)
parsed = urlparse(url)
is_managed = (
    parsed.scheme == "postgresql"
    and parsed.hostname in {"127.0.0.1", "localhost"}
    and (parsed.port or 5432) == 5432
    and parsed.username == os.environ["DB_ROLE_VALUE"]
    and parsed.path.lstrip("/") == os.environ["DB_NAME_VALUE"]
)
raise SystemExit(0 if is_managed else 1)
PY
}


grant_managed_database_permissions() {
    # PostgreSQL 15+ no longer grants CREATE on schema public to everyone. The
    # application role owns its dedicated database/schema so Alembic can create
    # and alter objects, while no privilege is granted outside this database.
    runuser -u postgres -- psql -v ON_ERROR_STOP=1 -v db="$DB_NAME" -v role="$DB_ROLE" -q <<'SQL'
SELECT format('ALTER DATABASE %I OWNER TO %I', :'db', :'role') \gexec
SQL
    runuser -u postgres -- psql -v ON_ERROR_STOP=1 -v role="$DB_ROLE" -d "$DB_NAME" -q <<'SQL'
ALTER SCHEMA public OWNER TO :"role";
GRANT USAGE, CREATE ON SCHEMA public TO :"role";
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO :"role";
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO :"role";
SQL
}


setup_postgresql() {
    step "PostgreSQL database"
    if ! conf_unset DB_URL; then
        if uses_managed_local_database; then
            todo "verify owner and public schema permissions for local database ${DB_NAME}"
            run grant_managed_database_permissions
        else
            skip "DB_URL already set in the config file (external or custom database; permissions left unchanged)"
        fi
        return
    fi
    local password exists
    exists="$(runuser -u postgres -- psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='${DB_ROLE}'" 2>/dev/null || true)"
    say "  CallMe Manage keeps its data in its own database \"${DB_NAME}\", owned by the database"
    say "  user \"${DB_ROLE}\". Other databases and users on this PostgreSQL are not touched."
    if [[ "$exists" == "1" ]]; then
        # role exists but the config file lost its URL: its password becomes the one typed now
        say "  The database user ${DB_ROLE} already exists; it gets the password you type now."
        todo "set the password of existing role ${DB_ROLE}"
    else
        todo "create role ${DB_ROLE} and database ${DB_NAME}"
    fi
    if [[ "${DRY_RUN:-0}" == "1" ]]; then
        say "  (dry-run) ask for the password, psql create/alter role, create database"
        password="dry-run"
    else
        password="$(ask_new_password "Choose a password for database user ${DB_ROLE} (any characters)")"
        # password passed through stdin (psql variable), never on a command line
        printf '%s' "$password" | runuser -u postgres -- bash -c "
            psql -v ON_ERROR_STOP=1 -v role='${DB_ROLE}' -v pw=\"\$(cat)\" -q <<'SQL'
SELECT format('CREATE ROLE %I LOGIN', :'role') WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'role') \\gexec
ALTER ROLE :\"role\" WITH LOGIN PASSWORD :'pw';
SQL"
        if [[ "$(runuser -u postgres -- psql -tAc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'")" != "1" ]]; then
            runuser -u postgres -- createdb -O "$DB_ROLE" "$DB_NAME"
        fi
        grant_managed_database_permissions
    fi
    conf_set DB_URL "postgresql+asyncpg://${DB_ROLE}:$(url_quote "$password")@127.0.0.1:5432/${DB_NAME}"
}

setup_redis() {
    step "Redis"
    if ! conf_unset REDIS_URL; then
        skip "REDIS_URL already set in the config file"
        return
    fi
    local reply password="" choice bind
    reply="$(redis-cli -h 127.0.0.1 -p "$REDIS_PORT" ping 2>&1 || true)"
    if [[ "$reply" == "PONG" ]]; then
        bind="$(redis-cli -h 127.0.0.1 -p "$REDIS_PORT" CONFIG GET bind 2>/dev/null | sed -n 2p || true)"
        say "  Redis answers without a password (it listens on: ${bind:-unknown})."
        say "    1) Keep Redis without a password   [default]"
        say "    2) Set a password for Redis now - every other program that uses this Redis"
        say "       will need it too"
        while true; do
            choice="$(ask "Choose [1-2, Enter = 1]")"
            [[ -z "$choice" || "$choice" == "1" || "$choice" == "2" ]] && break
            warn "choose 1 or 2"
        done
        if [[ "$choice" == "2" ]]; then
            if [[ "${DRY_RUN:-0}" == "1" ]]; then
                say "  (dry-run) ask for the password, CONFIG SET requirepass, CONFIG REWRITE"
                password="dry-run"
            else
                password="$(ask_new_password "Choose a Redis password (any characters)")"
                todo "set the Redis password (requirepass) and save it to redis.conf"
                # -x: the password arrives on stdin exactly as typed - no quoting, not visible in `ps`
                printf '%s' "$password" | redis-cli -h 127.0.0.1 -p "$REDIS_PORT" -x CONFIG SET requirepass >/dev/null
                if ! REDISCLI_AUTH="$password" redis-cli -h 127.0.0.1 -p "$REDIS_PORT" CONFIG REWRITE >/dev/null 2>&1; then
                    warn "could not write redis.conf - the password lasts until Redis restarts; add 'requirepass' to redis.conf"
                fi
            fi
        else
            skip "Redis password (left as it is: none)"
        fi
    elif [[ "$reply" == *NOAUTH* ]]; then
        say "  This Redis already has a password (set outside this installer). Type it here;"
        say "  it is only used to connect - it is not changed."
        local tries
        for tries in 1 2 3; do
            password="$(ask_existing_password "Existing Redis password")"
            if [[ -z "$password" ]]; then
                warn "the password is needed to use this Redis"
            elif REDISCLI_AUTH="$password" redis-cli -h 127.0.0.1 -p "$REDIS_PORT" ping 2>/dev/null | grep -q PONG; then
                break
            else
                warn "Redis did not accept that password"
            fi
            password=""
        done
        [[ -n "$password" ]] || die "no working Redis password - find it in the requirepass line of /etc/redis/redis.conf, then run the installer again"
    else
        die "Redis is not answering on 127.0.0.1:${REDIS_PORT} ($reply)"
    fi
    if [[ -n "$password" ]]; then
        conf_set REDIS_URL "redis://:$(url_quote "$password")@127.0.0.1:${REDIS_PORT}/0"
    else
        conf_set REDIS_URL "redis://127.0.0.1:${REDIS_PORT}/0"
    fi
}
