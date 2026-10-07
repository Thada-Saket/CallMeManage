# Local PostgreSQL database/user and Redis password (sourced by install_service.sh).
# Already-configured DB_URL / REDIS_URL in the config file are left alone (e.g. an existing remote DB).

DB_NAME="callmemanage"
DB_ROLE="callmemanage"
REDIS_PORT="${REDIS_PORT:-6379}"


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
    password="$(random_secret 24)"
    exists="$(runuser -u postgres -- psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='${DB_ROLE}'" 2>/dev/null || true)"
    if [[ "$exists" == "1" ]]; then
        # role exists but the config file lost its URL: rotate the password so we know it
        todo "reset password of existing role ${DB_ROLE}"
    else
        todo "create role ${DB_ROLE} and database ${DB_NAME}"
    fi
    if [[ "${DRY_RUN:-0}" == "1" ]]; then
        say "  (dry-run) psql create/alter role, create database"
    else
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
    conf_set DB_URL "postgresql+asyncpg://${DB_ROLE}:${password}@127.0.0.1:5432/${DB_NAME}"
}

setup_redis() {
    step "Redis password"
    if ! conf_unset REDIS_URL; then
        skip "REDIS_URL already set in the config file"
        return
    fi
    local reply password
    reply="$(redis-cli -h 127.0.0.1 -p "$REDIS_PORT" ping 2>&1 || true)"
    if [[ "$reply" == "PONG" ]]; then
        password="$(random_secret 24)"
        todo "set a Redis password (requirepass) and save it to redis.conf"
        if [[ "${DRY_RUN:-0}" != "1" ]]; then
            # command via stdin so the password never appears in `ps`
            printf 'CONFIG SET requirepass "%s"\n' "$password" | redis-cli -h 127.0.0.1 -p "$REDIS_PORT" >/dev/null
            if ! REDISCLI_AUTH="$password" redis-cli -h 127.0.0.1 -p "$REDIS_PORT" CONFIG REWRITE >/dev/null 2>&1; then
                warn "could not write redis.conf - the password lasts until Redis restarts; add 'requirepass' to redis.conf"
            fi
        fi
    elif [[ "$reply" == *NOAUTH* ]]; then
        say "  Redis already has a password (set by someone else)."
        password="$(ask "Enter the existing Redis password" secret)"
        [[ -n "$password" ]] || die "Redis password is required to continue"
        REDISCLI_AUTH="$password" redis-cli -h 127.0.0.1 -p "$REDIS_PORT" ping 2>/dev/null | grep -q PONG || die "That Redis password was not accepted"
    else
        die "Redis is not answering on 127.0.0.1:${REDIS_PORT} ($reply)"
    fi
    conf_set REDIS_URL "redis://:${password}@127.0.0.1:${REDIS_PORT}/0"
}
