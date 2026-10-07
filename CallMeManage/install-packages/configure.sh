# Step-by-step setup of the website address and the external services, shared by
# install.sh and `callmemanage setup ...` (sourced, not run directly).
# Each wizard asks everything first, tests what it can, and writes the config file only
# at the end - an aborted wizard changes nothing.

# --- small checks (values go through the environment, never the command line) ---

valid_site_url() {
    SITE_VALUE="$1" python3 - <<'PY'
import os
from urllib.parse import urlparse
value = os.environ["SITE_VALUE"].strip().rstrip("/")
parsed = urlparse(value)
ok = parsed.scheme in {"http", "https"} and parsed.hostname and not parsed.path and not parsed.query
raise SystemExit(0 if ok else 1)
PY
}

normalize_root_path() {
    local value="${1:-/}"
    value="/${value#/}"
    value="${value%/}/"
    [[ "$value" == "//" ]] && value="/"
    printf '%s' "$value"
}

valid_root_path() {
    [[ "$1" == "/" || "$1" =~ ^/([A-Za-z0-9._~-]+/)+$ ]]
}

site_host() {
    SITE_VALUE="$1" python3 -c 'import os; from urllib.parse import urlparse; print(urlparse(os.environ["SITE_VALUE"]).hostname or "")'
}

# --- website address ---

# SITE_URL and ROOT_PATH. Enter keeps the current value.
configure_site() {
    step "Website address"
    say "  SITE_URL  = the address people type, without a path (e.g. https://www.example.ac.th)."
    say "              Leave it empty if the website is only opened by IP."
    say "  ROOT_PATH = / normally, or e.g. /cmm/ when a reverse proxy forwards https://<site>/cmm/"
    say "              here (the proxy must forward /cmm/ unchanged)."
    local site root
    while true; do
        site="$(ask_default "SITE_URL" "$(conf_get SITE_URL)")"
        site="${site%/}"
        [[ -z "$site" || "$site" == "-" ]] && { site=""; break; }
        valid_site_url "$site" && break
        warn "must look like https://www.example.ac.th (no path; the path goes in ROOT_PATH). Type - to leave it empty."
    done
    while true; do
        root="$(normalize_root_path "$(ask_default "ROOT_PATH" "$(conf_get ROOT_PATH)")")"
        valid_root_path "$root" && break
        warn "use / or a path such as /cmm/ (letters, digits, . _ ~ -)"
    done
    conf_set SITE_URL "$site"
    conf_set ROOT_PATH "$root"
    local port
    port="$(conf_get FRONTEND_PORT)"
    say "  Website: ${site:-https://<this machine>:${port:-8080}}$root"
}

# Where devices download their config file when added. Empty (default) = straight from this
# machine at https://<call-home IP>:<BACKEND_PORT>. Enter keeps the current value, - clears it.
configure_bootstrap() {
    step "Bootstrap download address for devices"
    local port
    port="$(conf_get BACKEND_PORT)"
    say "  Leave it empty (recommended): devices download straight from https://<call-home IP>:${port:-8000}"
    say "  Or a URL through a reverse proxy, without /bootstrap, e.g. https://www.example.ac.th/cmm/api"
    say "  (devices then need DNS, and the proxy an RSA certificate - many Cisco IOS-XE cannot use ECDSA)"
    local current value
    current="$(conf_get BOOTSTRAP_BASE_URL)"
    while true; do
        value="$(ask "Bootstrap URL${current:+ [$current - Enter keeps it, - clears it]} (Enter = empty)")"
        [[ -z "$value" ]] && value="$current"
        [[ "$value" == "-" ]] && value=""
        value="${value%/}"
        value="${value%/bootstrap}"
        if [[ -z "$value" || "$value" =~ ^https://[^/[:space:]]+(/[^[:space:]]*)?$ ]]; then break; fi
        warn "must start with https:// (or press Enter to leave it empty)"
    done
    conf_set BOOTSTRAP_BASE_URL "$value"
    say "  Devices download from: ${value:-https://<call-home IP>:${port:-8000}}/bootstrap/..."
}

# Asks for SITE_URL when a feature needs it and it is still empty. Returns 1 when left empty.
need_site_url() {
    [[ -n "$(conf_get SITE_URL)" ]] && return 0
    say "  This needs the website address (SITE_URL), e.g. https://www.example.ac.th"
    local site
    site="$(ask "SITE_URL")"
    site="${site%/}"
    if [[ -n "$site" ]] && valid_site_url "$site"; then conf_set SITE_URL "$site"; return 0; fi
    warn "no valid SITE_URL - nothing changed"
    return 1
}

# --- Cloudflare Turnstile ---

setup_turnstile() {
    step "Cloudflare Turnstile (\"I am not a robot\" check)"
    say "  Get the keys (free):"
    say "    1. https://dash.cloudflare.com -> Turnstile -> Add widget"
    say "    2. Hostname: the host name of SITE_URL (no https://, no path)"
    say "    3. Widget mode: Managed -> Create, then copy the Site Key and the Secret Key"
    say "  (Testing without an account: site key 1x00000000000000000000AA,"
    say "   secret 1x0000000000000000000000000000000AA - always passes, no real protection.)"
    need_site_url || return 1
    say "  Hostname to register at Cloudflare: $(site_host "$(conf_get SITE_URL)")"
    local site_key secret
    site_key="$(ask_default "Site key" "$(conf_get TURNSTILE_SITE_KEY)")"
    secret="$(ask "Secret key$([[ -n "$(conf_get TURNSTILE_SECRET_KEY)" ]] && echo " [Enter = keep current]")" secret)"
    secret="${secret:-$(conf_get TURNSTILE_SECRET_KEY)}"
    if [[ -z "$site_key" || -z "$secret" ]]; then warn "site key and secret key are both needed - nothing changed"; return 1; fi

    say "  Checking the secret key with Cloudflare..."
    local result
    result="$(TURNSTILE_SECRET="$secret" python3 - <<'PY'
import json, os, urllib.error, urllib.parse, urllib.request
data = urllib.parse.urlencode({"secret": os.environ["TURNSTILE_SECRET"], "response": "callmemanage-setup-check"}).encode()
try:
    with urllib.request.urlopen("https://challenges.cloudflare.com/turnstile/v0/siteverify", data=data, timeout=10) as r:
        codes = json.load(r).get("error-codes", [])
except urllib.error.HTTPError as error:  # an unknown secret is answered with HTTP 400 + error codes
    try:
        codes = json.loads(error.read()).get("error-codes", [])
    except ValueError:
        codes = ["offline"]
except Exception:
    codes = ["offline"]
print("bad-secret" if "invalid-input-secret" in codes else "offline" if "offline" in codes else "ok")
raise SystemExit
PY
)"
    case "$result" in
        bad-secret) warn "Cloudflare does not know this secret key (copy it again) - nothing changed"; return 1 ;;
        offline)    warn "could not reach Cloudflare to check the key (no internet?)"
                    yes_no "Save it anyway?" y || { say "  Nothing changed."; return 1; } ;;
        *)          say "  Secret key accepted by Cloudflare." ;;
    esac
    conf_set TURNSTILE_SITE_KEY "$site_key"
    conf_set TURNSTILE_SECRET_KEY "$secret"
    conf_set TURNSTILE_ENABLED yes
    say "  Cloudflare is ON. Browsers must reach challenges.cloudflare.com."
}

# --- email (Gmail by default) ---

setup_email() {
    step "Email (codes for sign-up and \"forgot password\")"
    say "  With Gmail:"
    say "    1. Turn on 2-Step Verification: https://myaccount.google.com/security"
    say "    2. https://myaccount.google.com/apppasswords -> name it CallMeManage -> Create"
    say "    3. Copy the 16-letter app password (not your normal Gmail password)"
    local address password host port
    address="$(ask_default "Gmail address (sender)" "$(conf_get SMTP_USERNAME)")"
    [[ "$address" == *@*.* ]] || { warn "not an email address - nothing changed"; return 1; }
    password="$(ask "App password$([[ -n "$(conf_get SMTP_APP_PASSWORD)" ]] && echo " [Enter = keep current]")" secret)"
    password="${password// /}"
    password="${password:-$(conf_get SMTP_APP_PASSWORD)}"
    [[ -n "$password" ]] || { warn "the app password is needed - nothing changed"; return 1; }
    host="$(conf_get SMTP_HOST)"; host="${host:-smtp.gmail.com}"
    port="$(conf_get SMTP_PORT)"; port="${port:-587}"
    if ! yes_no "Is this a Gmail account?" y; then
        host="$(ask_default "SMTP server" "$host")"
        port="$(ask_default "SMTP port (465 or 587)" "$port")"
        [[ "$port" == 465 || "$port" == 587 ]] || { warn "port must be 465 or 587 - nothing changed"; return 1; }
    else
        host="smtp.gmail.com"; port=587
    fi

    say "  Signing in to $host..."
    local result
    result="$(SMTP_HOST_VALUE="$host" SMTP_PORT_VALUE="$port" SMTP_USER_VALUE="$address" SMTP_PASS_VALUE="$password" python3 - <<'PY'
import os, smtplib, ssl
host, port = os.environ["SMTP_HOST_VALUE"], int(os.environ["SMTP_PORT_VALUE"])
user, password = os.environ["SMTP_USER_VALUE"], os.environ["SMTP_PASS_VALUE"]
try:
    if port == 465:
        smtp = smtplib.SMTP_SSL(host, port, timeout=15, context=ssl.create_default_context())
    else:
        smtp = smtplib.SMTP(host, port, timeout=15); smtp.starttls(context=ssl.create_default_context())
    smtp.login(user, password); smtp.quit()
    print("ok")
except smtplib.SMTPAuthenticationError:
    print("bad-login")
except Exception:
    print("offline")
PY
)"
    case "$result" in
        bad-login) warn "the mail server refused this address/app password (2-Step Verification on? app password copied right?) - nothing changed"; return 1 ;;
        offline)   warn "could not talk to $host:$port to test the login (no internet, or the port is blocked)"
                   yes_no "Save it anyway?" y || { say "  Nothing changed."; return 1; } ;;
        *)         say "  Signed in to the mail server." ;;
    esac
    conf_set SMTP_USERNAME "$address"
    conf_set SMTP_APP_PASSWORD "$password"
    conf_set SMTP_HOST "$host"
    conf_set SMTP_PORT "$port"
    conf_set EMAIL_ENABLED yes
    say "  Email is ON."
}

# --- Google sign-in ---

setup_google() {
    step "Google sign-in"
    need_site_url || return 1
    local redirect
    redirect="$(conf_get SITE_URL)$(normalize_root_path "$(conf_get ROOT_PATH)")api/auth/google/callback"
    say "  1. https://console.cloud.google.com -> create a project"
    say "  2. APIs & Services -> OAuth consent screen -> complete it (User type: External)"
    say "  3. APIs & Services -> Credentials -> Create credentials -> OAuth client ID"
    say "     Application type: Web application"
    say "  4. Authorized redirect URIs -> Add URI, paste exactly:"
    say ""
    say "        $redirect"
    say ""
    say "  5. Create, then copy the Client ID and the Client secret"
    local client_id secret
    client_id="$(ask_default "Client ID" "$(conf_get GOOGLE_CLIENT_ID)")"
    if [[ "$client_id" != *.apps.googleusercontent.com ]]; then
        warn "a Client ID ends with .apps.googleusercontent.com - nothing changed"; return 1
    fi
    secret="$(ask "Client secret$([[ -n "$(conf_get GOOGLE_CLIENT_SECRET)" ]] && echo " [Enter = keep current]")" secret)"
    secret="${secret:-$(conf_get GOOGLE_CLIENT_SECRET)}"
    [[ -n "$secret" ]] || { warn "the client secret is needed - nothing changed"; return 1; }
    conf_set GOOGLE_CLIENT_ID "$client_id"
    conf_set GOOGLE_CLIENT_SECRET "$secret"
    conf_set GOOGLE_ENABLED yes
    say "  Google sign-in is ON."
    [[ "$(conf_get SIGNUP_ENABLED)" =~ ^(true|yes|on|1)$ ]] \
        || say "  Note: SIGNUP_ENABLED=false - new people cannot create accounts (sudo callmemanage config to change)."
}

# --- used by the installer ---

configure_external_services() {
    step "Cloudflare / Email / Google (all optional - the system works without them)"
    say "  Skip now and set them up any time later, one at a time:"
    say "    sudo callmemanage setup turnstile | email | google"
    yes_no "Set any of them up now?" n || { skip "external services"; return 0; }
    yes_no "Cloudflare Turnstile (bot check)?" n && { setup_turnstile || true; }
    yes_no "Email (Gmail)?" n && { setup_email || true; }
    yes_no "Google sign-in?" n && { setup_google || true; }
    return 0
}

# SIGNUP_ENABLED: may people create their own account? Asked after the external services,
# because sign-up only works through email codes or Google.
configure_signup() {
    step "Sign-up on the website"
    say "  May people create their own account with the Sign Up button?"
    say "  No = only an admin creates accounts (sudo callmemanage user add)."
    local default=n
    [[ "$(conf_get SIGNUP_ENABLED)" =~ ^([Tt]rue|[Yy]es|[Oo]n|1)$ ]] && default=y
    if yes_no "Allow sign-up?" "$default"; then
        conf_set SIGNUP_ENABLED true
        say "  Sign-up is ON - anyone who can open the website can create an account."
        if [[ ! "$(conf_get EMAIL_ENABLED)" =~ ^([Tt]rue|[Yy]es|[Oo]n|1)$ && ! "$(conf_get GOOGLE_ENABLED)" =~ ^([Tt]rue|[Yy]es|[Oo]n|1)$ ]]; then
            warn "sign-up needs email (for the code) or Google sign-in, and both are off - nobody can"
            warn "finish signing up until one is on: sudo callmemanage setup email (or google)"
        fi
    else
        conf_set SIGNUP_ENABLED false
        say "  Sign-up is OFF - create accounts with: sudo callmemanage user add"
    fi
}

create_first_account() {
    step "First website account"
    if [[ "${DRY_RUN:-0}" == "1" ]]; then say "  (dry-run) ask for username, email and password"; return; fi
    as_app_user "cd '$PROJECT_ROOT' && '$VENV_DIR/bin/python' tools/create_user.py --if-none" \
        || warn "no account yet - create one later with: sudo callmemanage user add"
}
