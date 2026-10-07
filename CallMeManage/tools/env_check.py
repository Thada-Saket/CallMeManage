""" |======= Config check before starting CallMe Manage =======|

    .venv/bin/python tools/env_check.py            (or: callmemanage check)

Checks /etc/callmemanage/callmemanage.conf (or the file in CALLMEMANAGE_CONF).
Exit 0: the system can start (warnings may be printed).
Exit 1: something required is missing or invalid - the message says what and where.
Never prints secret values.
"""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend.core.config_file import config_file, read_config_values  # noqa: E402

# Keys from the old .env that have no meaning in the config file any more.
RETIRED_KEYS = {
    "VITE_BASE_PATH": "use ROOT_PATH",
    "VITE_API_URL": "remove it (the API is always <ROOT_PATH>api)",
    "VITE_TURNSTILE_SITE_KEY": "use TURNSTILE_SITE_KEY",
}


def line_numbers(path: Path) -> dict[str, int]:
    numbers = {}
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            numbers.setdefault(stripped.split("=", 1)[0].strip(), number)
    return numbers


def where(key: str, numbers: dict[str, int]) -> str:
    return f" (line {numbers[key]})" if key in numbers else ""


def readable_file(label: str, value: str, problems: list[str]) -> None:
    path = Path(value)
    path = path if path.is_absolute() else ROOT / path
    if not path.is_file():
        problems.append(f"{label} not found: {path}")
    elif not os.access(path, os.R_OK):
        problems.append(f"{label} is not readable by user '{os.environ.get('USER') or os.getuid()}': {path} "
                        "(copy it into /etc/callmemanage/cert/ and give it to that user)")


def main() -> int:
    path = config_file()
    # `callmemanage config` checks a draft copy; messages name the real file
    shown = os.environ.get("CALLMEMANAGE_CONF_SHOWN") or str(path)
    problems, warnings = [], []
    if not path.is_file():
        print(f"[x] {path} not found - run: sudo ./install_service.sh")
        return 1
    if not os.access(path, os.R_OK):
        print(f"[x] {path} is not readable by this user - run the check with: sudo callmemanage check")
        return 1

    numbers = line_numbers(path)
    raw = read_config_values(path)
    for key, advice in RETIRED_KEYS.items():
        if key in raw:
            problems.append(f"{key}{where(key, numbers)} is no longer used - {advice}")

    try:
        from pydantic import ValidationError
        from backend.core.load_environment import TURNSTILE_TEST_SECRETS, load_environment
        settings = load_environment()
    except ValidationError as exc:
        for error in exc.errors():
            key = ".".join(str(part) for part in error["loc"])
            message = error["msg"].removeprefix("Value error, ")
            if key in RETIRED_KEYS:
                continue  # already explained above
            if message == "Extra inputs are not permitted":
                message = "unknown setting (spelling mistake?)"
            problems.append(f"{key}{where(key, numbers)}: {message}" if key else message)
        settings = None

    if settings is not None:
        readable_file("SSH private key (SSH_KEY_PATH)", settings.SSH_KEY_PATH, problems)
        readable_file("SSH public key", str(ROOT / "tools/keys/rsa_public_key.pem"), problems)
        readable_file("HTTPS certificate (TLS_CERT_FILE)", settings.TLS_CERT_FILE, problems)
        readable_file("HTTPS private key (TLS_KEY_FILE)", settings.TLS_KEY_FILE, problems)

        from backend.cli_generator import CLOUD_SERVER_IP
        if not CLOUD_SERVER_IP:
            problems.append(f"call-home address: interface '{settings.CALLHOME_INTERFACE}' has no IPv4 "
                            "and CALLHOME_ADDRESS is empty - run: sudo ./install_service.sh --configure")

        if not settings.TURNSTILE_ENABLED:
            warnings.append("Cloudflare is off - no bot check before the website or on login (rate limits only). "
                            "Turn it on: sudo callmemanage setup turnstile")
        elif settings.TURNSTILE_SECRET_KEY in TURNSTILE_TEST_SECRETS:
            warnings.append("Cloudflare uses the official TEST key - no real bot protection")
        if not settings.EMAIL_ENABLED:
            warnings.append("Email is off - users cannot reset a forgotten password by email "
                            "(sudo callmemanage user passwd <name>); turn it on: sudo callmemanage setup email")
        if settings.SIGNUP_ENABLED:
            warnings.append("SIGNUP_ENABLED=true - anyone who reaches the site can create an account")
        if settings.BOOTSTRAP_BASE_URL and settings.BOOTSTRAP_BASE_URL.rstrip("/").endswith("/bootstrap"):
            warnings.append("BOOTSTRAP_BASE_URL ends with /bootstrap, so device links get it twice and devices "
                            "receive the web page instead of their config - leave /bootstrap out "
                            "(e.g. https://www.example.ac.th/cmm/api) or leave it empty (recommended)")

    for line in warnings:
        print(f"[!] {line}")
    for line in problems:
        print(f"[x] {line}")
    if problems:
        print(f"\nFix the items above in {shown} (sudo callmemanage config), then start again.")
        return 1
    print(f"[ok] {shown} is complete enough to start")
    return 0


if __name__ == "__main__":
    sys.exit(main())
