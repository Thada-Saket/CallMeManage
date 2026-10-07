""" |======= Where the configuration file lives =======|

All settings (ports, certificate, keys of external services, database URLs ...) are in
one file, /etc/callmemanage/callmemanage.conf, written by install_service.sh and edited
with `sudo callmemanage config`. It lives outside the project folder, so `git pull`
never touches it.

CALLMEMANAGE_CONF points somewhere else, e.g. for development:
    CALLMEMANAGE_CONF=$PWD/callmemanage.conf .venv/bin/python app.py
"""

import os
from pathlib import Path

DEFAULT_CONFIG_FILE = Path("/etc/callmemanage/callmemanage.conf")
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


def config_file() -> Path:
    return Path(os.environ.get("CALLMEMANAGE_CONF") or DEFAULT_CONFIG_FILE)


def read_config_values(path: Path | None = None) -> dict[str, str]:
    """KEY=value lines as written in the file (comments and blank lines skipped)."""
    values: dict[str, str] = {}
    target = path or config_file()
    for line in target.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        values[key.strip()] = value.strip()
    return values
