"""Validation of the console (Device CLI) user created on a Fresh Out of the Box device.

Shared by the request schema and the CLI generator (defence in depth). Cisco and Huawei put the username and the
plain password straight into the CLI text the user pastes onto the device, so a newline or a `?` in either value
would become another command / the IOS help key. Every error message is fixed text: it never contains the value
that was checked. Rules must stay in sync with CONSOLE_USERNAME_* / CONSOLE_PASSWORD_RULES in
frontend/cloud_management/src/pages/CliGenerator.jsx."""
import re

USERNAME_MAX_LENGTH = 32
HUAWEI_USERNAME_MIN_LENGTH = 6      # CE12800 rejects a local-user shorter than 6 characters
PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 25            # conservative: IOS-XE plain `username ... secret` is the tightest of the three vendors

# same allowlist as the Local Administrator username (tools/local_admin_policy.py)
_USERNAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
# printable ASCII without whitespace, minus the characters that break a pasted CLI line
_PASSWORD_ALLOWED = re.compile(r"[\x21-\x7E]+")
_FORBIDDEN_PASSWORD_CHARS = set('?"\'\\`')


def validate_console_username(vendor: str, username: object, reserved_username: str) -> str:
    if not isinstance(username, str) or not username.strip():
        raise ValueError("Console username is required")
    username = username.strip()
    if len(username) > USERNAME_MAX_LENGTH or not _USERNAME.fullmatch(username):
        raise ValueError("Console username may only contain letters, digits, '.', '_' and '-' "
                         f"(start with a letter or digit, at most {USERNAME_MAX_LENGTH} characters)")
    if vendor == "huawei" and len(username) < HUAWEI_USERNAME_MIN_LENGTH:
        raise ValueError(f"Huawei Console Username must be at least {HUAWEI_USERNAME_MIN_LENGTH} characters long")
    if reserved_username and username.lower() == str(reserved_username).lower():
        raise ValueError("Console username is reserved by the system")
    return username


def validate_console_password(password: object) -> str:
    if not isinstance(password, str) or not password:
        raise ValueError("Console password is required")
    if not _PASSWORD_ALLOWED.fullmatch(password) or any(c in _FORBIDDEN_PASSWORD_CHARS for c in password):
        raise ValueError("Console password contains characters that are not allowed "
                         "(spaces, non-English characters, ? \" ' \\ `)")
    unmet = []
    if not PASSWORD_MIN_LENGTH <= len(password) <= PASSWORD_MAX_LENGTH:
        unmet.append(f"be {PASSWORD_MIN_LENGTH}-{PASSWORD_MAX_LENGTH} characters long")
    if not re.search(r"[a-z]", password):
        unmet.append("contain lowercase letter (a-z)")
    if not re.search(r"[A-Z]", password):
        unmet.append("contain uppercase letter (A-Z)")
    if not re.search(r"[0-9]", password):
        unmet.append("contain a number (0-9)")
    if not re.search(r"[^A-Za-z0-9]", password):
        unmet.append("contain special character (!@#$%^&* etc.)")
    if unmet:
        raise ValueError("Console password must: " + ", ".join(unmet))
    return password
