"""Validation of the optional Local Administrator (Phase 10, Existing Device only).

Shared by the request schema and the CLI generator (defence in depth). Every error message is fixed text: it never
contains the username or the password that was checked."""
import re
import unicodedata

USERNAME_MAX_LENGTH = 32
USERNAME_MIN_LENGTH = 6
PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 25            # conservative: IOS-XE plain `username ... secret` is the tightest of the three vendors

# conservative allowlist (no vendor grammar guessing): starts alphanumeric, then alnum . _ -
_USERNAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
# printable ASCII without whitespace; `?` (IOS help key), quotes, backslash and backtick can break a pasted CLI line
_FORBIDDEN_PASSWORD_CHARS = set('?"\'\\`')


def validate_local_admin_username(vendor: str, username: object, reserved_username: str) -> str:
    if not isinstance(username, str) or not username:
        raise ValueError("Local administrator username is required")
    if len(username) > USERNAME_MAX_LENGTH or not _USERNAME.fullmatch(username):
        raise ValueError("Local administrator username may only contain letters, digits, '.', '_' and '-' "
                         f"(start with a letter or digit, at most {USERNAME_MAX_LENGTH} characters)")
    if len(username) < USERNAME_MIN_LENGTH:
        raise ValueError(
            f"Local administrator username must be at least {USERNAME_MIN_LENGTH} characters long"
        )
    if reserved_username and username.lower() == str(reserved_username).lower():
        raise ValueError("Local administrator username is reserved by the system")
    return username


def validate_local_admin_password(password: object) -> str:
    if not isinstance(password, str) or not password:
        raise ValueError("Local administrator password is required")
    if any(ord(c) < 0x21 or ord(c) > 0x7E or unicodedata.category(c).startswith("C") for c in password) \
            or any(c in _FORBIDDEN_PASSWORD_CHARS for c in password):
        raise ValueError("Local administrator password contains characters that are not allowed "
                         "(whitespace, control characters, non-ASCII, ? \" ' \\ `)")
    if not PASSWORD_MIN_LENGTH <= len(password) <= PASSWORD_MAX_LENGTH:
        raise ValueError(f"Local administrator password must be {PASSWORD_MIN_LENGTH}-{PASSWORD_MAX_LENGTH} characters long")
    unmet = []
    if not re.search(r"[a-z]", password):
        unmet.append("contain lowercase letter (a-z)")
    if not re.search(r"[A-Z]", password):
        unmet.append("contain uppercase letter (A-Z)")
    if not re.search(r"[0-9]", password):
        unmet.append("contain a number (0-9)")
    if not re.search(r"[^A-Za-z0-9]", password):
        unmet.append("contain special character (!@#$%^&* etc.)")
    if unmet:
        raise ValueError("Local administrator password must: " + ", ".join(unmet))
    return password
