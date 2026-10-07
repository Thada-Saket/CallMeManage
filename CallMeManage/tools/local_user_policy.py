"""Policy for the System Setting > User Info page (live local users on a device).

The password rules are the CLI Generator's (tools/local_admin_policy.py); this
module only adds the username rules of this page and the privilege mapping.
Every error message is fixed text: it never contains the submitted password.
"""
import re

from tools.local_admin_policy import USERNAME_MAX_LENGTH, validate_local_admin_password

USERNAME_MIN_LENGTH = 6
# Same allowlist as the CLI Generator local administrator (tools/local_admin_policy.py)
_USERNAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
# The NETCONF management account. Never listed, created, edited or deleted from
# the web page, whatever MNG_USER says or how the name is cased.
DEFAULT_RESERVED_USERNAME = "Netconf-MGMT"

LOCAL_USER_WRITE_COMMANDS = frozenset({"set_new_local_user", "edit_local_user", "delete_local_user"})
LOCAL_USER_COMMANDS = LOCAL_USER_WRITE_COMMANDS | {"get_local_user"}

# Canonical privilege <-> value each translator accepts. Single source of truth
# for the backend; the frontend mirror lives in utils/localUsers.js.
VENDOR_PRIVILEGES = {
    "cisco": {"monitor": 1, "admin": 15},
    "juniper": {"monitor": "operator", "admin": "super-user"},
    "huawei": {"monitor": 0, "admin": 3},
}

_ALLOWED_PARAMETERS = {
    "set_new_local_user": ({"username", "privilege", "passwd"}, {"username", "privilege", "passwd"}),
    "edit_local_user": ({"username", "privilege", "passwd"}, {"username"}),
    "delete_local_user": ({"username"}, {"username"}),
}


def reserved_usernames() -> set[str]:
    """Lower-cased names that are hidden and protected (case-insensitive compare)."""
    names = {DEFAULT_RESERVED_USERNAME.lower()}
    try:
        from backend.core.load_environment import load_environment

        configured = load_environment().MNG_USER
        if configured:
            names.add(str(configured).lower())
    except Exception:
        pass
    return names


def is_reserved_username(username: object) -> bool:
    return isinstance(username, str) and username.strip().lower() in reserved_usernames()


def canonical_privilege(vendor: str, raw: object) -> str | None:
    """Device value -> "monitor"/"admin"; None when the value is not one this page manages.

    Unknown Brownfield levels (e.g. Cisco 7, Junos read-only, Huawei 2) are
    never guessed as either level - the caller shows them as unrecognised.
    """
    text = "" if raw is None else str(raw).strip()
    for canonical, value in VENDOR_PRIVILEGES.get(vendor, {}).items():
        if text == str(value):
            return canonical
    return None


def validate_new_username(username: object) -> str:
    if not isinstance(username, str) or not username:
        raise ValueError("Username is required")
    if not USERNAME_MIN_LENGTH <= len(username) <= USERNAME_MAX_LENGTH or not _USERNAME.fullmatch(username):
        raise ValueError(
            f"Username must be {USERNAME_MIN_LENGTH}-{USERNAME_MAX_LENGTH} characters, start with a letter or number, "
            "and contain only letters, numbers, period (.), underscore (_) and hyphen (-)"
        )
    if is_reserved_username(username):
        raise ValueError("This username is reserved by the system")
    return username


def validate_existing_username(username: object) -> str:
    """Edit/Delete target: a Brownfield name read from the device, not the create format.

    Its existence is proven by a fresh device read; here we only refuse
    nonsense and the reserved management account.
    """
    if not isinstance(username, str) or not username.strip():
        raise ValueError("Username is required")
    if len(username) > 253 or any(ord(c) < 0x21 or ord(c) == 0x7F for c in username):
        raise ValueError("Username contains characters that are not allowed")
    if is_reserved_username(username):
        raise ValueError("This username is reserved by the system")
    return username


def validate_password(password: object) -> str:
    try:
        return validate_local_admin_password(password)
    except ValueError as exc:
        # Same rules and fixed texts as the CLI Generator, minus its feature name
        raise ValueError(str(exc).replace("Local administrator password", "Password")) from None


def _vendor_privilege(vendor: str, value: object):
    allowed = VENDOR_PRIVILEGES.get(vendor)
    if allowed is None:
        raise ValueError("Local users are not supported on this device")
    for candidate in allowed.values():
        if str(value).strip() == str(candidate) and not isinstance(value, bool):
            return candidate
    raise ValueError("Privilege must be Monitor Only or Network Admin")


def validate_local_user_request(vendor: str, command: str, parameters: dict) -> dict:
    """Validate a User Info write and return the exact parameters for the translator."""
    if vendor not in VENDOR_PRIVILEGES:
        raise ValueError("Local users are not supported on this device")
    allowed, required = _ALLOWED_PARAMETERS[command]
    if not isinstance(parameters, dict):
        raise ValueError("Invalid request")
    present = {key for key, value in parameters.items() if value is not None}
    unexpected = set(parameters) - allowed
    if unexpected:
        raise ValueError("Unexpected field: " + ", ".join(sorted(unexpected)))
    missing = required - present
    if missing:
        raise ValueError("Missing field: " + ", ".join(sorted(missing)))

    if command == "set_new_local_user":
        return {
            "username": validate_new_username(parameters["username"]),
            "privilege": _vendor_privilege(vendor, parameters["privilege"]),
            "passwd": validate_password(parameters["passwd"]),
        }

    username = validate_existing_username(parameters["username"])
    if command == "delete_local_user":
        return {"username": username}

    clean = {"username": username}
    if "privilege" in present:
        clean["privilege"] = _vendor_privilege(vendor, parameters["privilege"])
    if "passwd" in present:
        clean["passwd"] = validate_password(parameters["passwd"])
    if len(clean) == 1:
        raise ValueError("Change the privilege or enter a new password")
    return clean


def check_target_against_device(command: str, username: str, device_usernames: list[str]) -> None:
    """Fresh-read guard run inside the device lock, just before the write.

    Create refuses any existing name case-insensitively (Huawei treats names
    case-insensitively, and a near-duplicate is confusing on every vendor).
    Edit/Delete need the exact list key to still exist, so a stale page never
    re-creates a deleted user through NETCONF merge or reports a no-op delete.
    Raises LookupError (missing) or FileExistsError (duplicate).
    """
    if command == "set_new_local_user":
        wanted = username.lower()
        if any(name.lower() == wanted for name in device_usernames):
            raise FileExistsError(f"User '{username}' already exists on the device")
        return
    if username not in device_usernames:
        raise LookupError(f"User '{username}' no longer exists on the device. Refresh the list and try again.")


def history_parameters(command: str, parameters: dict) -> dict:
    """Backward-compatible entry point for the central history policy."""
    from tools.history_redaction import sanitize_history_parameters

    return sanitize_history_parameters(command, parameters)


def redact_secret(text: str, secret: str | None) -> str:
    """Remove the plaintext (and its XML-escaped form) from a message sent to the browser."""
    if not secret or not isinstance(text, str):
        return text
    from xml.sax.saxutils import escape

    for form in {secret, escape(secret), escape(secret, {'"': "&quot;", "'": "&apos;"})}:
        text = text.replace(form, "********")
    return text
