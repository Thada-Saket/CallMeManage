""" |======= Account (website) password policy =======|

CM-09: the one place that decides whether a *new* website account password is
acceptable. Request schemas and the user CRUD both call it, so the API cannot be
bypassed. Mirrored for UX only in frontend/cloud_management/src/utils/accountPassword.js.

Not used at login: existing accounts keep signing in with older passwords.
Not the device local-user policy (tools/local_admin_policy.py) - that one carries
Cisco/Juniper/Huawei CLI limits which do not apply to website accounts.
"""

ACCOUNT_PASSWORD_MIN_LENGTH = 8
ACCOUNT_PASSWORD_MAX_LENGTH = 256

# Fixed text: never include the submitted value in an error.
ACCOUNT_PASSWORD_POLICY_MESSAGE = (
    "Password must be 8-256 characters and contain a lowercase letter, "
    "an uppercase letter, a number, and a special character"
)


def _is_ascii_lower(char: str) -> bool:
    return "a" <= char <= "z"


def _is_ascii_upper(char: str) -> bool:
    return "A" <= char <= "Z"


def _is_ascii_digit(char: str) -> bool:
    return "0" <= char <= "9"


def _is_special(char: str) -> bool:
    # anything outside [A-Za-z0-9] counts, including space and non-ASCII
    return not (_is_ascii_lower(char) or _is_ascii_upper(char) or _is_ascii_digit(char))


def validate_account_password(password: object) -> str:
    """Return the password unchanged when it meets the policy, else raise ValueError."""
    if not isinstance(password, str):
        raise ValueError(ACCOUNT_PASSWORD_POLICY_MESSAGE)
    if not ACCOUNT_PASSWORD_MIN_LENGTH <= len(password) <= ACCOUNT_PASSWORD_MAX_LENGTH:
        raise ValueError(ACCOUNT_PASSWORD_POLICY_MESSAGE)
    for rule in (_is_ascii_lower, _is_ascii_upper, _is_ascii_digit, _is_special):
        if not any(rule(char) for char in password):
            raise ValueError(ACCOUNT_PASSWORD_POLICY_MESSAGE)
    return password
