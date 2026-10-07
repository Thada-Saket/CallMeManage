"""Password hashing shared by CLI generation and live device translators."""

import subprocess


def hash_password_sha512(password: str) -> str:
    """Return an OpenSSL SHA-512 crypt hash accepted by Junos.

    The plaintext is sent through stdin, never through argv where it could be
    exposed by a process listing. Error messages deliberately contain no user
    input.
    """
    if not isinstance(password, str) or not password:
        raise ValueError("Password is required")
    result = subprocess.run(
        ["openssl", "passwd", "-6", "-stdin"],
        input=password,
        capture_output=True,
        text=True,
        check=True,
    )
    hashed = result.stdout.strip()
    if not hashed.startswith("$6$"):
        raise RuntimeError("Password hashing returned an unsupported format")
    return hashed
