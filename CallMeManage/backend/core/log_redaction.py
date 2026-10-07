""" |======= Access-log redaction =======|

uvicorn's access log prints the full request line. Google OAuth secrets are in
the callback query and bootstrap secrets are in the URL path, so both forms are
redacted before the record reaches any access-log handler.
"""

import logging
import re

# Paths whose query string must never reach the access log.
SENSITIVE_QUERY_PATHS = ("/auth/google/callback",)
REDACTED_QUERY = "?<redacted>"
BOOTSTRAP_PATH_RE = re.compile(
    r"^(?P<prefix>(?:/api)?/bootstrap/)[^/?]+(?P<suffix>/config\.txt)$"
)
REDACTED_BOOTSTRAP_TOKEN = "<redacted>"


class SensitiveQueryFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        # uvicorn.access args: (client_addr, method, full_path, http_version, status_code)
        if isinstance(args, tuple) and len(args) >= 3 and isinstance(args[2], str):
            path, separator, _query = args[2].partition("?")
            bootstrap_match = BOOTSTRAP_PATH_RE.fullmatch(path)
            if bootstrap_match:
                path = (
                    bootstrap_match.group("prefix")
                    + REDACTED_BOOTSTRAP_TOKEN
                    + bootstrap_match.group("suffix")
                )
                record.args = args[:2] + (path + (REDACTED_QUERY if separator else ""),) + args[3:]
                return True
            if separator and path in SENSITIVE_QUERY_PATHS:
                record.args = args[:2] + (path + REDACTED_QUERY,) + args[3:]
        return True


def install_access_log_redaction() -> None:
    logger = logging.getLogger("uvicorn.access")
    if not any(isinstance(existing, SensitiveQueryFilter) for existing in logger.filters):
        logger.addFilter(SensitiveQueryFilter())
