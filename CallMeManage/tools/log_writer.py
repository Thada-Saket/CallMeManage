""" |======= Persistent backend log (like nginx/apache access logs) =======|

Usage (see scripts/secure.sh):
    uvicorn app:app ... 2>&1 | python3 tools/log_writer.py logs/backend.log

Reads everything the backend writes to stdout/stderr and
  1. echoes it to the terminal unchanged (colors included), and
  2. appends it to the log file with a local timestamp, ANSI colors removed.

The file is never truncated: stopping and starting the backend keeps adding to it.
At local midnight the file is rotated (backend.log -> backend.log.2026-10-06.gz)
and the newest LOG_KEEP_DAYS rotated files are kept, like logrotate daily + compress.

It must never take the backend down with it: Ctrl+C is ignored here so the
backend's own shutdown lines are still recorded, and any file error only stops
the file copy - the terminal echo and the pipe keep working until the backend exits.
"""

import gzip
import logging
import logging.handlers
import os
import re
import shutil
import signal
import sys
from datetime import datetime

LOG_KEEP_DAYS = int(os.environ.get("LOG_KEEP_DAYS", "90"))
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


def _gzip_rotator(source: str, dest: str) -> None:
    with open(source, "rb") as src, gzip.open(dest, "wb") as out:
        shutil.copyfileobj(src, out)
    os.remove(source)
    os.chmod(dest, 0o600)


def build_handler(path: str) -> logging.Handler:
    os.makedirs(os.path.dirname(os.path.abspath(path)), mode=0o700, exist_ok=True)
    handler = logging.handlers.TimedRotatingFileHandler(
        path, when="midnight", backupCount=LOG_KEEP_DAYS, encoding="utf-8", delay=False
    )
    handler.namer = lambda name: name + ".gz"
    handler.rotator = _gzip_rotator
    handler.setFormatter(logging.Formatter("%(message)s"))
    try:
        os.chmod(path, 0o600)  # logs may contain IPs, device IDs and audit records
    except OSError:
        pass
    return handler


def stamp(line: str) -> str:
    return f"{datetime.now().astimezone().isoformat(timespec='seconds')} {_ANSI.sub('', line)}"


def run(path: str, source=None, echo=None) -> None:
    source = source or sys.stdin.buffer
    echo = echo or sys.stdout.buffer
    handler = None
    try:
        handler = build_handler(path)
    except OSError as exc:
        echo.write(f"[log-writer] cannot open {path}: {exc} - logging to terminal only\n".encode())
        echo.flush()

    for raw in iter(source.readline, b""):
        try:
            echo.write(raw)
            echo.flush()
        except (BrokenPipeError, OSError):
            pass  # terminal gone (e.g. closed SSH session): keep writing the file
        if handler is None:
            continue
        line = raw.decode("utf-8", "replace").rstrip("\r\n")
        try:
            handler.emit(logging.makeLogRecord({"msg": stamp(line)}))
        except Exception as exc:  # disk full, permissions... never stop draining the pipe
            handler = None
            try:
                echo.write(f"[log-writer] stopped writing {path}: {type(exc).__name__}\n".encode())
                echo.flush()
            except OSError:
                pass
    if handler is not None:
        handler.close()


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit("usage: log_writer.py <logfile>")
    # Ctrl+C reaches the whole pipeline; let uvicorn handle it and keep reading
    # until it has written its shutdown messages and closed the pipe.
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    os.umask(0o077)
    run(sys.argv[1])


if __name__ == "__main__":
    main()
