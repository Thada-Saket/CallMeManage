"""Optional, non-authentication Call Home diagnostics."""

from backend.core.load_environment import load_environment


def identity_debug_enabled() -> bool:
    return bool(load_environment().CALLHOME_IDENTITY_DEBUG)


def log_identity(ip: str, serial: str | None) -> None:
    """Debug only: never called for authentication and never persists the serial."""
    if not identity_debug_enabled():
        return
    safe_ip = ip if isinstance(ip, str) and ip else "unknown"
    safe_serial = serial if isinstance(serial, str) and serial else "unavailable"
    print(f"[callhome-debug] ip={safe_ip} serial={safe_serial}")


# ---------- Verbose Call Home log (CALLHOME_VERBOSE_LOG, default off) ----------
# Default output is one line per connection ("[+] Call Home from <ip>  host-key: <fp>")
# plus warnings/rejections/errors. Turning this on adds the per-device detail block
# and the success/progress lines. Never prints tokens, hashes, passwords or raw XML.

def verbose_enabled() -> bool:
    return load_environment().CALLHOME_VERBOSE_LOG is True


def log_verbose(message: str) -> None:
    if verbose_enabled():
        print(message)


def log_connected_device(
    *, ip: str, fingerprint: str | None, vendor: str, dev_id: str, route: str, metadata=None, serial: str | None = None,
) -> None:
    if not verbose_enabled():
        return

    def value(text) -> str:
        # device-supplied text: drop control characters so a value cannot forge extra log lines
        if not isinstance(text, str) or not text:
            return "unavailable"
        cleaned = "".join(ch if ch.isprintable() else "?" for ch in text)[:128]
        return cleaned or "unavailable"

    print(
        f"[callhome] device connected ({route})\n"
        f"    IP Address      = {value(ip)}\n"
        f"    Host Key        = {value(fingerprint)}\n"
        f"    Vendor          = {value(vendor)}\n"
        f"    Device ID       = {value(dev_id)}\n"
        f"    Hostname        = {value(getattr(metadata, 'hostname', None))}\n"
        f"    Model           = {value(getattr(metadata, 'model', None))}\n"
        f"    Firmware        = {value(getattr(metadata, 'firmware', None))}\n"
        f"    Serial Number   = {value(serial)}"
    )
