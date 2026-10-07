""" |======= Load Secret Value =======| """

import re
from typing import Literal
import ipaddress
from urllib.parse import urlparse
from pydantic import EmailStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from backend.core.config_file import PROJECT_ROOT, config_file


TURNSTILE_TEST_SECRETS = {
    "1x0000000000000000000000000000000AA",
    "2x0000000000000000000000000000000AA",
    "3x0000000000000000000000000000000AA",
}
DEFAULT_CERT_DIR = PROJECT_ROOT / "tools" / "keys" / "cert"


def _missing(switch: str, names: list[str]) -> str:
    return f"{switch}=yes but {' and '.join(names)} {'is' if len(names) == 1 else 'are'} empty"


class Setting(BaseSettings):
    APP_ENV: Literal["development", "test", "production"] = "development"
    # Public address of the website as people type it, without a path
    # (https://www.example.ac.th). Empty = reached by IP only; Google sign-in and a real
    # Cloudflare key need it. The Google URLs and Turnstile hostname are derived from it.
    SITE_URL: str | None = None
    # Path the website lives under: "/" or e.g. "/cmm/" behind a reverse proxy at /cmm.
    ROOT_PATH: str = "/"
    BIND_HOST: str = "0.0.0.0"
    FRONTEND_PORT: int = 8080
    BACKEND_PORT: int = 8000
    CALLHOME_PORT: int = 4334
    TLS_CERT_FILE: str = str(DEFAULT_CERT_DIR / "server.crt")
    TLS_KEY_FILE: str = str(DEFAULT_CERT_DIR / "server.key")
    SSH_KEY_PATH: str
    DB_URL: str
    JWT_SECRET_KEY: str
    REDIS_URL: str
    MNG_USER: str
    # Google sign-in: GOOGLE_ENABLED plus the client ID/secret. The redirect URI and the
    # frontend URL are derived from SITE_URL + ROOT_PATH (set them only to override).
    GOOGLE_ENABLED: bool = False
    GOOGLE_CLIENT_ID: str | None = None
    GOOGLE_CLIENT_SECRET: str | None = None
    GOOGLE_REDIRECT_URI: str | None = None
    FRONTEND_BASE_URL: str | None = None
    # Extra Host headers to accept, comma-separated (e.g. a LAN name). Never "*".
    ALLOWED_HOSTS: str = ""
    # Short-lived Redis record for OAuth state/nonce/PKCE. It is consumed once
    # by the Google callback and is not a login/session lifetime.
    REGISTRATION_FLOW_TTL_SECONDS: int = 10 * 60
    # Email (OTP for sign-up and password reset). Optional: without it codes cannot be
    # sent and those flows answer "temporarily unavailable"; the rest of the system runs.
    EMAIL_ENABLED: bool = False
    SMTP_HOST: str | None = "smtp.gmail.com"
    SMTP_PORT: int = 465
    SMTP_USERNAME: EmailStr | None = None
    SMTP_APP_PASSWORD: str | None = None
    SMTP_FROM_NAME: str = "CallMe Manage"
    # Cloudflare Turnstile (bot check before the website and on every login). Off = no
    # bot check at all, only rate limits; production refuses that.
    TURNSTILE_ENABLED: bool = False
    TURNSTILE_SITE_KEY: str | None = None
    TURNSTILE_SECRET_KEY: str | None = None
    # derived from SITE_URL (localhost without it); set it only to override
    TURNSTILE_EXPECTED_HOSTNAME: str | None = None
    # Address that devices call home to (Cisco/Huawei accept an IPv4 address only).
    # CALLHOME_ADDRESS wins when set; otherwise the IPv4 of CALLHOME_INTERFACE is used.
    CALLHOME_INTERFACE: str = "tailscale0"
    CALLHOME_ADDRESS: str | None = None
    # Where this server waits for devices to call home (port CALLHOME_PORT):
    # 0.0.0.0 = every interface (default), or one IPv4 address of this machine.
    CALLHOME_LISTEN_ADDRESS: str = "0.0.0.0"
    # Where devices download their bootstrap file, without the trailing /bootstrap.
    # Empty = straight to this machine: https://<call-home address>:<BACKEND_PORT>.
    # Behind a reverse proxy at /cmm: https://<site>/cmm/api (devices then need DNS).
    BOOTSTRAP_BASE_URL: str | None = None
    # (dynamic feature ขั้นที่ 4) เปิดการกรองคำสั่งตามความสามารถของอุปกรณ์ - ค่าเริ่มต้นปิด
    # ดู _capability_filter_enabled ใน backend/api/device_router.py
    CAPABILITY_FILTER_ENABLED: bool = True
    # Full token authentication: ค่าอื่นรวม hybrid/legacy ถูกปฏิเสธตอน startup
    CALLHOME_AUTH_MODE: Literal["token"] = "token"
    # Debug identity ปิดโดย default; เปิดแล้ว log เฉพาะ peer IP + Serial ที่มากับ metadata RPC เดิม
    # ไม่ใช้ยืนยันตัวตนและไม่ persist ลงฐานข้อมูล
    CALLHOME_IDENTITY_DEBUG: bool = False
    # log รายละเอียดตอนอุปกรณ์ call-home (Vendor/Serial/Device ID/Hostname/Model/Firmware/capability)
    # ปิดเป็นค่าเริ่มต้น: ปกติแสดงแค่ "[+] Call Home from <ip>  host-key: <fingerprint>" ; เปิดแล้วอ่าน serial เพิ่ม 1 RPC
    CALLHOME_VERBOSE_LOG: bool = False
    # CM-12: kill switch การสมัครสมาชิก (Email + Google) - ปิดเป็นค่าเริ่มต้นเสมอ ไม่ผูกกับ APP_ENV
    # ต้องตั้ง SIGNUP_ENABLED=true เองเมื่อพร้อมเปิด; login/logout/password reset ไม่ขึ้นกับค่านี้
    SIGNUP_ENABLED: bool = True

    @model_validator(mode="before")
    @classmethod
    def empty_means_default(cls, data):
        # "KEY=" in the config file means "not set": the default applies (or None),
        # same as leaving the line out
        if isinstance(data, dict):
            return {key: value for key, value in data.items() if not (isinstance(value, str) and not value.strip())}
        return data

    @field_validator("GOOGLE_CLIENT_ID")
    @classmethod
    def validate_google_client_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        if cleaned.lower().startswith(("replace", "your-", "your_")) or not cleaned.endswith(
            ".apps.googleusercontent.com"
        ):
            raise ValueError("GOOGLE_CLIENT_ID must be a Google OAuth web client ID")
        return cleaned

    @field_validator("GOOGLE_CLIENT_SECRET")
    @classmethod
    def validate_google_client_secret(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        if not cleaned or cleaned.lower().startswith(("replace", "your-", "your_")):
            raise ValueError("GOOGLE_CLIENT_SECRET must not use a placeholder value")
        return cleaned

    @field_validator("ALLOWED_HOSTS")
    @classmethod
    def validate_allowed_hosts(cls, value: str) -> str:
        hosts = [item.strip().lower() for item in (value or "").split(",") if item.strip()]
        for host in hosts:
            if host == "*" or "/" in host or ":" in host or " " in host:
                raise ValueError("ALLOWED_HOSTS must list hostnames only (no '*', ports or URLs)")
        return ",".join(hosts)

    @field_validator("GOOGLE_REDIRECT_URI", "FRONTEND_BASE_URL")
    @classmethod
    def validate_application_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip().rstrip("/")
        parsed = urlparse(cleaned)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Application URLs must be absolute HTTP(S) URLs without credentials")
        return cleaned

    @field_validator("JWT_SECRET_KEY")
    @classmethod
    def validate_jwt_secret(cls, value: str) -> str:
        cleaned = value.strip()
        if len(cleaned) < 32 or cleaned.lower().startswith(
            ("replace", "change-me", "your-", "your_", "generate-", "generate_")
        ):
            raise ValueError("JWT_SECRET_KEY must contain at least 32 characters")
        return cleaned

    @field_validator("SMTP_APP_PASSWORD", "TURNSTILE_SECRET_KEY")
    @classmethod
    def validate_external_secret(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        if not cleaned or cleaned.lower().startswith(
            ("replace", "change-me", "your-", "your_", "generate-", "generate_")
        ):
            raise ValueError("External service secrets must not use placeholder values")
        return cleaned

    @field_validator("SMTP_PORT")
    @classmethod
    def validate_smtp_port(cls, value: int) -> int:
        if value not in {465, 587}:
            raise ValueError("SMTP_PORT must be 465 (implicit TLS) or 587 (STARTTLS)")
        return value

    @field_validator("CALLHOME_ADDRESS")
    @classmethod
    def validate_callhome_address(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            return str(ipaddress.IPv4Address(value.strip()))
        except ValueError as exc:
            raise ValueError("CALLHOME_ADDRESS must be an IPv4 address (devices cannot use a hostname)") from exc

    @field_validator("CALLHOME_LISTEN_ADDRESS")
    @classmethod
    def validate_callhome_listen_address(cls, value: str) -> str:
        try:
            return str(ipaddress.IPv4Address(value.strip()))
        except ValueError as exc:
            raise ValueError("CALLHOME_LISTEN_ADDRESS must be 0.0.0.0 (all interfaces) or one IPv4 address of this machine") from exc

    @field_validator("BOOTSTRAP_BASE_URL")
    @classmethod
    def validate_bootstrap_base_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip().rstrip("/")
        parsed = urlparse(cleaned)
        if parsed.scheme != "https" or not parsed.hostname or parsed.query or parsed.fragment or parsed.username:
            raise ValueError("BOOTSTRAP_BASE_URL must look like https://<host>[:port][/path], e.g. https://www.example.ac.th/cmm/api")
        return cleaned

    @field_validator("SITE_URL")
    @classmethod
    def validate_site_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip().rstrip("/")
        parsed = urlparse(cleaned)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.path
                or parsed.query or parsed.fragment or parsed.username):
            raise ValueError("SITE_URL must look like https://www.example.ac.th (no path - the path goes in ROOT_PATH)")
        return cleaned

    @field_validator("ROOT_PATH")
    @classmethod
    def validate_root_path(cls, value: str) -> str:
        cleaned = (value or "/").strip().strip("/")
        if cleaned and not re.fullmatch(r"[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)*", cleaned):
            raise ValueError("ROOT_PATH must be / or a path such as /cmm/ (letters, digits, . _ ~ -)")
        return f"/{cleaned}/" if cleaned else "/"

    @field_validator("FRONTEND_PORT", "BACKEND_PORT", "CALLHOME_PORT")
    @classmethod
    def validate_port(cls, value: int) -> int:
        if not 1 <= value <= 65535:
            raise ValueError("ports must be between 1 and 65535")
        return value

    @property
    def google_configured(self) -> bool:
        return self.GOOGLE_ENABLED and all(
            (self.GOOGLE_CLIENT_ID, self.GOOGLE_CLIENT_SECRET, self.GOOGLE_REDIRECT_URI, self.FRONTEND_BASE_URL)
        )

    @property
    def smtp_configured(self) -> bool:
        return self.EMAIL_ENABLED and all((self.SMTP_HOST, self.SMTP_USERNAME, self.SMTP_APP_PASSWORD))

    def bootstrap_base_url(self, callhome_ip: str | None) -> str:
        return self.BOOTSTRAP_BASE_URL or f"https://{callhome_ip}:{self.BACKEND_PORT}"

    @field_validator("REGISTRATION_FLOW_TTL_SECONDS")
    @classmethod
    def validate_registration_flow_ttl(cls, value: int) -> int:
        if not 60 <= value <= 30 * 60:
            raise ValueError("REGISTRATION_FLOW_TTL_SECONDS must be between 60 and 1800 seconds")
        return value

    @field_validator("TURNSTILE_EXPECTED_HOSTNAME")
    @classmethod
    def validate_turnstile_hostname(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip().casefold()
        if "://" in cleaned or "/" in cleaned:
            raise ValueError("TURNSTILE_EXPECTED_HOSTNAME must be a hostname without scheme, port, or path")
        return cleaned

    @model_validator(mode="after")
    def derive_and_check(self):
        site = urlparse(self.SITE_URL) if self.SITE_URL else None
        if site is not None:
            public_root = f"{self.SITE_URL}{self.ROOT_PATH}"
            self.FRONTEND_BASE_URL = self.FRONTEND_BASE_URL or public_root.rstrip("/")
            self.GOOGLE_REDIRECT_URI = self.GOOGLE_REDIRECT_URI or f"{public_root}api/auth/google/callback"
            self.TURNSTILE_EXPECTED_HOSTNAME = self.TURNSTILE_EXPECTED_HOSTNAME or site.hostname
        self.TURNSTILE_EXPECTED_HOSTNAME = self.TURNSTILE_EXPECTED_HOSTNAME or "localhost"

        if len({self.FRONTEND_PORT, self.BACKEND_PORT, self.CALLHOME_PORT}) != 3:
            raise ValueError("FRONTEND_PORT, BACKEND_PORT and CALLHOME_PORT must be three different ports")

        # A feature switched on must be complete; switched off, its values are ignored.
        if self.TURNSTILE_ENABLED:
            missing = [name for name in ("TURNSTILE_SITE_KEY", "TURNSTILE_SECRET_KEY") if not getattr(self, name)]
            if missing:
                raise ValueError(_missing("TURNSTILE_ENABLED", missing))
            if self.TURNSTILE_SECRET_KEY not in TURNSTILE_TEST_SECRETS and site is None:
                raise ValueError("TURNSTILE_ENABLED=yes needs SITE_URL (Cloudflare checks the site's hostname)")
        if self.EMAIL_ENABLED:
            missing = [name for name in ("SMTP_HOST", "SMTP_USERNAME", "SMTP_APP_PASSWORD") if not getattr(self, name)]
            if missing:
                raise ValueError(_missing("EMAIL_ENABLED", missing))
        if self.GOOGLE_ENABLED:
            missing = [name for name in ("GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET") if not getattr(self, name)]
            if site is None:
                missing.append("SITE_URL")
            if missing:
                raise ValueError(_missing("GOOGLE_ENABLED", missing))

        if self.APP_ENV == "production":
            if not self.TURNSTILE_ENABLED:
                raise ValueError("APP_ENV=production needs TURNSTILE_ENABLED=yes (real Cloudflare keys)")
            if self.TURNSTILE_SECRET_KEY in TURNSTILE_TEST_SECRETS:
                raise ValueError("Production must not use an official Turnstile testing secret")
            if self.TURNSTILE_EXPECTED_HOSTNAME in {"localhost", "127.0.0.1"}:
                raise ValueError("Production must not use a localhost Turnstile hostname")
            if self.google_configured:
                redirect = urlparse(self.GOOGLE_REDIRECT_URI)
                frontend = urlparse(self.FRONTEND_BASE_URL)
                if redirect.scheme != "https" or frontend.scheme != "https":
                    raise ValueError("Production Google sign-in needs an https:// SITE_URL")
                if redirect.hostname != self.TURNSTILE_EXPECTED_HOSTNAME or frontend.hostname != self.TURNSTILE_EXPECTED_HOSTNAME:
                    raise ValueError("Production authentication URLs must use the SITE_URL hostname")
        return self

    # The file is read on every load_environment() call (callers that need a value once
    # cache it themselves). Unknown keys are rejected so a typo is reported, not ignored.
    model_config = SettingsConfigDict(
         case_sensitive=True,
         hide_input_in_errors=True,
    )


def load_environment():
    return Setting(_env_file=config_file())
