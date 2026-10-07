""" |======= Allowed Host headers (TrustedHostMiddleware) =======|

The list is derived from configuration the system already has, so production
picks up its real domain from the same settings instead of a wildcard:
local names, the server IP that devices use for bootstrap downloads, the
hostnames of every SITE_URL address, the auth URLs and BOOTSTRAP_BASE_URL, and optional
ALLOWED_HOSTS from the config file.
"""

from urllib.parse import urlparse

LOCAL_HOSTS = ("localhost", "127.0.0.1", "www.callmemanage.local", "callmemanage.local")


def build_allowed_hosts(settings, cloud_server_ip: str | None) -> list[str]:
    hosts: list[str] = list(LOCAL_HOSTS)
    # Devices fetch https://<cloud server ip>/bootstrap/... through the proxy,
    # which forwards that IP as the Host header.
    if cloud_server_ip:
        hosts.append(cloud_server_ip)
    if settings.TURNSTILE_EXPECTED_HOSTNAME:
        hosts.append(settings.TURNSTILE_EXPECTED_HOSTNAME)
    for url in (*settings.site_urls, settings.FRONTEND_BASE_URL, settings.GOOGLE_REDIRECT_URI, settings.BOOTSTRAP_BASE_URL):
        if url and urlparse(url).hostname:
            hosts.append(urlparse(url).hostname)
    hosts.extend((settings.ALLOWED_HOSTS or "").split(","))
    unique = []
    for host in (h.strip().lower() for h in hosts):
        if host and host not in unique:
            unique.append(host)
    return unique
