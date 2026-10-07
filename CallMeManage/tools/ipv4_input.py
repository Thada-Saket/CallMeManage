"""Explicit IPv4 syntax validators. Context-specific restrictions are opt-in."""
import ipaddress
import re


def validate_address(value: str, field: str = "IP address") -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string containing four IPv4 octets")
    text = value.strip()
    if not re.fullmatch(r"(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}", text):
        raise ValueError(f"{field} must contain four octets without leading zeros")
    try:
        return str(ipaddress.IPv4Address(text))
    except ValueError as exc:
        raise ValueError(f"{field} octets must be between 0 and 255") from exc


def validate_prefix(value, field: str = "prefix") -> int:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValueError(f"{field} must be an integer between 0 and 32")
    text = str(value).strip()
    if not re.fullmatch(r"(?:0|[1-9][0-9]?)", text) or not 0 <= int(text) <= 32:
        raise ValueError(f"{field} must be an integer between 0 and 32")
    return int(text)


def validate_subnet(value: str, field: str = "subnet mask") -> str:
    mask = validate_address(value, field)
    inverse = int(ipaddress.IPv4Address(mask)) ^ 0xFFFFFFFF
    if inverse & (inverse + 1):
        raise ValueError(f"{field} must have contiguous 1 bits followed by 0 bits")
    return mask


def validate_wildcard(value: str, field: str = "wildcard", *, contiguous: bool = False) -> str:
    mask = validate_address(value, field)
    number = int(ipaddress.IPv4Address(mask))
    if contiguous and number & (number + 1):
        raise ValueError(f"{field} must be contiguous for this operation")
    return mask


def validate_cidr(value: str, field: str = "address/prefix", *, network_only: bool = False,
                  host_only: bool = False) -> str:
    if not isinstance(value, str) or value.strip().count("/") != 1:
        raise ValueError(f"{field} must be IPv4 address/prefix")
    address, prefix = value.strip().split("/")
    interface = ipaddress.IPv4Interface(f"{validate_address(address, field)}/{validate_prefix(prefix, field)}")
    if network_only and interface.ip != interface.network.network_address:
        raise ValueError(f"{field} must be a network address")
    if host_only and interface.network.prefixlen < 31 and interface.ip in (
        interface.network.network_address, interface.network.broadcast_address,
    ):
        raise ValueError(f"{field} must be a host address")
    return str(interface)
